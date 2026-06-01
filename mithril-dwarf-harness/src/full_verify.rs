//! Top-level verifier runners. After every per-check comparison the
//! harness also runs both implementations' top-level entry points and
//! bitwise-compares the results.
//!
//! - Mithril: `MithrilCertificateVerifier::verify_*` (async; driven on
//!   a fresh Tokio current-thread runtime per call).
//! - Dwarf: `mithril_dwarf::verify_*` (sync).
//!
//! Both verdicts are projected to a canonical `Result<(), ErrorCategory>`
//! (encoded into [`CheckResult::bytes`]) so a divergence between
//! "accept vs reject" or "reject with X vs reject with Y" surfaces as a
//! bitwise mismatch.

use std::sync::Arc;

use async_trait::async_trait;
use mithril_common::StdResult;
use mithril_common::certificate_chain::{
    CertificateRetriever, CertificateRetrieverError, CertificateVerifier, CertificateVerifierError,
    MithrilCertificateVerifier,
};
use mithril_common::entities::Certificate;
use mithril_dwarf::certificate_verification::VerifyError;
use mithril_dwarf::parser::byte_deserializer::CertificateZeroCopy;

use crate::types::{CheckResult, ErrorCategory};

pub fn mithril_full_verify_standard(cert: &Certificate, prev: &Certificate) -> CheckResult {
    let retriever: Arc<dyn CertificateRetriever> = Arc::new(MockRetriever { prev: prev.clone() });
    let verifier = MithrilCertificateVerifier::new(no_op_logger(), retriever);
    let result = run_async(verifier.verify_standard_certificate(cert, prev));
    match result {
        Ok(()) => CheckResult::pass(Vec::new()),
        Err(e) => CheckResult::fail(mithril_error_to_category(&e), Vec::new()),
    }
}

pub fn mithril_full_verify_genesis(cert: &Certificate, genesis_vk_hex: &str) -> CheckResult {
    use mithril_common::crypto_helper::ProtocolGenesisVerificationKey;
    let verifier = MithrilCertificateVerifier::new(
        no_op_logger(),
        Arc::new(MockRetriever { prev: cert.clone() }),
    );
    let Ok(genesis_vk) = ProtocolGenesisVerificationKey::from_json_hex(genesis_vk_hex) else {
        return CheckResult::fail(ErrorCategory::StructuralError, Vec::new());
    };
    let result = run_async(verifier.verify_genesis_certificate(cert, &genesis_vk));
    match result {
        Ok(()) => CheckResult::pass(Vec::new()),
        Err(e) => CheckResult::fail(mithril_error_to_category(&e), Vec::new()),
    }
}

/// Map upstream Mithril's `CertificateVerifierError` (wrapped in
/// `anyhow::Error` by the verifier) to the canonical `ErrorCategory` the
/// harness compares on. Variants not matched are reported as
/// `StructuralError` so the comparison still byte-matches when both impls
/// surface the same out-of-band failure shape.
fn mithril_error_to_category(e: &anyhow::Error) -> ErrorCategory {
    if let Some(cv) = e.downcast_ref::<CertificateVerifierError>() {
        match cv {
            CertificateVerifierError::CertificateChainInfiniteLoop => ErrorCategory::InfiniteLoop,
            CertificateVerifierError::CertificateChainMissingEpoch => ErrorCategory::EpochChainGap,
            CertificateVerifierError::CertificateEpochUnmatch => {
                ErrorCategory::EpochInProtocolMessageMismatch
            }
            CertificateVerifierError::CertificateChainPreviousHashUnmatch => {
                ErrorCategory::PreviousHashMismatch
            }
            CertificateVerifierError::CertificateHashUnmatch => ErrorCategory::HashMismatch,
            CertificateVerifierError::CertificateProtocolMessageUnmatch => {
                ErrorCategory::SignedMessageMismatch
            }
            CertificateVerifierError::CertificateChainAVKUnmatch => ErrorCategory::AvkMismatch,
            CertificateVerifierError::CertificateChainProtocolParametersUnmatch => {
                ErrorCategory::ProtocolParamsMismatch
            }
            CertificateVerifierError::VerifyMultiSignature(_) => ErrorCategory::BlsVerifyFailed,
            CertificateVerifierError::CertificateGenesis(_) => ErrorCategory::Ed25519VerifyFailed,
            CertificateVerifierError::InvalidGenesisCertificateProvided
            | CertificateVerifierError::InvalidStandardCertificateProvided => {
                ErrorCategory::StructuralError
            }
        }
    } else {
        ErrorCategory::StructuralError
    }
}

pub fn dwarf_full_verify_standard(
    cert: &CertificateZeroCopy,
    prev: &CertificateZeroCopy,
) -> CheckResult {
    match mithril_dwarf::verify_standard_certificate(cert, prev) {
        Ok(()) => CheckResult::pass(Vec::new()),
        Err(e) => CheckResult::fail(verify_error_to_category(e), Vec::new()),
    }
}

pub fn dwarf_full_verify_genesis(cert: &CertificateZeroCopy, genesis_vk: &[u8; 32]) -> CheckResult {
    match mithril_dwarf::verify_genesis_certificate(cert, genesis_vk) {
        Ok(()) => CheckResult::pass(Vec::new()),
        Err(e) => CheckResult::fail(verify_error_to_category(e), Vec::new()),
    }
}

/// Map dwarf's native `VerifyError` to a canonical `ErrorCategory`.
///
/// **No catch-all arm.** Every `VerifyError` variant is matched
/// explicitly so a future variant added in
/// `src/certificate_verification/mod.rs` becomes a compile error here
/// until the harness is updated to classify it. The previous
/// `_ => StructuralError` arm silently absorbed unmapped variants,
/// which would have masked a real divergence if dwarf invented a new
/// failure mode (e.g. a new BLS sub-check) and the harness defaulted
/// it to a coarse bucket.
pub fn verify_error_to_category(e: VerifyError) -> ErrorCategory {
    match e {
        VerifyError::InfiniteLoop => ErrorCategory::InfiniteLoop,
        VerifyError::PreviousHashMismatch => ErrorCategory::PreviousHashMismatch,
        VerifyError::EpochGap => ErrorCategory::EpochChainGap,
        VerifyError::EpochMismatch => ErrorCategory::EpochInProtocolMessageMismatch,
        VerifyError::CurrentEpochNotFound => ErrorCategory::EpochInProtocolMessageMismatch,
        VerifyError::HashMismatch => ErrorCategory::HashMismatch,
        VerifyError::SignedMessageMismatch => ErrorCategory::SignedMessageMismatch,
        // Both same-epoch AVK mismatch and cross-epoch chain mismatch
        // reduce to Mithril's single `CertificateChainAVKUnmatch` at the
        // full-verify level; harness aligns them too so the bitwise byte
        // comparison agrees.
        VerifyError::AVKMismatch | VerifyError::NextAVKNotFound => ErrorCategory::AvkMismatch,
        VerifyError::ProtocolParamsMismatch | VerifyError::NextProtocolParamsNotFound => {
            ErrorCategory::ProtocolParamsMismatch
        }
        VerifyError::BLSVerificationFailed
        | VerifyError::IndexOutOfBounds
        | VerifyError::IndexNotUnique
        | VerifyError::LotteryLost
        | VerifyError::NoQuorum
        | VerifyError::BatchProofInvalid
        | VerifyError::InvalidBatchProof => ErrorCategory::BlsVerifyFailed,
        VerifyError::Ed25519VerificationFailed
        | VerifyError::InvalidGenesisSignature
        | VerifyError::NoGenesisKeyProvided => ErrorCategory::Ed25519VerifyFailed,
        // Parse / encoding / placeholder variants — none of these have a
        // direct upstream Mithril counterpart that the harness compares
        // against at fine granularity, so they collapse to
        // `StructuralError` (the same bucket upstream's
        // `InvalidGenesisCertificateProvided` /
        // `InvalidStandardCertificateProvided` collapse into).
        VerifyError::InvalidUtf8
        | VerifyError::ParseIntError
        | VerifyError::InvalidHexEncoding
        | VerifyError::FormatError
        | VerifyError::NotStandardCertificate
        | VerifyError::NotGenesisCertificate
        | VerifyError::InvalidAVKEncoding
        | VerifyError::InvalidProtocolParamsHash
        | VerifyError::NotImplemented => ErrorCategory::StructuralError,
    }
}

// Async glue

struct MockRetriever {
    prev: Certificate,
}

#[async_trait]
impl CertificateRetriever for MockRetriever {
    async fn get_certificate_details(
        &self,
        hash: &str,
    ) -> Result<Certificate, CertificateRetrieverError> {
        // Hash-aware: only return `prev` when the queried hash matches.
        // Returning `prev` unconditionally would mask the scenario where a
        // mutation flips `cert.previous_hash` to something else — Mithril
        // would silently get back the genuine prev and skip the mismatch,
        // diverging from dwarf which catches the flip directly. Mirror
        // upstream's "not found" semantics for any other hash.
        if hash == self.prev.hash {
            Ok(self.prev.clone())
        } else {
            Err(CertificateRetrieverError(anyhow::anyhow!(
                "MockRetriever: requested hash {hash} not in mock set"
            )))
        }
    }
}

fn no_op_logger() -> slog::Logger {
    slog::Logger::root(slog::Discard, slog::o!())
}

fn run_async<F: std::future::Future<Output = StdResult<()>>>(fut: F) -> StdResult<()> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build current-thread runtime")
        .block_on(fut)
}
