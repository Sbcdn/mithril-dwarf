//! Certificate verification.

pub mod basic_checks;
pub mod complex_checks;
pub mod hash_sink;
pub mod medium_checks;

pub use hash_sink::{HashSink, Sha256Sink};

use crate::parser::byte_deserializer::{CertificateZeroCopy, SignatureBasicZeroCopy};

/// 4-byte `Copy` enum; no payload, no allocation on failure paths.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyError {
    // Basic
    InfiniteLoop,
    PreviousHashMismatch,
    EpochGap,
    EpochMismatch,
    CurrentEpochNotFound,

    // Medium
    HashMismatch,
    SignedMessageMismatch,

    // Chain
    AVKMismatch,
    ProtocolParamsMismatch,
    NextAVKNotFound,
    NextProtocolParamsNotFound,

    // BLS
    BLSVerificationFailed,
    IndexOutOfBounds,
    IndexNotUnique,
    LotteryLost,
    NoQuorum,
    BatchProofInvalid,

    // Genesis
    Ed25519VerificationFailed,
    InvalidGenesisSignature,
    NoGenesisKeyProvided,

    // Parsing
    InvalidUtf8,
    ParseIntError,
    InvalidHexEncoding,
    FormatError,

    // Dispatch
    NotStandardCertificate,
    NotGenesisCertificate,

    // Batch proof
    InvalidBatchProof,
    InvalidAVKEncoding,
    InvalidProtocolParamsHash,

    NotImplemented,
}

/// Genesis (Ed25519-signed) certificate.
pub fn verify_genesis_certificate(
    cert: &CertificateZeroCopy,
    genesis_vk: &[u8; 32],
) -> Result<(), VerifyError> {
    let genesis_sig = match &cert.signature {
        SignatureBasicZeroCopy::Genesis { signature_bytes } => signature_bytes,
        _ => return Err(VerifyError::NotGenesisCertificate),
    };

    medium_checks::verify_hash_matches_content(cert)?;
    medium_checks::verify_signed_message_matches_protocol(cert)?;
    basic_checks::verify_epoch_matches_protocol_message(cert)?;
    verify_ed25519_signature(cert.signed_message, genesis_sig, genesis_vk)?;

    Ok(())
}

/// Standard (BLS-multisigned) certificate, verified against its predecessor.
///
/// Phases run cheapest-first; `pm_digest` and `pp_digest` are computed once
/// and threaded into both phase 2 and phase 3 to avoid a second SHA-256.
pub fn verify_standard_certificate(
    cert: &CertificateZeroCopy,
    prev_cert: &CertificateZeroCopy,
) -> Result<(), VerifyError> {
    let _multi_sig = match &cert.signature {
        SignatureBasicZeroCopy::Multi { signature, .. } => signature,
        _ => return Err(VerifyError::NotStandardCertificate),
    };

    // Phase 1: basic comparisons.
    basic_checks::verify_not_infinite_loop(cert)?;
    basic_checks::verify_epoch_matches_protocol_message(cert)?;
    basic_checks::verify_epoch_chaining(cert, prev_cert)?;
    basic_checks::verify_previous_hash_matches(cert, prev_cert)?;

    // Phase 2: SHA-256 over canonical bytes.
    let pm_digest = medium_checks::compute_protocol_message_digest(&cert.protocol_message);
    let pp_digest = medium_checks::compute_protocol_parameters_digest(
        cert.metadata.k,
        cert.metadata.m,
        cert.metadata.phi_f,
    );
    medium_checks::verify_hash_matches_content_with_pm_and_pp_digests(
        cert, &pm_digest, &pp_digest,
    )?;
    medium_checks::verify_signed_message_matches_protocol_with_pm_digest(cert, &pm_digest)?;

    // Phase 3: AVK + protocol-params chaining.
    if cert.epoch == prev_cert.epoch {
        basic_checks::verify_avk_same_epoch(cert, prev_cert)?;
        basic_checks::verify_protocol_params_same_epoch(cert, prev_cert)?;
    } else {
        complex_checks::verify_avk_chain(cert, prev_cert)?;
        complex_checks::verify_protocol_params_chain_cross_epoch_with_pp_digest(
            cert, prev_cert, &pp_digest,
        )?;
    }

    // Phase 4: BLS multi-signature.
    complex_checks::verify_bls_multisig(cert)?;

    Ok(())
}

/// Dispatch on signature variant; genesis needs `genesis_vk`, standard needs `prev_cert`.
pub fn verify_certificate(
    cert: &CertificateZeroCopy,
    prev_cert: Option<&CertificateZeroCopy>,
    genesis_vk: Option<&[u8; 32]>,
) -> Result<(), VerifyError> {
    match &cert.signature {
        SignatureBasicZeroCopy::Genesis { .. } => {
            let key = genesis_vk.ok_or(VerifyError::NoGenesisKeyProvided)?;
            verify_genesis_certificate(cert, key)
        }
        SignatureBasicZeroCopy::Multi { .. } => {
            let prev = prev_cert.ok_or(VerifyError::PreviousHashMismatch)?;
            verify_standard_certificate(cert, prev)
        }
    }
}

/// Walks `certificates[0..]` (newest → oldest); the last entry must be genesis.
pub fn verify_certificate_chain(
    certificates: &[CertificateZeroCopy],
    genesis_vk: Option<&[u8; 32]>,
) -> Result<(), VerifyError> {
    if certificates.is_empty() {
        return Ok(());
    }
    for i in 0..certificates.len() {
        let prev = certificates.get(i + 1);
        verify_certificate(&certificates[i], prev, genesis_vk)?;
    }
    Ok(())
}

/// Aligned with upstream `ProtocolGenesisVerificationKey::verify` —
/// `verify_strict` adds small-order checks on R / A and uses the
/// un-cofactored equation. Genesis-only path; +~49,800 RISC0 cycles
/// per chain (measured in the downstream guest harness with `--features guest-bench`).
fn verify_ed25519_signature(
    message: &[u8],
    signature: &[u8],
    public_key: &[u8; 32],
) -> Result<(), VerifyError> {
    use ed25519_dalek::{Signature, VerifyingKey};

    if signature.len() != 64 {
        return Err(VerifyError::InvalidGenesisSignature);
    }

    let sig = Signature::from_bytes(
        signature
            .try_into()
            .map_err(|_| VerifyError::InvalidGenesisSignature)?,
    );
    let vk =
        VerifyingKey::from_bytes(public_key).map_err(|_| VerifyError::InvalidGenesisSignature)?;

    vk.verify_strict(message, &sig)
        .map_err(|_| VerifyError::Ed25519VerificationFailed)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_error_fits_in_4_bytes() {
        assert!(core::mem::size_of::<VerifyError>() <= 4);
    }

    /// Regression pin: ed25519 path must reject a small-order public
    /// key (identity point). `verify_strict` enforces this via
    /// `is_small_order()`; legacy `verify` would accept a crafted
    /// `(R=identity, s=0)` signature. Fails if the call site reverts to
    /// non-strict.
    #[test]
    fn ed25519_rejects_small_order_public_key() {
        let mut identity_vk = [0u8; 32];
        identity_vk[0] = 0x01;
        let mut sig_bytes = [0u8; 64];
        sig_bytes[0] = 0x01;
        assert!(matches!(
            verify_ed25519_signature(b"small-order pin", &sig_bytes, &identity_vk),
            Err(VerifyError::Ed25519VerificationFailed)
                | Err(VerifyError::InvalidGenesisSignature)
        ));
    }
}
