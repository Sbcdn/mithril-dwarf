//! Per-check runners for standard (non-genesis) certificates.
//!
//! Each check is a pair of functions — one driven through upstream Mithril
//! (`mithril-common` primitives), one driven through dwarf's own `verify_*`
//! functions. Both produce a [`CheckResult`] whose
//! `bytes` field is the canonical encoding of "what this check produced."
//! The harness compares the two `bytes` fields bitwise; a difference
//! means the implementations disagree on that check.
//!
//! Both sides go through the same entry point as the production verifier
//! would — the Mithril side calls `mithril-common` primitives the way
//! `MithrilCertificateVerifier::verify_standard_certificate` does; the
//! dwarf side calls `mithril_dwarf::certificate_verification::*::verify_*`
//! (never the raw `compute_*_hash` helpers, which would skip the
//! verifier-level rejection paths). Computed digests are included only as
//! a payload so the bitwise comparison can also notice if the hashes
//! themselves differ between implementations.

use mithril_common::entities::{Certificate, CertificateSignature, ProtocolMessagePartKey};

use mithril_dwarf::certificate_verification::basic_checks::{
    verify_avk_same_epoch, verify_epoch_chaining, verify_epoch_matches_protocol_message,
    verify_not_infinite_loop, verify_previous_hash_matches, verify_protocol_params_same_epoch,
};
use mithril_dwarf::certificate_verification::complex_checks::{
    verify_avk_chain, verify_bls_multisig, verify_protocol_params_chain,
};
use mithril_dwarf::certificate_verification::medium_checks::{
    compute_certificate_hash, compute_protocol_message_hash, verify_hash_matches_content,
    verify_signed_message_matches_protocol,
};
use mithril_dwarf::parser::byte_deserializer::CertificateZeroCopy;

use crate::check_helpers::{
    decode_sha256_hex, epoch_pair_payload, epoch_parse_payload,
    parse_epoch_from_dwarf_protocol_message,
};
use crate::types::{CheckResult, ErrorCategory};

pub const SPECS: &[(&str, &str)] = &[
    (
        "not_infinite_loop",
        "cert.hash != cert.previous_hash (loop guard)",
    ),
    (
        "certificate_hash_matches_content",
        "SHA-256(canonical certificate bytes) == cert.hash",
    ),
    (
        "signed_message_matches_protocol_message",
        "SHA-256(canonical protocol_message bytes) == cert.signed_message",
    ),
    (
        "multi_signature_verifies",
        "BLS multi-signature verifies (per-index lottery wins, Merkle batch proof, BLS aggregate)",
    ),
    (
        "epoch_matches_protocol_message",
        "cert.epoch == protocol_message[CurrentEpoch]",
    ),
    (
        "epoch_chaining",
        "|cert.epoch - prev.epoch| <= 1 (matches Mithril's Epoch::has_gap_with)",
    ),
    ("previous_hash_matches", "cert.previous_hash == prev.hash"),
    (
        "avk_same_epoch",
        "(same-epoch) cert.aggregate_verification_key == prev.aggregate_verification_key",
    ),
    (
        "avk_chain",
        "(cross-epoch) cert.aggregate_verification_key == prev.protocol_message[NextAggregateVerificationKey]",
    ),
    (
        "protocol_params_same_epoch",
        "(same-epoch) cert.metadata.protocol_parameters == prev.metadata.protocol_parameters",
    ),
    (
        "protocol_params_chain",
        "(cross-epoch) hash(cert.metadata.protocol_parameters) == prev.protocol_message[NextProtocolParameters]",
    ),
];

// MITHRIL side

pub fn mithril_not_infinite_loop(cert: &Certificate) -> CheckResult {
    if cert.hash != cert.previous_hash {
        CheckResult::pass(Vec::new())
    } else {
        CheckResult::fail(ErrorCategory::InfiniteLoop, Vec::new())
    }
}

pub fn mithril_certificate_hash_matches_content(cert: &Certificate) -> CheckResult {
    let computed = cert.compute_hash();
    let digest = decode_sha256_hex(&computed);
    if computed == cert.hash {
        CheckResult::pass(digest)
    } else {
        CheckResult::fail(ErrorCategory::HashMismatch, digest)
    }
}

pub fn mithril_signed_message_matches_protocol_message(cert: &Certificate) -> CheckResult {
    let computed = cert.protocol_message.compute_hash();
    let digest = decode_sha256_hex(&computed);
    if computed == cert.signed_message {
        CheckResult::pass(digest)
    } else {
        CheckResult::fail(ErrorCategory::SignedMessageMismatch, digest)
    }
}

pub fn mithril_multi_signature_verifies(cert: &Certificate) -> CheckResult {
    match &cert.signature {
        // `MultiSignature(entity_type, multi_sig)` — first field is the
        // `SignedEntityType` describing what the signature is over (e.g.
        // `MithrilStakeDistribution(epoch)`).
        CertificateSignature::MultiSignature(_, multi_sig) => {
            match multi_sig.verify(
                cert.signed_message.as_bytes(),
                &cert.aggregate_verification_key,
                &cert.metadata.protocol_parameters.clone().into(),
            ) {
                Ok(()) => CheckResult::pass(Vec::new()),
                Err(_) => CheckResult::fail(ErrorCategory::BlsVerifyFailed, Vec::new()),
            }
        }
        CertificateSignature::GenesisSignature(_) => CheckResult::not_applicable(),
    }
}

/// Mirrors Mithril's `verify_epoch_matches_protocol_message` which does a
/// **string compare** of `protocol_message[CurrentEpoch]` against
/// `cert.epoch.to_string()` — not a u64 compare. `"00007"` would parse to
/// 7 but never `== "7"`, so we must do string-compare to match Mithril
/// exactly.
pub fn mithril_epoch_matches_protocol_message(cert: &Certificate) -> CheckResult {
    let stored = cert
        .protocol_message
        .message_parts
        .get(&ProtocolMessagePartKey::CurrentEpoch);
    let parsed_u64 = stored.and_then(|v| v.parse::<u64>().ok());
    let payload = epoch_parse_payload(parsed_u64);
    let expected = cert.epoch.0.to_string();
    match stored {
        Some(v) if v == &expected => CheckResult::pass(payload),
        _ => CheckResult::fail(ErrorCategory::EpochInProtocolMessageMismatch, payload),
    }
}

/// Mithril's `Epoch::has_gap_with` (`mithril-common/src/entities/epoch.rs`):
/// `self.0.abs_diff(other.0) > 1`. So Mithril accepts both `prev == cert + 1`
/// (regression-by-one) and `cert == prev + 1` (the normal case). The harness
/// must mirror this exactly even though dwarf uses a stricter formulation
/// (see the dwarf side's `checked_add` formulation in
/// `basic_checks::verify_epoch_chaining`).
pub fn mithril_epoch_chaining(cert: &Certificate, prev: &Certificate) -> CheckResult {
    let payload = epoch_pair_payload(cert.epoch.0, prev.epoch.0);
    if cert.epoch.0.abs_diff(prev.epoch.0) <= 1 {
        CheckResult::pass(payload)
    } else {
        CheckResult::fail(ErrorCategory::EpochChainGap, payload)
    }
}

pub fn mithril_previous_hash_matches(cert: &Certificate, prev: &Certificate) -> CheckResult {
    if cert.previous_hash == prev.hash {
        CheckResult::pass(Vec::new())
    } else {
        CheckResult::fail(ErrorCategory::PreviousHashMismatch, Vec::new())
    }
}

pub fn mithril_avk_same_epoch(cert: &Certificate, prev: &Certificate) -> CheckResult {
    if cert.epoch != prev.epoch {
        return CheckResult::not_applicable();
    }
    if cert.aggregate_verification_key == prev.aggregate_verification_key {
        CheckResult::pass(Vec::new())
    } else {
        CheckResult::fail(ErrorCategory::AvkMismatch, Vec::new())
    }
}

pub fn mithril_avk_chain(cert: &Certificate, prev: &Certificate) -> CheckResult {
    if cert.epoch == prev.epoch {
        return CheckResult::not_applicable();
    }
    let Some(next_avk_hex) = prev
        .protocol_message
        .message_parts
        .get(&ProtocolMessagePartKey::NextAggregateVerificationKey)
    else {
        return CheckResult::fail(ErrorCategory::AvkChainMismatch, Vec::new());
    };
    let current_hex = match cert.aggregate_verification_key.to_json_hex() {
        Ok(h) => h,
        Err(_) => return CheckResult::fail(ErrorCategory::StructuralError, Vec::new()),
    };
    if next_avk_hex == &current_hex {
        CheckResult::pass(Vec::new())
    } else {
        CheckResult::fail(ErrorCategory::AvkChainMismatch, Vec::new())
    }
}

pub fn mithril_protocol_params_same_epoch(cert: &Certificate, prev: &Certificate) -> CheckResult {
    if cert.epoch != prev.epoch {
        return CheckResult::not_applicable();
    }
    if cert.metadata.protocol_parameters == prev.metadata.protocol_parameters {
        CheckResult::pass(Vec::new())
    } else {
        CheckResult::fail(ErrorCategory::ProtocolParamsMismatch, Vec::new())
    }
}

pub fn mithril_protocol_params_chain(cert: &Certificate, prev: &Certificate) -> CheckResult {
    if cert.epoch == prev.epoch {
        return CheckResult::not_applicable();
    }
    let Some(next_params_hash) = prev
        .protocol_message
        .message_parts
        .get(&ProtocolMessagePartKey::NextProtocolParameters)
    else {
        return CheckResult::fail(ErrorCategory::ProtocolParamsChainMismatch, Vec::new());
    };
    let current_hash = cert.metadata.protocol_parameters.compute_hash();
    if next_params_hash == &current_hash {
        CheckResult::pass(Vec::new())
    } else {
        CheckResult::fail(ErrorCategory::ProtocolParamsChainMismatch, Vec::new())
    }
}

// DWARF side — every function goes through dwarf's `verify_*` entrypoint,
// not the raw `compute_*_hash` helpers. (Raw helpers would skip the
// verifier-level rejection paths and let a Pass slip through where the
// production verifier would reject.) Computed digests are included as
// `payload` so bitwise comparison surfaces hash divergences too.

pub fn dwarf_not_infinite_loop(cert: &CertificateZeroCopy) -> CheckResult {
    match verify_not_infinite_loop(cert) {
        Ok(()) => CheckResult::pass(Vec::new()),
        Err(_) => CheckResult::fail(ErrorCategory::InfiniteLoop, Vec::new()),
    }
}

pub fn dwarf_certificate_hash_matches_content(cert: &CertificateZeroCopy) -> CheckResult {
    // Payload: the computed digest, so the bitwise comparison also covers
    // hash equality, not just pass/fail.
    let digest = compute_certificate_hash(cert)
        .map(|h| decode_sha256_hex(&h))
        .unwrap_or_else(|_| decode_sha256_hex(""));
    match verify_hash_matches_content(cert) {
        Ok(()) => CheckResult::pass(digest),
        Err(_) => CheckResult::fail(ErrorCategory::HashMismatch, digest),
    }
}

pub fn dwarf_signed_message_matches_protocol_message(cert: &CertificateZeroCopy) -> CheckResult {
    let digest = decode_sha256_hex(&compute_protocol_message_hash(&cert.protocol_message));
    match verify_signed_message_matches_protocol(cert) {
        Ok(()) => CheckResult::pass(digest),
        Err(_) => CheckResult::fail(ErrorCategory::SignedMessageMismatch, digest),
    }
}

pub fn dwarf_multi_signature_verifies(cert: &CertificateZeroCopy) -> CheckResult {
    use mithril_dwarf::parser::SignatureBasicZeroCopy;
    match &cert.signature {
        SignatureBasicZeroCopy::Multi { .. } => match verify_bls_multisig(cert) {
            Ok(()) => CheckResult::pass(Vec::new()),
            Err(_) => CheckResult::fail(ErrorCategory::BlsVerifyFailed, Vec::new()),
        },
        SignatureBasicZeroCopy::Genesis { .. } => CheckResult::not_applicable(),
    }
}

pub fn dwarf_epoch_matches_protocol_message(cert: &CertificateZeroCopy) -> CheckResult {
    let parsed = parse_epoch_from_dwarf_protocol_message(cert);
    let payload = epoch_parse_payload(parsed);
    match verify_epoch_matches_protocol_message(cert) {
        Ok(()) => CheckResult::pass(payload),
        Err(_) => CheckResult::fail(ErrorCategory::EpochInProtocolMessageMismatch, payload),
    }
}

pub fn dwarf_epoch_chaining(cert: &CertificateZeroCopy, prev: &CertificateZeroCopy) -> CheckResult {
    let payload = epoch_pair_payload(cert.epoch, prev.epoch);
    match verify_epoch_chaining(cert, prev) {
        Ok(()) => CheckResult::pass(payload),
        Err(_) => CheckResult::fail(ErrorCategory::EpochChainGap, payload),
    }
}

pub fn dwarf_previous_hash_matches(
    cert: &CertificateZeroCopy,
    prev: &CertificateZeroCopy,
) -> CheckResult {
    match verify_previous_hash_matches(cert, prev) {
        Ok(()) => CheckResult::pass(Vec::new()),
        Err(_) => CheckResult::fail(ErrorCategory::PreviousHashMismatch, Vec::new()),
    }
}

pub fn dwarf_avk_same_epoch(cert: &CertificateZeroCopy, prev: &CertificateZeroCopy) -> CheckResult {
    if cert.epoch != prev.epoch {
        return CheckResult::not_applicable();
    }
    match verify_avk_same_epoch(cert, prev) {
        Ok(()) => CheckResult::pass(Vec::new()),
        Err(_) => CheckResult::fail(ErrorCategory::AvkMismatch, Vec::new()),
    }
}

pub fn dwarf_avk_chain(cert: &CertificateZeroCopy, prev: &CertificateZeroCopy) -> CheckResult {
    if cert.epoch == prev.epoch {
        return CheckResult::not_applicable();
    }
    match verify_avk_chain(cert, prev) {
        Ok(()) => CheckResult::pass(Vec::new()),
        Err(_) => CheckResult::fail(ErrorCategory::AvkChainMismatch, Vec::new()),
    }
}

pub fn dwarf_protocol_params_same_epoch(
    cert: &CertificateZeroCopy,
    prev: &CertificateZeroCopy,
) -> CheckResult {
    if cert.epoch != prev.epoch {
        return CheckResult::not_applicable();
    }
    match verify_protocol_params_same_epoch(cert, prev) {
        Ok(()) => CheckResult::pass(Vec::new()),
        Err(_) => CheckResult::fail(ErrorCategory::ProtocolParamsMismatch, Vec::new()),
    }
}

pub fn dwarf_protocol_params_chain(
    cert: &CertificateZeroCopy,
    prev: &CertificateZeroCopy,
) -> CheckResult {
    if cert.epoch == prev.epoch {
        return CheckResult::not_applicable();
    }
    match verify_protocol_params_chain(cert, prev) {
        Ok(()) => CheckResult::pass(Vec::new()),
        Err(_) => CheckResult::fail(ErrorCategory::ProtocolParamsChainMismatch, Vec::new()),
    }
}
