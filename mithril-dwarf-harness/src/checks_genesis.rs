//! Per-check runners for genesis certificates.
//!
//! Genesis certificates are verified differently from standard ones:
//! there is no previous certificate, no AVK chaining, no BLS multi-
//! signature. Instead the signature is a plain Ed25519 signature over
//! the signed_message, verified with the network's bootstrap key.
//!
//! Both sides go through real verifier entrypoints — the Mithril side
//! uses `ProtocolGenesisVerificationKey::verify` (which internally calls
//! `verify_strict`, matching `MithrilCertificateVerifier::verify_genesis_certificate`);
//! the dwarf side uses `mithril_dwarf::certificate_verification::verify_genesis_certificate`.

use mithril_common::crypto_helper::ProtocolGenesisVerificationKey;
use mithril_common::entities::{Certificate, CertificateSignature, ProtocolMessagePartKey};
use mithril_dwarf::certificate_verification::medium_checks::{
    compute_certificate_hash, compute_protocol_message_hash, verify_hash_matches_content,
    verify_signed_message_matches_protocol,
};
use mithril_dwarf::certificate_verification::verify_genesis_certificate;
use mithril_dwarf::parser::byte_deserializer::CertificateZeroCopy;

use crate::check_helpers::{
    decode_sha256_hex, epoch_parse_payload, parse_epoch_from_dwarf_protocol_message,
};
use crate::types::{CheckResult, ErrorCategory};

pub const SPECS: &[(&str, &str)] = &[
    (
        "certificate_hash_matches_content",
        "SHA-256(canonical certificate bytes) == cert.hash",
    ),
    (
        "signed_message_matches_protocol_message",
        "SHA-256(canonical protocol_message bytes) == cert.signed_message",
    ),
    (
        "epoch_matches_protocol_message",
        "cert.epoch == protocol_message[CurrentEpoch]",
    ),
    (
        "ed25519_verify_genesis_signature",
        "ProtocolGenesisVerificationKey::verify (strict) succeeds over cert.signed_message",
    ),
];

// MITHRIL side

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

/// Mirrors Mithril's `verify_epoch_matches_protocol_message` semantics:
/// string-compare `protocol_message[CurrentEpoch]` against
/// `cert.epoch.to_string()`.
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

/// Verify the genesis Ed25519 signature exactly as
/// `MithrilCertificateVerifier::verify_genesis_certificate` does:
/// `ProtocolGenesisVerificationKey::verify(signed_message_bytes,
/// genesis_signature)`, which internally is
/// `ed25519_dalek::VerifyingKey::verify_strict`. Dwarf now matches
/// (see `verify_ed25519_signature`).
pub fn mithril_ed25519_verify(
    cert: &Certificate,
    genesis_vk: &ProtocolGenesisVerificationKey,
) -> CheckResult {
    match &cert.signature {
        CertificateSignature::GenesisSignature(genesis_sig) => {
            match genesis_vk.verify(cert.signed_message.as_bytes(), genesis_sig) {
                Ok(()) => CheckResult::pass(Vec::new()),
                Err(_) => CheckResult::fail(ErrorCategory::Ed25519VerifyFailed, Vec::new()),
            }
        }
        CertificateSignature::MultiSignature(_, _) => CheckResult::not_applicable(),
    }
}

// DWARF side — goes through dwarf's `verify_*` entrypoints, not raw
// `compute_*_hash` helpers. (Raw helpers would skip the verifier-level
// rejection paths and let a Pass slip through where the production
// verifier would reject.)

pub fn dwarf_certificate_hash_matches_content(cert: &CertificateZeroCopy) -> CheckResult {
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

pub fn dwarf_epoch_matches_protocol_message(cert: &CertificateZeroCopy) -> CheckResult {
    use mithril_dwarf::certificate_verification::basic_checks::verify_epoch_matches_protocol_message;
    let parsed = parse_epoch_from_dwarf_protocol_message(cert);
    let payload = epoch_parse_payload(parsed);
    match verify_epoch_matches_protocol_message(cert) {
        Ok(()) => CheckResult::pass(payload),
        Err(_) => CheckResult::fail(ErrorCategory::EpochInProtocolMessageMismatch, payload),
    }
}

pub fn dwarf_ed25519_verify(cert: &CertificateZeroCopy, genesis_vk: &[u8; 32]) -> CheckResult {
    use mithril_dwarf::parser::SignatureBasicZeroCopy;
    match &cert.signature {
        SignatureBasicZeroCopy::Genesis { .. } => {
            match verify_genesis_certificate(cert, genesis_vk) {
                Ok(()) => CheckResult::pass(Vec::new()),
                Err(_) => CheckResult::fail(ErrorCategory::Ed25519VerifyFailed, Vec::new()),
            }
        }
        SignatureBasicZeroCopy::Multi { .. } => CheckResult::not_applicable(),
    }
}
