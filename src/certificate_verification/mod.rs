//! Certificate verification for RISC0
//! Optimized for minimal cycle count while maintaining security
//use risc0_zkvm::guest::env;

pub mod basic_checks;
pub mod complex_checks;
pub mod medium_checks;

use crate::parser::byte_deserializer::{CertificateZeroCopy, SignatureBasicZeroCopy};

/// Lightweight error type (no string allocations!)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyError {
    // Basic check errors (~5K cycles)
    InfiniteLoop,
    PreviousHashMismatch,
    EpochGap,
    EpochMismatch,
    CurrentEpochNotFound,

    // Medium check errors (~100K cycles)
    HashMismatch,
    SignedMessageMismatch,

    // Chain verification errors
    AVKMismatch,
    ProtocolParamsMismatch,
    NextAVKNotFound,
    NextProtocolParamsNotFound,

    // BLS verification errors (~23M cycles)
    BLSVerificationFailed,
    IndexOutOfBounds,
    IndexNotUnique,
    LotteryLost,
    NoQuorum,
    BatchProofInvalid,

    // Genesis verification errors
    Ed25519VerificationFailed,
    InvalidGenesisSignature,

    // Parsing/encoding errors
    InvalidUtf8,
    ParseIntError,
    InvalidHexEncoding,
    FormatError,

    // Type errors
    NotStandardCertificate,
    NotGenesisCertificate,

    // Batch proof errors
    InvalidBatchProof,
    InvalidAVKEncoding,
    InvalidProtocolParamsHash,

    // Placeholder
    NotImplemented,
}

/// Verify a genesis certificate
/// Genesis certificates use Ed25519 signature instead of BLS multi-signature
pub fn verify_genesis_certificate(
    cert: &CertificateZeroCopy,
    genesis_vk: &[u8; 32], // Ed25519 public key
) -> Result<(), VerifyError> {
    // Must be genesis signature
    let genesis_sig = match &cert.signature {
        SignatureBasicZeroCopy::Genesis { signature_bytes } => signature_bytes,
        _ => return Err(VerifyError::NotGenesisCertificate),
    };

    // Check hash matches content
    medium_checks::verify_hash_matches_content(cert)?;

    // Check signed message matches protocol message
    medium_checks::verify_signed_message_matches_protocol(cert)?;

    // Check epoch matches protocol message
    basic_checks::verify_epoch_matches_protocol_message(cert)?;

    // Verify Ed25519 signature
    verify_ed25519_signature(cert.signed_message, genesis_sig, genesis_vk)?;

    Ok(())
}

/// Verify a standard (non-genesis) certificate against its previous certificate
/// This follows Mithril's verify_standard_certificate logic exactly
pub fn verify_standard_certificate(
    cert: &CertificateZeroCopy,
    prev_cert: &CertificateZeroCopy,
) -> Result<(), VerifyError> {
    // Must be multi signature
    let _multi_sig = match &cert.signature {
        SignatureBasicZeroCopy::Multi { signature, .. } => signature,
        _ => return Err(VerifyError::NotStandardCertificate),
    };

    // === PHASE 1: BASIC CHECKS (~5K cycles) ===
    // Fail fast checks that don't require computation
    //let start = env::cycle_count();
    basic_checks::verify_not_infinite_loop(cert)?;
    //let end = env::cycle_count();
    //eprintln!("verify_not_infinite_loop: {}", end - start);

    //let start = env::cycle_count();
    basic_checks::verify_epoch_matches_protocol_message(cert)?;
    //let end = env::cycle_count();
    //eprintln!("verify_epoch_matches_protocol_message: {}", end - start);

    //let start = env::cycle_count();
    basic_checks::verify_epoch_chaining(cert, prev_cert)?;
    //let end = env::cycle_count();
    //eprintln!("verify_epoch_chaining: {}", end - start);

    //let start = env::cycle_count();
    basic_checks::verify_previous_hash_matches(cert, prev_cert)?;
    //let end = env::cycle_count();
    //eprintln!("verify_previous_hash_matches: {}", end - start);

    // === PHASE 2: MEDIUM CHECKS (~100K cycles) ===
    // Hash computations
    //let start = env::cycle_count();
    medium_checks::verify_hash_matches_content(cert)?;
    //let end = env::cycle_count();
    //eprintln!("verify_hash_matches_content: {}", end - start);

    //let start = env::cycle_count();
    medium_checks::verify_signed_message_matches_protocol(cert)?;
    //let end = env::cycle_count();
    //eprintln!("verify_signed_message_matches_protocol: {}", end - start);

    // === PHASE 3: CHAIN VERIFICATION ===
    // AVK and protocol params chaining
    let same_epoch = cert.epoch == prev_cert.epoch;

    if same_epoch {
        // Same epoch: must match exactly
        basic_checks::verify_avk_same_epoch(cert, prev_cert)?;
        basic_checks::verify_protocol_params_same_epoch(cert, prev_cert)?;
    } else {
        // Different epoch: check against next_ values from previous cert
        //let start = env::cycle_count();
        complex_checks::verify_avk_chain(cert, prev_cert)?;
        //let end = env::cycle_count();
        //eprintln!("verify_avk_chain: {}", end - start);
        //let start = env::cycle_count();
        complex_checks::verify_protocol_params_chain(cert, prev_cert)?;
        //let end = env::cycle_count();
        //eprintln!("verify_protocol_params_chain: {}", end - start);
    }

    // === PHASE 4: BLS MULTI-SIGNATURE VERIFICATION (~23M cycles) ===
    // Most expensive check - only if all above passed!
    //let start = env::cycle_count();
    complex_checks::verify_bls_multisig(cert)?;
    //let end = env::cycle_count();
    //eprintln!("verify_bls_multisig: {}", end - start);

    Ok(())
}

/// Verify a certificate (either genesis or standard)
/// This is the main entry point that determines certificate type
/// Matches Mithril's verify_certificate function
pub fn verify_certificate(
    cert: &CertificateZeroCopy,
    prev_cert: Option<&CertificateZeroCopy>,
    genesis_vk: &[u8; 32],
) -> Result<(), VerifyError> {
    match &cert.signature {
        SignatureBasicZeroCopy::Genesis { .. } => {
            // Genesis certificate
            verify_genesis_certificate(cert, genesis_vk)
        }
        SignatureBasicZeroCopy::Multi { .. } => {
            // Standard certificate - needs previous certificate
            let prev = prev_cert.ok_or(VerifyError::PreviousHashMismatch)?;
            verify_standard_certificate(cert, prev)
        }
    }
}

/// Verify an entire certificate chain
/// Starts from the given certificate and walks backwards to genesis
/// This matches Mithril's verify_certificate_chain logic
pub fn verify_certificate_chain(
    certificates: &[CertificateZeroCopy],
    genesis_vk: &[u8; 32],
) -> Result<(), VerifyError> {
    if certificates.is_empty() {
        return Ok(());
    }

    // Verify each certificate in order (newest to oldest)
    for i in 0..certificates.len() {
        let cert = &certificates[i];
        let prev_cert = if i + 1 < certificates.len() {
            Some(&certificates[i + 1])
        } else {
            None
        };

        verify_certificate(cert, prev_cert, genesis_vk)?;
    }

    Ok(())
}

/// Verify Ed25519 signature (for genesis certificates)
/// Uses RISC0's Ed25519 precompile if available, otherwise software implementation
fn verify_ed25519_signature(
    message: &[u8],
    signature: &[u8],
    public_key: &[u8; 32],
) -> Result<(), VerifyError> {
    // Use ed25519-dalek for host testing
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

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

    vk.verify(message, &sig)
        .map_err(|_| VerifyError::Ed25519VerificationFailed)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verify_error_size() {
        // Ensure error type is small (important for RISC0)
        assert!(core::mem::size_of::<VerifyError>() <= 4);
    }
}
