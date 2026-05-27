//! Ultra-cheap verification checks (simple comparisons, no cryptography)
//! These checks use only comparisons and should be done first to fail fast.

use super::VerifyError;
use crate::parser::CertificateZeroCopy;

// Protocol message part key discriminants
const CURRENT_EPOCH: u8 = 4;

/// Check if certificate is chaining to itself (infinite loop)
/// Just a slice comparison.
#[inline]
pub fn verify_not_infinite_loop(cert: &CertificateZeroCopy) -> Result<(), VerifyError> {
    if cert.hash == cert.previous_hash {
        return Err(VerifyError::InfiniteLoop);
    }
    Ok(())
}

/// Verify that certificate's previous_hash matches the previous certificate's hash
/// Slice comparison.
#[inline]
pub fn verify_previous_hash_matches(
    cert: &CertificateZeroCopy,
    prev_cert: &CertificateZeroCopy,
) -> Result<(), VerifyError> {
    if cert.previous_hash != prev_cert.hash {
        return Err(VerifyError::PreviousHashMismatch);
    }
    Ok(())
}

/// Verify epoch chaining: epochs must be same or increment by exactly 1
/// Two u64 comparisons.
#[inline]
pub fn verify_epoch_chaining(
    cert: &CertificateZeroCopy,
    prev_cert: &CertificateZeroCopy,
) -> Result<(), VerifyError> {
    let curr_epoch = cert.epoch;
    let prev_epoch = prev_cert.epoch;

    // Epochs must be same or increment by 1
    if curr_epoch != prev_epoch && curr_epoch != prev_epoch + 1 {
        return Err(VerifyError::EpochGap);
    }
    Ok(())
}

/// Verify that epoch in certificate matches the CurrentEpoch in protocol_message
/// Iterates protocol message parts, parses number.
#[inline]
pub fn verify_epoch_matches_protocol_message(
    cert: &CertificateZeroCopy,
) -> Result<(), VerifyError> {
    // Find CurrentEpoch (discriminant = 4) in protocol message
    for (key_discriminant, value) in &cert.protocol_message.parts {
        if *key_discriminant == CURRENT_EPOCH {
            // Parse epoch from bytes (it's stored as UTF-8 string)
            let epoch_from_msg = parse_u64_from_utf8(value)?;
            if epoch_from_msg != cert.epoch {
                return Err(VerifyError::EpochMismatch);
            }
            return Ok(());
        }
    }
    Err(VerifyError::CurrentEpochNotFound)
}

/// Verify AVK chaining when certificates are in SAME epoch
/// Slice comparison.
#[inline]
pub fn verify_avk_same_epoch(
    cert: &CertificateZeroCopy,
    prev_cert: &CertificateZeroCopy,
) -> Result<(), VerifyError> {
    // Compare all three fields
    if cert.aggregate_verification_key.root != prev_cert.aggregate_verification_key.root
        || cert.aggregate_verification_key.nr_leaves
            != prev_cert.aggregate_verification_key.nr_leaves
        || cert.aggregate_verification_key.total_stake
            != prev_cert.aggregate_verification_key.total_stake
    {
        return Err(VerifyError::AVKMismatch);
    }
    Ok(())
}

/// Verify protocol parameters chaining when certificates are in SAME epoch
/// Compares k, m, phi_f.
#[inline]
pub fn verify_protocol_params_same_epoch(
    cert: &CertificateZeroCopy,
    prev_cert: &CertificateZeroCopy,
) -> Result<(), VerifyError> {
    let curr_params = &cert.metadata;
    let prev_params = &prev_cert.metadata;

    if curr_params.k != prev_params.k
        || curr_params.m != prev_params.m
        || curr_params.phi_f != prev_params.phi_f
    {
        return Err(VerifyError::ProtocolParamsMismatch);
    }
    Ok(())
}

// Helper: Parse u64 from UTF-8 bytes (used for epoch parsing)
// UTF-8 validation + parse
#[inline]
fn parse_u64_from_utf8(bytes: &[u8]) -> Result<u64, VerifyError> {
    let s = core::str::from_utf8(bytes).map_err(|_| VerifyError::InvalidUtf8)?;
    s.parse::<u64>().map_err(|_| VerifyError::ParseIntError)
}

#[cfg(test)]
mod tests {
    //use super::*;

    // Test helpers would go here
    // We can add these later for unit testing
}
