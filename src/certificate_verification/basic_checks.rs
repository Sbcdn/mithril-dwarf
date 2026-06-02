//! Phase 1 checks: comparisons only, no cryptography.

use super::VerifyError;
use crate::parser::CertificateZeroCopy;

/// `ProtocolMessagePartKey::CurrentEpoch` discriminant at upstream Mithril 2617.0.
const CURRENT_EPOCH: u8 = 5;

#[inline]
pub fn verify_not_infinite_loop(cert: &CertificateZeroCopy) -> Result<(), VerifyError> {
    if cert.hash == cert.previous_hash {
        return Err(VerifyError::InfiniteLoop);
    }
    Ok(())
}

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

/// Same epoch or `prev + 1`.
#[inline]
pub fn verify_epoch_chaining(
    cert: &CertificateZeroCopy,
    prev_cert: &CertificateZeroCopy,
) -> Result<(), VerifyError> {
    if cert.epoch != prev_cert.epoch && cert.epoch != prev_cert.epoch + 1 {
        return Err(VerifyError::EpochGap);
    }
    Ok(())
}

/// `cert.epoch` must match the `CurrentEpoch` part of the protocol message
/// (carried as UTF-8 decimal).
#[inline]
pub fn verify_epoch_matches_protocol_message(
    cert: &CertificateZeroCopy,
) -> Result<(), VerifyError> {
    for (key_discriminant, value) in &cert.protocol_message.parts {
        if *key_discriminant == CURRENT_EPOCH {
            let epoch_from_msg = parse_u64_from_utf8(value)?;
            if epoch_from_msg != cert.epoch {
                return Err(VerifyError::EpochMismatch);
            }
            return Ok(());
        }
    }
    Err(VerifyError::CurrentEpochNotFound)
}

#[inline]
pub fn verify_avk_same_epoch(
    cert: &CertificateZeroCopy,
    prev_cert: &CertificateZeroCopy,
) -> Result<(), VerifyError> {
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

#[inline]
pub fn verify_protocol_params_same_epoch(
    cert: &CertificateZeroCopy,
    prev_cert: &CertificateZeroCopy,
) -> Result<(), VerifyError> {
    let a = &cert.metadata;
    let b = &prev_cert.metadata;
    if a.k != b.k || a.m != b.m || a.phi_f != b.phi_f {
        return Err(VerifyError::ProtocolParamsMismatch);
    }
    Ok(())
}

#[inline]
fn parse_u64_from_utf8(bytes: &[u8]) -> Result<u64, VerifyError> {
    let s = core::str::from_utf8(bytes).map_err(|_| VerifyError::InvalidUtf8)?;
    s.parse::<u64>().map_err(|_| VerifyError::ParseIntError)
}
