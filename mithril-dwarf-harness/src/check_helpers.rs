//! Shared helpers used by both `checks_standard` and `checks_genesis`.

use mithril_dwarf::parser::byte_deserializer::CertificateZeroCopy;

/// Discriminant byte for `ProtocolMessagePartKey::CurrentEpoch` in dwarf's
/// zero-copy parser.
///
/// MUST stay in sync with `CURRENT_EPOCH` in
/// `mithril-dwarf/src/certificate_verification/basic_checks.rs`.
/// Both are derived from the writer in `src/parser/byte_deserializer.rs`.
pub const CURRENT_EPOCH_DISCRIMINANT: u8 = 5;

/// Decode a SHA-256 hex string into bytes. A successful decode produces
/// the 32 raw digest bytes prefixed with `0x00`; a failure produces the
/// original ASCII bytes prefixed with `0x01`. The tag byte prevents two
/// silent decode failures from byte-matching each other.
pub fn decode_sha256_hex(hex_str: &str) -> Vec<u8> {
    match hex::decode(hex_str) {
        Ok(bytes) => {
            let mut out = Vec::with_capacity(1 + bytes.len());
            out.push(0x00);
            out.extend_from_slice(&bytes);
            out
        }
        Err(_) => {
            let mut out = Vec::with_capacity(1 + hex_str.len());
            out.push(0x01);
            out.extend_from_slice(hex_str.as_bytes());
            out
        }
    }
}

/// Pack `cert.epoch` and `prev.epoch` as concatenated big-endian u64s.
pub fn epoch_pair_payload(cert_epoch: u64, prev_epoch: u64) -> Vec<u8> {
    const PAYLOAD_LEN: usize = 2 * core::mem::size_of::<u64>();
    let mut out = Vec::with_capacity(PAYLOAD_LEN);
    out.extend_from_slice(&cert_epoch.to_be_bytes());
    out.extend_from_slice(&prev_epoch.to_be_bytes());
    out
}

/// Parse `protocol_message[CurrentEpoch]` from a dwarf-parsed cert. The
/// value lives as UTF-8 decimal in the zero-copy `parts` map.
pub fn parse_epoch_from_dwarf_protocol_message(cert: &CertificateZeroCopy) -> Option<u64> {
    for (key, value) in &cert.protocol_message.parts {
        if *key == CURRENT_EPOCH_DISCRIMINANT {
            let s = core::str::from_utf8(value).ok()?;
            return s.parse::<u64>().ok();
        }
    }
    None
}

/// Encode a parsed-or-missing epoch into a single canonical byte block.
/// Tag byte `0x00` for `Some(_)`, `0x01` for `None`. The tag prevents a
/// missing-epoch sentinel from colliding with a legitimate value of
/// `u64::MAX`.
pub fn epoch_parse_payload(parsed: Option<u64>) -> Vec<u8> {
    let mut out = Vec::with_capacity(9);
    match parsed {
        Some(p) => {
            out.push(0x00);
            out.extend_from_slice(&p.to_be_bytes());
        }
        None => {
            out.push(0x01);
            out.extend_from_slice(&u64::MAX.to_be_bytes());
        }
    }
    out
}
