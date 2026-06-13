//! Script and datum hashes, matching the Cardano ledger / pallas `ComputeHash`.
//! Blake2b only — no CBOR parse, no pallas — so they ride under `tx-parsing`
//! alongside the txid hasher. The locator (`tx-components`) feeds the exact
//! byte slices; these turn them into the `0x05` script / datum leaf hashes.

use blake2::digest::consts::{U28, U32};
use blake2::{Blake2b, Digest};

/// Script language. Its tag byte prefixes the script-hash preimage (ledger
/// `language`: native `0x00`, Plutus V1/V2/V3 `0x01`/`0x02`/`0x03`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ScriptLanguage {
    Native = 0x00,
    PlutusV1 = 0x01,
    PlutusV2 = 0x02,
    PlutusV3 = 0x03,
}

/// Script hash = `blake2b224(language_tag ‖ script_bytes)` (pallas
/// `ComputeHash<28>`). `script_bytes` is the native script's CBOR or a Plutus
/// script's raw bytes, exactly as the ledger hashes them.
pub fn script_hash(lang: ScriptLanguage, script_bytes: &[u8]) -> [u8; 28] {
    let mut h = Blake2b::<U28>::new();
    h.update([lang as u8]);
    h.update(script_bytes);
    h.finalize().into()
}

/// Datum hash = `blake2b256(datum_cbor)` (pallas `ComputeHash<32>`).
pub fn datum_hash(datum_bytes: &[u8]) -> [u8; 32] {
    Blake2b::<U32>::digest(datum_bytes).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn script_hash_is_tagged_blake2b224() {
        // Hash is 28 bytes and the language tag is part of the preimage:
        // the same bytes under different languages must differ.
        let bytes = b"\x82\x00\x00"; // arbitrary script-shaped CBOR
        let n = script_hash(ScriptLanguage::Native, bytes);
        let v1 = script_hash(ScriptLanguage::PlutusV1, bytes);
        let v2 = script_hash(ScriptLanguage::PlutusV2, bytes);
        assert_eq!(n.len(), 28);
        assert_ne!(n, v1);
        assert_ne!(v1, v2);

        // Explicit preimage: blake2b224(0x02 ‖ bytes).
        let mut h = Blake2b::<U28>::new();
        h.update([0x02u8]);
        h.update(bytes);
        let expect: [u8; 28] = h.finalize().into();
        assert_eq!(v2, expect);
    }

    #[test]
    fn datum_hash_is_blake2b256() {
        let d = b"\xd8\x79\x80"; // CBOR for an empty constructor
        let got = datum_hash(d);
        let expect: [u8; 32] = Blake2b::<U32>::digest(d).into();
        assert_eq!(got, expect);
        assert_eq!(got.len(), 32);
    }
}
