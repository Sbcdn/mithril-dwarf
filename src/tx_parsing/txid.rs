//! Cardano transaction id = Blake2b-256 of the transaction body's raw CBOR.
//!
//! A Cardano transaction is a CBOR array `[body, witness_set, is_valid, aux]`;
//! its id is the Blake2b-256 digest of `body`'s *original* CBOR bytes (Conway
//! `Hasher::<256>::hash_cbor(transaction_body)` in pallas / the ledger). The
//! host pre-slices those bytes (Plutus CBOR is non-canonical, so the original
//! span — not a re-encoding — must be hashed); the guest only hashes.

use blake2::digest::consts::U32;
use blake2::{Blake2b, Digest};

/// `blake2b256(body_bytes)` where `body_bytes` is the raw CBOR of the tx body
/// (element 0 of the transaction array), as sliced by the host.
#[inline]
pub fn cardano_tx_id(body_bytes: &[u8]) -> [u8; 32] {
    Blake2b::<U32>::digest(body_bytes).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_blake2b256_of_input() {
        // Empty input: known Blake2b-256 digest of the empty message.
        let got = cardano_tx_id(&[]);
        let want = hex::decode("0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8")
            .unwrap();
        assert_eq!(got.as_slice(), want.as_slice());
    }

    #[test]
    fn distinct_inputs_distinct_ids() {
        assert_ne!(cardano_tx_id(b"a"), cardano_tx_id(b"b"));
    }
}
