//! Transaction leaf identifier, byte-for-byte equal to upstream iog/main
//! `CardanoBlockTransactionMkTreeNode::leaf_identifier` for the `Transaction`
//! variant: `Tx/{transaction_hash}/{block_hash}/{block_number}/{slot_number}`,
//! hashes as lowercase hex, numbers as decimal. Built into a stack buffer with
//! the existing hex/decimal helpers — no `format!`, no heap `String`.

use crate::certificate_verification::medium_checks::{hex_digest_to_buf, write_u64_dec};

/// Binary fields the guest binds; the leaf string is built from these.
#[derive(Clone, Copy, Debug)]
pub struct TxLeafInput {
    pub tx_id: [u8; 32],
    pub block_hash: [u8; 32],
    pub block_number: u64,
    pub slot_number: u64,
}

/// Upper bound on a tx leaf: `"Tx/"` + 64 hex + `"/"` + 64 hex + `"/"` + 20
/// decimal + `"/"` + 20 decimal.
pub const MAX_TX_LEAF_LEN: usize = 3 + 64 + 1 + 64 + 1 + 20 + 1 + 20;

/// Write `n` as decimal into `out` at `pos` via the shared `write_u64_dec`
/// (matches upstream `u64::to_string`), returning the new position.
#[inline]
pub(super) fn write_u64_dec_into(out: &mut [u8], pos: usize, n: u64) -> usize {
    let mut w = SliceWriter { buf: out, pos };
    let _ = write_u64_dec(&mut w, n);
    w.pos
}

/// `core::fmt::Write` over a fixed stack buffer; lets us reuse the optimized
/// `write_u64_dec` for the decimal fields without a heap `String`.
struct SliceWriter<'a> {
    buf: &'a mut [u8],
    pos: usize,
}

impl core::fmt::Write for SliceWriter<'_> {
    #[inline]
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        let b = s.as_bytes();
        let end = self.pos + b.len();
        if end > self.buf.len() {
            return Err(core::fmt::Error);
        }
        self.buf[self.pos..end].copy_from_slice(b);
        self.pos = end;
        Ok(())
    }
}

/// v1 (`CardanoTransactions`) leaf: the bare `transaction_hash` as a 64-char
/// lowercase-hex string (the current public-mainnet format). Distinct from the
/// composite v2 leaf ([`build_tx_leaf_v2`]).
#[inline]
pub fn build_tx_leaf_v1<'a>(tx_id: &[u8; 32], out: &'a mut [u8; 64]) -> &'a [u8] {
    hex_digest_to_buf(tx_id, out);
    out
}

/// v2 (`CardanoBlocksTransactions`) leaf, byte-for-byte equal to upstream
/// `leaf_identifier`. Write it into `out` (>= [`MAX_TX_LEAF_LEN`]) and return
/// the written prefix.
#[inline]
pub fn build_tx_leaf_v2<'a>(input: &TxLeafInput, out: &'a mut [u8; MAX_TX_LEAF_LEN]) -> &'a [u8] {
    let mut pos = 0usize;
    let push = |out: &mut [u8; MAX_TX_LEAF_LEN], pos: &mut usize, bytes: &[u8]| {
        out[*pos..*pos + bytes.len()].copy_from_slice(bytes);
        *pos += bytes.len();
    };

    push(out, &mut pos, b"Tx/");
    {
        let mut hex = [0u8; 64];
        hex_digest_to_buf(&input.tx_id, &mut hex);
        push(out, &mut pos, &hex);
    }
    push(out, &mut pos, b"/");
    {
        let mut hex = [0u8; 64];
        hex_digest_to_buf(&input.block_hash, &mut hex);
        push(out, &mut pos, &hex);
    }
    push(out, &mut pos, b"/");
    pos = write_u64_dec_into(out, pos, input.block_number);
    push(out, &mut pos, b"/");
    pos = write_u64_dec_into(out, pos, input.slot_number);

    &out[..pos]
}

#[cfg(test)]
mod tests {
    use super::*;

    // Byte-for-byte vs the upstream format string (the test may use `format!`;
    // the production path must not). Pins lowercase hex + decimal numbers.
    #[test]
    fn leaf_matches_upstream_format() {
        let input = TxLeafInput {
            tx_id: [0xABu8; 32],
            block_hash: [0x07u8; 32],
            block_number: 12_345,
            slot_number: 9_876_543_210,
        };
        let mut buf = [0u8; MAX_TX_LEAF_LEN];
        let got = build_tx_leaf_v2(&input, &mut buf);

        let want = format!(
            "Tx/{}/{}/{}/{}",
            hex::encode(input.tx_id),
            hex::encode(input.block_hash),
            input.block_number,
            input.slot_number,
        );
        assert_eq!(got, want.as_bytes());
        // Sanity: lowercase hex, exactly 64 chars per hash.
        assert!(want.starts_with("Tx/abab"));
    }

    #[test]
    fn leaf_handles_zero_numbers() {
        let input = TxLeafInput {
            tx_id: [0u8; 32],
            block_hash: [0xFFu8; 32],
            block_number: 0,
            slot_number: 0,
        };
        let mut buf = [0u8; MAX_TX_LEAF_LEN];
        let got = build_tx_leaf_v2(&input, &mut buf);
        let want = format!(
            "Tx/{}/{}/0/0",
            hex::encode(input.tx_id),
            hex::encode(input.block_hash)
        );
        assert_eq!(got, want.as_bytes());
    }
}
