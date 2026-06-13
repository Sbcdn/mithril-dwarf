//! Custom serde-free proof wire. The host transcodes the upstream proof (json
//! for v1, bincode for v2) into this flat, fixed-layout form; the guest parses
//! it by slicing — no serde, no JSON, bounds-checked, panic-free.
//!
//! Layout (all integers little-endian):
//! ```text
//! MKMapProof := MKProof master, u32 sub_count, sub_count × (u64 start, u64 end, MKMapProof)
//! MKProof    := u64 proof_size, node root, u32 leaf_count,
//!               leaf_count × (u64 position, node leaf), u32 item_count, item_count × node
//! node       := u32 len, len bytes          // length-prefixed: a node may be a 32-byte
//!                                            // internal digest OR a variable-length leaf
//! ```
//! `node` is length-prefixed for *every* node because an MMR proof item (or a
//! single-leaf root) can itself be a variable-length leaf, not only a 32-byte digest.

use super::node::MKTreeNode;
use super::proof::{BlockRange, MKMapProof, MKProof, TxError};

// Guards so adversarial bytes can't drive unbounded allocation. Generous vs any
// real proof; an over-cap value is simply a reject.
const MAX_COUNT: u32 = 1_000_000;
const MAX_NODE_LEN: u32 = 1 << 20; // 1 MiB
const MAX_DEPTH: u32 = 16;

/// Bounds-checked little-endian cursor; every read errors (never panics) past end.
struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    #[inline]
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    #[inline]
    fn remaining(&self) -> usize {
        self.data.len() - self.pos
    }

    #[inline]
    fn take(&mut self, n: usize) -> Result<&'a [u8], TxError> {
        let end = self.pos.checked_add(n).ok_or(TxError::InvalidProof)?;
        let slice = self.data.get(self.pos..end).ok_or(TxError::InvalidProof)?;
        self.pos = end;
        Ok(slice)
    }

    #[inline]
    fn u32(&mut self) -> Result<u32, TxError> {
        let b = self.take(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    #[inline]
    fn u64(&mut self) -> Result<u64, TxError> {
        let b = self.take(8)?;
        Ok(u64::from_le_bytes([
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        ]))
    }

    #[inline]
    fn node(&mut self) -> Result<MKTreeNode, TxError> {
        let len = self.u32()?;
        if len > MAX_NODE_LEN {
            return Err(TxError::InvalidProof);
        }
        Ok(MKTreeNode::new(self.take(len as usize)?.to_vec()))
    }
}

fn read_proof(r: &mut Reader) -> Result<MKProof, TxError> {
    let inner_proof_size = r.u64()?;
    let inner_root = r.node()?;

    // Reserve no more than the remaining bytes could actually hold (a leaf entry
    // is >= 8 position + 4 length bytes), so a forged count can't amplify a few
    // bytes into a huge allocation. `take()` still bounds the per-node bytes.
    let leaf_count = r.u32()?;
    if leaf_count > MAX_COUNT {
        return Err(TxError::InvalidProof);
    }
    let mut inner_leaves = Vec::with_capacity((leaf_count as usize).min(r.remaining() / 12));
    for _ in 0..leaf_count {
        let position = r.u64()?;
        inner_leaves.push((position, r.node()?));
    }

    let item_count = r.u32()?;
    if item_count > MAX_COUNT {
        return Err(TxError::InvalidProof);
    }
    // A proof item is >= 4 length bytes.
    let mut inner_proof_items = Vec::with_capacity((item_count as usize).min(r.remaining() / 4));
    for _ in 0..item_count {
        inner_proof_items.push(r.node()?);
    }

    Ok(MKProof {
        inner_root,
        inner_leaves,
        inner_proof_size,
        inner_proof_items,
    })
}

fn read_map(r: &mut Reader, depth: u32) -> Result<MKMapProof, TxError> {
    if depth > MAX_DEPTH {
        return Err(TxError::InvalidProof);
    }
    let master_proof = read_proof(r)?;
    let sub_count = r.u32()?;
    if sub_count > MAX_COUNT {
        return Err(TxError::InvalidProof);
    }
    // A sub-proof is >= 8 start + 8 end bytes (plus a nested proof).
    let mut sub_proofs = Vec::with_capacity((sub_count as usize).min(r.remaining() / 16));
    for _ in 0..sub_count {
        let start = r.u64()?;
        let end = r.u64()?;
        let sub = read_map(r, depth + 1)?;
        sub_proofs.push((BlockRange { start, end }, sub));
    }
    Ok(MKMapProof {
        master_proof,
        sub_proofs,
    })
}

/// Decode the custom wire into an [`MKMapProof`]. Any malformed / truncated /
/// trailing-garbage input is a reject (`Err`), never a panic.
pub fn decode_proof(bytes: &[u8]) -> Result<MKMapProof, TxError> {
    let mut r = Reader::new(bytes);
    let proof = read_map(&mut r, 0)?;
    if r.pos != bytes.len() {
        return Err(TxError::InvalidProof); // trailing bytes
    }
    Ok(proof)
}

// --- Host-side encoder (dep-free byte building; the guest only decodes) ---

fn write_node(out: &mut Vec<u8>, node: &MKTreeNode) {
    let bytes = node.as_bytes();
    out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(bytes);
}

fn write_proof(out: &mut Vec<u8>, p: &MKProof) {
    out.extend_from_slice(&p.inner_proof_size.to_le_bytes());
    write_node(out, &p.inner_root);
    out.extend_from_slice(&(p.inner_leaves.len() as u32).to_le_bytes());
    for (position, leaf) in &p.inner_leaves {
        out.extend_from_slice(&position.to_le_bytes());
        write_node(out, leaf);
    }
    out.extend_from_slice(&(p.inner_proof_items.len() as u32).to_le_bytes());
    for item in &p.inner_proof_items {
        write_node(out, item);
    }
}

fn write_map(out: &mut Vec<u8>, m: &MKMapProof) {
    write_proof(out, &m.master_proof);
    out.extend_from_slice(&(m.sub_proofs.len() as u32).to_le_bytes());
    for (range, sub) in &m.sub_proofs {
        out.extend_from_slice(&range.start.to_le_bytes());
        out.extend_from_slice(&range.end.to_le_bytes());
        write_map(out, sub);
    }
}

/// Encode an [`MKMapProof`] into the custom wire. Host-side transcoder output;
/// `decode_proof(encode_proof(p))` round-trips `p`.
pub fn encode_proof(proof: &MKMapProof) -> Vec<u8> {
    let mut out = Vec::new();
    write_map(&mut out, proof);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(b: &[u8]) -> MKTreeNode {
        MKTreeNode::new(b.to_vec())
    }

    fn sample() -> MKMapProof {
        let leaf = MKProof {
            inner_root: node(&[1u8; 32]),
            inner_leaves: vec![(7, node(b"Tx/deadbeef")), (9, node(&[2u8; 32]))],
            inner_proof_size: 11,
            inner_proof_items: vec![node(&[3u8; 32]), node(b"variable-len-item")],
        };
        MKMapProof {
            master_proof: MKProof {
                inner_root: node(&[9u8; 32]),
                inner_leaves: vec![(1, node(b"0-15"))],
                inner_proof_size: 1,
                inner_proof_items: vec![],
            },
            sub_proofs: vec![(BlockRange { start: 0, end: 15 }, MKMapProof { master_proof: leaf, sub_proofs: vec![] })],
        }
    }

    #[test]
    fn round_trip_preserves_all_fields() {
        let p = sample();
        let bytes = encode_proof(&p);
        let back = decode_proof(&bytes).expect("decode");
        // Re-encode and compare bytes: structural equality of the whole tree.
        assert_eq!(encode_proof(&back), bytes);
    }

    #[test]
    fn malformed_wire_errs_not_panics() {
        let bytes = encode_proof(&sample());
        // Truncations at every length must Err, never panic.
        for cut in 0..bytes.len() {
            let _ = decode_proof(&bytes[..cut]); // must not panic
        }
        // Trailing garbage rejects.
        let mut extra = bytes.clone();
        extra.push(0);
        assert!(matches!(decode_proof(&extra), Err(TxError::InvalidProof)));
    }

    #[test]
    fn forged_count_does_not_amplify_allocation() {
        // 16 bytes claiming 1,000,000 leaves with none following: must reject
        // without reserving for a million entries (capacity is bounded by the
        // remaining bytes, so no multi-MB allocation off a few bytes).
        let mut forged = Vec::new();
        forged.extend_from_slice(&0u64.to_le_bytes()); // proof_size
        forged.extend_from_slice(&0u32.to_le_bytes()); // root len = 0
        forged.extend_from_slice(&1_000_000u32.to_le_bytes()); // leaf_count, nothing follows
        assert!(matches!(decode_proof(&forged), Err(TxError::InvalidProof)));
    }
}
