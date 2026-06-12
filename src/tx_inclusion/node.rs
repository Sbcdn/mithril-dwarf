//! Merkle-tree node + Blake2s256 merge, bit-faithful to upstream iog/main
//! `mithril-common` `MKTreeNode` / `MergeMKTreeNode`
//! (`crypto_helper/merkle_tree.rs`).

use blake2::{Blake2s256, Digest};
use ckb_merkle_mountain_range::{Merge, Result as MMRResult};

/// A Merkle-tree node. A leaf holds its variable-length identifier bytes
/// (e.g. `Tx/{hash}/{block_hash}/{block_number}/{slot_number}`); an internal
/// node holds a 32-byte Blake2s256 digest. Mirrors upstream `MKTreeNode`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct MKTreeNode {
    bytes: Vec<u8>,
}

impl MKTreeNode {
    #[inline]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// `Blake2s256(left ‖ right)` — upstream `impl Add for &MKTreeNode`.
#[inline]
pub fn merge_nodes(left: &MKTreeNode, right: &MKTreeNode) -> MKTreeNode {
    let mut h = Blake2s256::new();
    h.update(&left.bytes);
    h.update(&right.bytes);
    MKTreeNode::new(h.finalize().to_vec())
}

/// ckb-mmr `Merge` = Blake2s256, identical to upstream `MergeMKTreeNode`.
/// `merge_peaks` is left as the crate default to match upstream (which does
/// not override it), preserving the peak-bagging order in `calculate_root`.
pub struct MergeMKTreeNode;

impl Merge for MergeMKTreeNode {
    type Item = MKTreeNode;

    #[inline]
    fn merge(left: &Self::Item, right: &Self::Item) -> MMRResult<Self::Item> {
        Ok(merge_nodes(left, right))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Upstream merge is Blake2s256(l ‖ r); pin the construction so a future
    // accidental swap to Blake2b or a reversed concatenation trips here.
    #[test]
    fn merge_is_blake2s256_left_then_right() {
        let l = MKTreeNode::new(b"left".to_vec());
        let r = MKTreeNode::new(b"right".to_vec());
        let got = merge_nodes(&l, &r);

        let mut h = Blake2s256::new();
        h.update(b"left");
        h.update(b"right");
        let want: [u8; 32] = h.finalize().into();
        assert_eq!(got.as_bytes(), &want);
        assert_eq!(got.as_bytes().len(), 32);
        // Order matters: swapping must change the digest.
        assert_ne!(merge_nodes(&r, &l).as_bytes(), got.as_bytes());
    }
}
