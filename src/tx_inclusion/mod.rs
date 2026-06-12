//! Cardano-transaction Merkle-inclusion proofs for the `oaks_tx` guest.
//!
//! Guest-side, serde-free, bit-equivalent to upstream iog/main
//! `MKMapProof<BlockRange>` (`mithril-common/src/crypto_helper/merkle_map.rs`).
//! The host transcodes the upstream bincode proof into a flat wire the guest
//! parses by slicing; the guest verifies via [`ckb_merkle_mountain_range`]
//! with a Blake2s256 merge and binds the result to the certified root.

mod leaf;
mod node;
mod proof;

pub use leaf::{build_tx_leaf, TxLeafInput, MAX_TX_LEAF_LEN};
pub use node::{merge_nodes, MKTreeNode, MergeMKTreeNode};
pub use proof::{BlockRange, MKMapProof, MKProof, TxError};
