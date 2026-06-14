//! Cardano-transaction Merkle-inclusion proofs for downstream zkVM guests.
//!
//! Guest-side, serde-free, bit-equivalent to upstream iog/main
//! `MKMapProof<BlockRange>` (`mithril-common/src/crypto_helper/merkle_map.rs`).
//! The host transcodes the upstream bincode proof into a flat wire the guest
//! parses by slicing; the guest verifies via [`ckb_merkle_mountain_range`]
//! with a Blake2s256 merge and binds the result to the certified root.

#[cfg(feature = "host")]
mod host;
mod leaf;
mod node;
mod proof;
mod wire;

#[cfg(feature = "host")]
pub use host::{tx_proof_to_wire_v1, tx_proof_to_wire_v2};
pub use leaf::{MAX_TX_LEAF_LEN, TxLeafInput, build_tx_leaf_v1, build_tx_leaf_v2};
pub use node::MKTreeNode;
pub use proof::{BlockRange, MKMapProof, MKProof, TxError};
pub use wire::{decode_proof, encode_proof};

/// Decode the wire proof, check it verifies, and bind its root to the certified
/// `expected_root` (32-byte Blake2s digest from the chain proof's journal). This
/// root binding is load-bearing: without it a proof over an attacker's own tree
/// would pass `verify`. Shared by both entrypoints, leaf-agnostic.
fn verify_and_bind(proof: &[u8], expected_root: &[u8; 32]) -> Result<MKMapProof, TxError> {
    let proof = decode_proof(proof)?;
    proof.verify()?;
    if proof.compute_root().as_bytes() != expected_root {
        return Err(TxError::RootMismatch);
    }
    Ok(proof)
}

/// Verify **v1** (`CardanoTransactions`) inclusion: every `tx_id` must be a leaf
/// of the proof, the proof must verify, and its root must equal the certified
/// `expected_root`. Returns `Err` (never panics) on any malformed input or
/// failed check; the caller owns aborting the proof.
pub fn verify_tx_inclusion_v1(
    proof: &[u8],
    tx_ids: &[[u8; 32]],
    expected_root: &[u8; 32],
) -> Result<(), TxError> {
    if tx_ids.is_empty() {
        return Err(TxError::LeafNotFound);
    }
    let proof = verify_and_bind(proof, expected_root)?;
    let mut buf = [0u8; 64];
    for tx_id in tx_ids {
        let leaf = build_tx_leaf_v1(tx_id, &mut buf);
        if !proof.contains(&MKTreeNode::new(leaf.to_vec())) {
            return Err(TxError::LeafNotFound);
        }
    }
    Ok(())
}

/// Verify **v2** (`CardanoBlocksTransactions`) inclusion: every composite leaf
/// (`Tx/{hash}/{block_hash}/{bn}/{sn}`) built from `leaves` must be in the proof,
/// the proof must verify, and its root must equal the certified `expected_root`.
/// The block fields are bound by the proof — a wrong field yields a leaf that the
/// proof does not contain. Returns `Err` (never panics) on any failure.
pub fn verify_tx_inclusion_v2(
    proof: &[u8],
    leaves: &[TxLeafInput],
    expected_root: &[u8; 32],
) -> Result<(), TxError> {
    if leaves.is_empty() {
        return Err(TxError::LeafNotFound);
    }
    let proof = verify_and_bind(proof, expected_root)?;
    let mut buf = [0u8; MAX_TX_LEAF_LEN];
    for input in leaves {
        let leaf = build_tx_leaf_v2(input, &mut buf);
        if !proof.contains(&MKTreeNode::new(leaf.to_vec())) {
            return Err(TxError::LeafNotFound);
        }
    }
    Ok(())
}
