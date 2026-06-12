//! Differential equivalence: mithril-dwarf `tx-inclusion` vs upstream Mithril.
//!
//! Non-circular — the reference is upstream's REAL `MKMap`/`MKMapProof` code
//! (the pinned `mithril-common`, whose tx-merkle source is byte-identical to
//! iog/main and ed25519-2.1.1 so it links alongside dwarf). We build a genuine
//! upstream proof, transcode its bincode into dwarf's types via a serde mirror,
//! and assert dwarf's verify / compute_root / leaf / contains all match.

use std::sync::Arc;

use mithril_common::crypto_helper::{
    MKMap, MKMapNode, MKTree, MKTreeNode as UpNode, MKTreeStoreInMemory,
};
use mithril_common::entities::{
    BlockNumber, BlockRange, CardanoBlockTransactionMkTreeNode, CardanoTransaction, SlotNumber,
};
use serde::Deserialize;

use mithril_dwarf::tx_inclusion::{
    build_tx_leaf, BlockRange as DwarfBlockRange, MKMapProof as DwarfMapProof,
    MKProof as DwarfProof, MKTreeNode as DwarfNode, TxLeafInput, MAX_TX_LEAF_LEN,
};

// --- Transcoder: upstream bincode-2 MKMapProof -> dwarf types (host side) ---
// Mirrors upstream field order (`Arc<MKTreeNode>` serde == `MKTreeNode`).

#[derive(Deserialize)]
struct ProofMirror {
    inner_root: UpNode,
    inner_leaves: Vec<(u64, UpNode)>,
    inner_proof_size: u64,
    inner_proof_items: Vec<UpNode>,
}

#[derive(Deserialize)]
struct MapProofMirror {
    master_proof: ProofMirror,
    sub_proofs: Vec<(BlockRange, MapProofMirror)>,
}

fn node(up: &UpNode) -> DwarfNode {
    DwarfNode::new(up.to_vec())
}

fn proof(m: &ProofMirror) -> DwarfProof {
    DwarfProof {
        inner_root: node(&m.inner_root),
        inner_leaves: m.inner_leaves.iter().map(|(p, n)| (*p, node(n))).collect(),
        inner_proof_size: m.inner_proof_size,
        inner_proof_items: m.inner_proof_items.iter().map(node).collect(),
    }
}

fn map_proof(m: &MapProofMirror) -> DwarfMapProof {
    DwarfMapProof {
        master_proof: proof(&m.master_proof),
        sub_proofs: m
            .sub_proofs
            .iter()
            .map(|(r, sub)| (DwarfBlockRange { start: *r.start, end: *r.end }, map_proof(sub)))
            .collect(),
    }
}

fn transcode(upstream_bincode: &[u8]) -> Result<DwarfMapProof, ()> {
    let (mirror, _): (MapProofMirror, _) =
        bincode2::serde::decode_from_slice(upstream_bincode, bincode2::config::standard())
            .map_err(|_| ())?;
    Ok(map_proof(&mirror))
}

// --- Test fixtures built with upstream's real code ---

fn h32(s: &str) -> [u8; 32] {
    let v = hex::decode(s).unwrap();
    let mut a = [0u8; 32];
    a.copy_from_slice(&v);
    a
}

fn tx(hash: &str, bn: u64, sn: u64, bh: &str) -> CardanoTransaction {
    CardanoTransaction::new(hash, BlockNumber(bn), SlotNumber(sn), bh)
}

fn sample_txs() -> Vec<CardanoTransaction> {
    vec![
        tx(&"ab".repeat(32), 3, 30, &"07".repeat(32)),
        tx(&"cd".repeat(32), 5, 50, &"d4".repeat(32)),
        tx(&"ef".repeat(32), 7, 70, &"f0".repeat(32)),
    ]
}

/// Build a genuine two-level upstream proof (outer MKMap over one BlockRange,
/// inner MKTree of composite tx leaves). Returns (proof bincode, root bytes).
fn upstream_proof(txs: &[CardanoTransaction], prove_idx: &[usize]) -> (Vec<u8>, Vec<u8>) {
    let range = BlockRange::from_block_number(BlockNumber(0)); // [0, 15)
    let leaves: Vec<CardanoBlockTransactionMkTreeNode> =
        txs.iter().cloned().map(Into::into).collect();
    let inner = MKTree::<MKTreeStoreInMemory>::new(&leaves).unwrap();
    let entries = vec![(range, MKMapNode::Tree(Arc::new(inner)))];
    let mk_map = MKMap::<_, _, MKTreeStoreInMemory>::new(&entries).unwrap();
    let root = mk_map.compute_root().unwrap();

    let prove: Vec<UpNode> = prove_idx
        .iter()
        .map(|&i| CardanoBlockTransactionMkTreeNode::from(txs[i].clone()).into())
        .collect();
    let up_proof = mk_map.compute_proof(&prove).unwrap();
    up_proof.verify().expect("upstream proof must verify");

    (up_proof.to_bytes().unwrap(), root.to_vec())
}

#[test]
fn dwarf_verify_root_leaf_contains_match_upstream() {
    let txs = sample_txs();
    let prove = [0usize, 2];
    let (bytes, up_root) = upstream_proof(&txs, &prove);

    let mine = transcode(&bytes).expect("transcode upstream proof");

    // (1) dwarf accepts the valid upstream proof.
    assert_eq!(mine.verify(), Ok(()), "dwarf rejected a valid upstream proof");
    // (2) root bytes identical to upstream's certified root.
    assert_eq!(mine.compute_root().as_bytes(), up_root.as_slice(), "root mismatch");

    // (3) leaf bytes byte-identical to upstream's composite leaf_identifier; the
    //     transcoded proof contains exactly the proved leaves.
    for &i in &prove {
        let up_leaf: UpNode = CardanoBlockTransactionMkTreeNode::from(txs[i].clone()).into();
        let input = TxLeafInput {
            tx_id: h32(&txs[i].transaction_hash),
            block_hash: h32(&txs[i].block_hash),
            block_number: *txs[i].block_number,
            slot_number: *txs[i].slot_number,
        };
        let mut buf = [0u8; MAX_TX_LEAF_LEN];
        let my_leaf = build_tx_leaf(&input, &mut buf);
        assert_eq!(my_leaf, up_leaf.to_vec().as_slice(), "leaf bytes differ from upstream");
        assert!(mine.contains(&DwarfNode::new(my_leaf.to_vec())), "proof missing proved leaf {i}");
    }

    // The unproved tx's leaf must not be present.
    let other: UpNode = CardanoBlockTransactionMkTreeNode::from(txs[1].clone()).into();
    assert!(!mine.contains(&DwarfNode::new(other.to_vec())), "proof contains an unproved leaf");
}

/// Multi-block-range proof: txs span several `BlockRange`s, so the outer
/// MKMap has multiple leaves and the `MKMapProof` carries multiple sub-proofs
/// — exercising the master-MMR + the `master.contains(range‖sub_root)` binding.
fn upstream_proof_multi(txs: &[CardanoTransaction], prove_idx: &[usize]) -> (Vec<u8>, Vec<u8>) {
    use std::collections::BTreeMap;
    let mut by_range: BTreeMap<u64, Vec<CardanoBlockTransactionMkTreeNode>> = BTreeMap::new();
    for tx in txs {
        let r = BlockRange::from_block_number(tx.block_number);
        by_range.entry(*r.start).or_default().push(tx.clone().into());
    }
    let entries: Vec<_> = by_range
        .into_iter()
        .map(|(start, leaves)| {
            let range = BlockRange::from_block_number(BlockNumber(start));
            let tree = MKTree::<MKTreeStoreInMemory>::new(&leaves).unwrap();
            (range, MKMapNode::Tree(Arc::new(tree)))
        })
        .collect();
    let mk_map = MKMap::<_, _, MKTreeStoreInMemory>::new(&entries).unwrap();
    let root = mk_map.compute_root().unwrap();

    let prove: Vec<UpNode> = prove_idx
        .iter()
        .map(|&i| CardanoBlockTransactionMkTreeNode::from(txs[i].clone()).into())
        .collect();
    let up_proof = mk_map.compute_proof(&prove).unwrap();
    up_proof.verify().expect("upstream multi-range proof must verify");
    (up_proof.to_bytes().unwrap(), root.to_vec())
}

#[test]
fn dwarf_matches_upstream_multi_range() {
    // 5 txs across 4 block ranges ([0,15),[15,30),[30,45),[45,60)).
    let txs = vec![
        tx(&"11".repeat(32), 3, 30, &"a1".repeat(32)),
        tx(&"22".repeat(32), 8, 80, &"a2".repeat(32)),
        tx(&"33".repeat(32), 20, 200, &"a3".repeat(32)),
        tx(&"44".repeat(32), 35, 350, &"a4".repeat(32)),
        tx(&"55".repeat(32), 50, 500, &"a5".repeat(32)),
    ];
    let prove = [0usize, 2, 4]; // one per several distinct ranges
    let (bytes, up_root) = upstream_proof_multi(&txs, &prove);
    let mine = transcode(&bytes).expect("transcode");

    assert_eq!(mine.verify(), Ok(()), "dwarf rejected a valid multi-range proof");
    assert_eq!(mine.compute_root().as_bytes(), up_root.as_slice(), "multi-range root mismatch");
    for &i in &prove {
        let up_leaf: UpNode = CardanoBlockTransactionMkTreeNode::from(txs[i].clone()).into();
        let input = TxLeafInput {
            tx_id: h32(&txs[i].transaction_hash),
            block_hash: h32(&txs[i].block_hash),
            block_number: *txs[i].block_number,
            slot_number: *txs[i].slot_number,
        };
        let mut buf = [0u8; MAX_TX_LEAF_LEN];
        let my_leaf = build_tx_leaf(&input, &mut buf);
        assert_eq!(my_leaf, up_leaf.to_vec().as_slice(), "multi-range leaf mismatch tx {i}");
        assert!(mine.contains(&DwarfNode::new(my_leaf.to_vec())), "missing proved leaf {i}");
    }
    // An unproved tx (range [15,30)) must be absent.
    let other: UpNode = CardanoBlockTransactionMkTreeNode::from(txs[1].clone()).into();
    assert!(!mine.contains(&DwarfNode::new(other.to_vec())), "contains an unproved leaf");
}

#[test]
fn dwarf_rejects_tampered_proof() {
    let txs = sample_txs();
    let (bytes, _root) = upstream_proof(&txs, &[0]);

    for flip in [bytes.len() - 1, bytes.len() / 2, bytes.len() / 4] {
        let mut bad = bytes.clone();
        bad[flip] ^= 0xFF;
        let verdict = std::panic::catch_unwind(|| match transcode(&bad) {
            Ok(p) => p.verify().is_ok(),
            Err(()) => false,
        });
        assert_eq!(verdict.ok(), Some(false), "accepted or panicked on tampered byte {flip}");
    }
}
