//! Differential equivalence: mithril-dwarf `tx-inclusion` vs upstream Mithril.
//!
//! Non-circular — the reference is upstream's REAL `MKMap`/`MKMapProof` code
//! (the pinned `mithril-common`, whose tx-merkle source is byte-identical to
//! iog/main and ed25519-2.1.1 so it links alongside dwarf). We build a genuine
//! upstream proof, run it through dwarf's host transcoder + guest wire decoder
//! (the production path), and assert dwarf's verify / compute_root / leaf /
//! contains all match upstream.

use std::sync::Arc;

use mithril_common::crypto_helper::{MKMap, MKMapNode, MKTree, MKTreeNode as UpNode, MKTreeStoreInMemory};
use mithril_common::entities::{
    BlockNumber, BlockRange, CardanoBlockTransactionMkTreeNode, CardanoTransaction, SlotNumber,
};

use mithril_dwarf::tx_inclusion::{
    build_tx_leaf_v1, build_tx_leaf_v2, decode_proof, encode_proof, tx_proof_to_wire_v1,
    tx_proof_to_wire_v2, verify_tx_inclusion_v1, verify_tx_inclusion_v2,
    MKMapProof as DwarfMapProof, MKTreeNode as DwarfNode, TxError, TxLeafInput, MAX_TX_LEAF_LEN,
};

// Full production path: upstream proof bytes -> dwarf's host transcoder (wire)
// -> dwarf's guest decoder. Exercises both ends dwarf owns, not a harness-local
// mirror — so the oracle also gates `tx_proof_to_wire_*`.

fn transcode(upstream_bincode: &[u8]) -> Result<DwarfMapProof, ()> {
    let wire = tx_proof_to_wire_v2(upstream_bincode).map_err(|_| ())?;
    decode_proof(&wire).map_err(|_| ())
}

fn transcode_json(json: &[u8]) -> Result<DwarfMapProof, ()> {
    let wire = tx_proof_to_wire_v1(json).map_err(|_| ())?;
    decode_proof(&wire).map_err(|_| ())
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
        let my_leaf = build_tx_leaf_v2(&input, &mut buf);
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
        let my_leaf = build_tx_leaf_v2(&input, &mut buf);
        assert_eq!(my_leaf, up_leaf.to_vec().as_slice(), "multi-range leaf mismatch tx {i}");
        assert!(mine.contains(&DwarfNode::new(my_leaf.to_vec())), "missing proved leaf {i}");
    }
    // An unproved tx (range [15,30)) must be absent.
    let other: UpNode = CardanoBlockTransactionMkTreeNode::from(txs[1].clone()).into();
    assert!(!mine.contains(&DwarfNode::new(other.to_vec())), "contains an unproved leaf");
}

/// Real mainnet vector (fetched via `fetch_tx_proof`): dwarf must verify a
/// genuine network `MKMapProof` and reconstruct the *certified* merkle root —
/// the strongest non-circular check (the root came from upstream's own
/// `verify`, dwarf rebuilds it with its Blake2s/MMR). Also confirms the real
/// tree's leaves are the composite `Tx/...` form.
#[test]
fn dwarf_matches_real_mainnet_proof() {
    let json = include_bytes!("test_data/tx_proofs/mainnet_proof.json");
    let certified_root = include_str!("test_data/tx_proofs/mainnet_root.hex").trim();

    let mine = transcode_json(json).expect("transcode real mainnet proof");

    assert_eq!(mine.verify(), Ok(()), "dwarf rejected a real mainnet proof");
    assert_eq!(
        hex::encode(mine.compute_root().as_bytes()),
        certified_root,
        "dwarf-reconstructed root != certified mainnet root",
    );

    // Current mainnet `CardanoTransactions` tree: the leaf is the bare txid hex
    // string (NOT the composite `Tx/...`, which is the newer v2 format). Confirm
    // dwarf's `contains` finds each real leaf, and the leaves are our 3 txids.
    let expected = [
        "1d013efbd0f784f801cc3542605f4dcedbc45c01e10c625124eea505158d546b",
        "9dad0d7f6bf1e793f2572ff96337d7dc30ef554c1c0687e66cfe3855a458f503",
        "fdb2d9b874ef322540a402fb83c2541f67b32451c4983af2d27e4217bc4b8559",
    ];
    let mut found = 0;
    for (_range, sub) in &mine.sub_proofs {
        for (_pos, leaf) in &sub.master_proof.inner_leaves {
            let s = std::str::from_utf8(leaf.as_bytes()).unwrap_or("");
            assert!(expected.contains(&s), "unexpected mainnet leaf: {s:?}");
            // dwarf's v1 leaf builder reproduces the real mainnet leaf byte-for-byte,
            // and the proof contains it.
            let mut buf = [0u8; 64];
            let built = build_tx_leaf_v1(&h32(s), &mut buf);
            assert_eq!(built, leaf.as_bytes(), "v1 leaf builder != real mainnet leaf");
            assert!(mine.contains(&DwarfNode::new(built.to_vec())), "proof missing built v1 leaf");
            found += 1;
        }
    }
    assert_eq!(found, 3, "expected 3 tx leaves, got {found}");
}

/// Real PREVIEW v2 (`CardanoBlocksTransactions`) vector: the live v2 endpoint
/// returns a bincode proof + the composite-leaf block fields. Proves
/// `build_tx_leaf_v2` reproduces the real composite leaf and that dwarf
/// verifies + reconstructs the certified `cardano_blocks_transactions_merkle_root`.
#[test]
fn dwarf_matches_real_preview_v2_proof() {
    let proof_bytes = include_bytes!("test_data/tx_proofs/preview_v2_proof.bin");
    let certified_root = include_str!("test_data/tx_proofs/preview_v2_root.hex").trim();
    let tx_line = include_str!("test_data/tx_proofs/preview_v2_tx.txt").trim();
    let mut it = tx_line.split_whitespace();
    let txid = it.next().unwrap();
    let block_hash = it.next().unwrap();
    let block_number: u64 = it.next().unwrap().parse().unwrap();
    let slot_number: u64 = it.next().unwrap().parse().unwrap();

    // v2 wire is bincode (not json like v1).
    let mine = transcode(proof_bytes).expect("transcode v2 bincode proof");

    assert_eq!(mine.verify(), Ok(()), "dwarf rejected a real v2 proof");
    assert_eq!(
        hex::encode(mine.compute_root().as_bytes()),
        certified_root,
        "dwarf root != certified blocks-transactions root",
    );

    let input = TxLeafInput {
        tx_id: h32(txid),
        block_hash: h32(block_hash),
        block_number,
        slot_number,
    };
    let mut buf = [0u8; MAX_TX_LEAF_LEN];
    let leaf = build_tx_leaf_v2(&input, &mut buf);
    assert!(leaf.starts_with(b"Tx/"), "v2 leaf not composite");

    // build_tx_leaf_v2 reproduces an actual leaf node in the live proof, and
    // dwarf's contains finds it.
    let mut matched = false;
    for (_r, sub) in &mine.sub_proofs {
        for (_p, l) in &sub.master_proof.inner_leaves {
            if l.as_bytes() == leaf {
                matched = true;
            }
        }
    }
    assert!(matched, "build_tx_leaf_v2 != any real v2 leaf");
    assert!(mine.contains(&DwarfNode::new(leaf.to_vec())), "v2 proof missing composite leaf");
}

/// The custom serde-free guest wire carries the real proofs losslessly:
/// host-encode -> guest-decode reproduces a proof that still verifies and binds
/// the same certified root. Covers both live formats (v1 json, v2 bincode).
#[test]
fn wire_round_trips_real_proofs() {
    let v1 =
        transcode_json(include_bytes!("test_data/tx_proofs/mainnet_proof.json")).expect("v1 transcode");
    let v1_root = include_str!("test_data/tx_proofs/mainnet_root.hex").trim();
    let v2 =
        transcode(include_bytes!("test_data/tx_proofs/preview_v2_proof.bin")).expect("v2 transcode");
    let v2_root = include_str!("test_data/tx_proofs/preview_v2_root.hex").trim();

    for (proof, root) in [(v1, v1_root), (v2, v2_root)] {
        let bytes = encode_proof(&proof);
        let decoded = decode_proof(&bytes).expect("wire decode");
        // Re-encoding the decoded proof is byte-identical: lossless structure.
        assert_eq!(encode_proof(&decoded), bytes, "wire not lossless");
        // The decoded proof still verifies and binds the same certified root.
        assert_eq!(decoded.verify(), Ok(()), "decoded proof failed verify");
        assert_eq!(
            hex::encode(decoded.compute_root().as_bytes()),
            root,
            "root changed through wire",
        );
    }
}

/// Full guest path for **v2**: wire bytes -> `verify_tx_inclusion_v2` -> decode,
/// verify, root-bind, contains. Accepts the real tx under the certified root and
/// rejects a wrong root / wrong tx / truncated wire — all as `Err`, never panic.
#[test]
fn entrypoint_full_guest_path_v2() {
    let v2 =
        transcode(include_bytes!("test_data/tx_proofs/preview_v2_proof.bin")).expect("v2 transcode");
    let wire = encode_proof(&v2);
    let root = h32(include_str!("test_data/tx_proofs/preview_v2_root.hex").trim());
    let mut it = include_str!("test_data/tx_proofs/preview_v2_tx.txt")
        .trim()
        .split_whitespace();
    let input = TxLeafInput {
        tx_id: h32(it.next().unwrap()),
        block_hash: h32(it.next().unwrap()),
        block_number: it.next().unwrap().parse().unwrap(),
        slot_number: it.next().unwrap().parse().unwrap(),
    };

    assert_eq!(verify_tx_inclusion_v2(&wire, &[input], &root), Ok(()));

    let mut bad_root = root;
    bad_root[0] ^= 1;
    assert_eq!(
        verify_tx_inclusion_v2(&wire, &[input], &bad_root),
        Err(TxError::RootMismatch),
    );

    let mut bad_tx = input;
    bad_tx.slot_number ^= 1;
    assert_eq!(
        verify_tx_inclusion_v2(&wire, &[bad_tx], &root),
        Err(TxError::LeafNotFound),
    );

    assert!(matches!(
        verify_tx_inclusion_v2(&wire[..wire.len() / 2], &[input], &root),
        Err(TxError::InvalidProof),
    ));
    assert_eq!(verify_tx_inclusion_v2(&wire, &[], &root), Err(TxError::LeafNotFound));
}

/// Full guest path for **v1**: a real mainnet leaf (bare txid) under the certified
/// root accepts; wrong root / wrong txid reject.
#[test]
fn entrypoint_full_guest_path_v1() {
    let v1 = transcode_json(include_bytes!("test_data/tx_proofs/mainnet_proof.json"))
        .expect("v1 transcode");
    let wire = encode_proof(&v1);
    let root = h32(include_str!("test_data/tx_proofs/mainnet_root.hex").trim());

    // Pull a real bare-txid leaf out of the proof.
    let mut txid = None;
    for (_r, sub) in &v1.sub_proofs {
        for (_p, l) in &sub.master_proof.inner_leaves {
            txid = Some(h32(std::str::from_utf8(l.as_bytes()).unwrap()));
        }
    }
    let txid = txid.expect("a v1 leaf");

    assert_eq!(verify_tx_inclusion_v1(&wire, &[txid], &root), Ok(()));

    let mut bad_root = root;
    bad_root[0] ^= 1;
    assert_eq!(
        verify_tx_inclusion_v1(&wire, &[txid], &bad_root),
        Err(TxError::RootMismatch),
    );

    let mut bad_tx = txid;
    bad_tx[0] ^= 1;
    assert_eq!(
        verify_tx_inclusion_v1(&wire, &[bad_tx], &root),
        Err(TxError::LeafNotFound),
    );
}

/// Panic-safety fuzz: every single-byte mutation and every truncation of a real
/// wire proof must return (Ok/Err) from the entrypoint, never panic.
#[test]
fn entrypoint_never_panics_on_mutated_wire() {
    let v2 =
        transcode(include_bytes!("test_data/tx_proofs/preview_v2_proof.bin")).expect("v2 transcode");
    let wire = encode_proof(&v2);
    let root = [0u8; 32];
    let input = TxLeafInput {
        tx_id: [0u8; 32],
        block_hash: [0u8; 32],
        block_number: 0,
        slot_number: 0,
    };

    for i in 0..wire.len() {
        for b in [0x01u8, 0x80, 0xFF] {
            let mut m = wire.clone();
            m[i] ^= b;
            let r = std::panic::catch_unwind(|| verify_tx_inclusion_v2(&m, &[input], &root));
            assert!(r.is_ok(), "panicked on byte-{i} mutation {b:#x}");
        }
    }
    for cut in 0..=wire.len() {
        let r = std::panic::catch_unwind(|| verify_tx_inclusion_v2(&wire[..cut], &[input], &root));
        assert!(r.is_ok(), "panicked on truncation at {cut}");
    }
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
