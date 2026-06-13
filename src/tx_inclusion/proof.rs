//! `MKProof` / `MKMapProof<BlockRange>` verify, contains and compute_root,
//! bit-faithful to upstream iog/main `crypto_helper/{merkle_tree,merkle_map}.rs`.
//! The MMR proof check delegates to [`ckb_merkle_mountain_range::MerkleProof`]
//! with the Blake2s256 merge, so peak-bagging / root is identical by
//! construction.

use ckb_merkle_mountain_range::MerkleProof;

use super::leaf::write_u64_dec_into;
use super::node::{MKTreeNode, MergeMKTreeNode, merge_nodes};

/// Failure reasons for the inclusion path. `Copy`, no payload — failure
/// allocates nothing, and the guest treats any `Err` as "reject".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxError {
    /// Wire bytes were malformed / truncated.
    InvalidProof,
    /// An MMR (sub or master) proof did not verify against its claimed root.
    ProofVerifyFailed,
    /// The master proof's leaves don't bind to the sub-proof roots.
    BindingFailed,
    /// A required leaf was not present in the proof.
    LeafNotFound,
    /// `compute_root()` did not equal the certified `expected_root`.
    RootMismatch,
}

/// A block range `[start, end)` — an outer `MKMap` key. Its tree node is the
/// UTF-8 of `"{start}-{end}"` (decimal), matching upstream `BlockRange -> MKTreeNode`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockRange {
    pub start: u64,
    pub end: u64,
}

impl BlockRange {
    /// `"{start}-{end}"` as an `MKTreeNode`, no `format!`.
    pub fn to_node(&self) -> MKTreeNode {
        // 20 + 1 + 20 worst case.
        let mut buf = [0u8; 41];
        let mut pos = write_u64_dec_into(&mut buf, 0, self.start);
        buf[pos] = b'-';
        pos += 1;
        pos = write_u64_dec_into(&mut buf, pos, self.end);
        MKTreeNode::new(buf[..pos].to_vec())
    }
}

/// A single-tree Merkle proof. Mirrors upstream `MKProof` fields exactly.
#[derive(Debug, Clone)]
pub struct MKProof {
    pub inner_root: MKTreeNode,
    pub inner_leaves: Vec<(u64, MKTreeNode)>,
    pub inner_proof_size: u64,
    pub inner_proof_items: Vec<MKTreeNode>,
}

impl MKProof {
    /// Upstream `MKProof::verify`: the MMR proof must reconstruct `inner_root`.
    pub fn verify(&self) -> Result<(), TxError> {
        let proof = MerkleProof::<MKTreeNode, MergeMKTreeNode>::new(
            self.inner_proof_size,
            self.inner_proof_items.clone(),
        );
        let ok = proof
            .verify(self.inner_root.clone(), self.inner_leaves.clone())
            .map_err(|_| TxError::ProofVerifyFailed)?;
        if ok {
            Ok(())
        } else {
            Err(TxError::ProofVerifyFailed)
        }
    }

    /// Every given leaf node must be byte-equal to one of the proof's leaves
    /// (membership only, as upstream).
    pub fn contains(&self, leaves: &[MKTreeNode]) -> bool {
        leaves
            .iter()
            .all(|leaf| self.inner_leaves.iter().any(|(_, l)| l == leaf))
    }

    pub fn root(&self) -> &MKTreeNode {
        &self.inner_root
    }
}

/// A merkelized-map proof over `BlockRange`. Mirrors upstream `MKMapProof`.
#[derive(Debug, Clone)]
pub struct MKMapProof {
    pub master_proof: MKProof,
    pub sub_proofs: Vec<(BlockRange, MKMapProof)>,
}

impl MKMapProof {
    /// Upstream `MKMapProof::compute_root` = the master proof's claimed root.
    pub fn compute_root(&self) -> MKTreeNode {
        self.master_proof.root().clone()
    }

    /// Upstream `MKMapProof::verify`: (1) each sub-proof verifies; (2) the
    /// master proof verifies; (3) the master proof's leaves contain, for each
    /// sub-proof, `Blake2s256("{start}-{end}" ‖ sub.compute_root())`.
    pub fn verify(&self) -> Result<(), TxError> {
        for (_range, sub) in &self.sub_proofs {
            sub.verify()?;
        }
        self.master_proof.verify()?;
        if !self.sub_proofs.is_empty() {
            let bound: Vec<MKTreeNode> = self
                .sub_proofs
                .iter()
                .map(|(range, sub)| merge_nodes(&range.to_node(), &sub.compute_root()))
                .collect();
            if !self.master_proof.contains(&bound) {
                return Err(TxError::BindingFailed);
            }
        }
        Ok(())
    }

    /// Upstream `MKMapProof::contains`: the leaf is in the master proof or in
    /// some sub-proof (recursive).
    pub fn contains(&self, leaf: &MKTreeNode) -> bool {
        self.master_proof.contains(core::slice::from_ref(leaf))
            || self.sub_proofs.iter().any(|(_, sub)| sub.contains(leaf))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ckb_merkle_mountain_range::{MMR, util::MemStore};

    // Build a real MMR with the Blake2s merge via ckb-mmr, produce a genuine
    // proof, wrap it in our MKProof, and assert verify()/contains behave. This
    // exercises the actual ckb-mmr verify path our code relies on.
    #[test]
    fn mkproof_verifies_a_real_ckb_mmr_proof() {
        let store = MemStore::<MKTreeNode>::default();
        let mut mmr = MMR::<MKTreeNode, MergeMKTreeNode, _>::new(0, &store);
        let leaves: Vec<MKTreeNode> = (0u8..5).map(|i| MKTreeNode::new(vec![i; 8])).collect();
        let positions: Vec<u64> = leaves
            .iter()
            .map(|l| mmr.push(l.clone()).unwrap())
            .collect();
        let root = mmr.get_root().unwrap();

        // Prove leaves 1 and 3.
        let proved = [1usize, 3];
        let pos: Vec<u64> = proved.iter().map(|&i| positions[i]).collect();
        let genp = mmr.gen_proof(pos).unwrap();

        let mkproof = MKProof {
            inner_root: root.clone(),
            inner_leaves: proved
                .iter()
                .map(|&i| (positions[i], leaves[i].clone()))
                .collect(),
            inner_proof_size: genp.mmr_size(),
            inner_proof_items: genp.proof_items().to_vec(),
        };

        assert_eq!(mkproof.verify(), Ok(()));
        assert!(mkproof.contains(&[leaves[1].clone(), leaves[3].clone()]));
        assert!(!mkproof.contains(&[leaves[0].clone()]));

        // Tamper the claimed root → verify must fail (not panic).
        let mut bad = mkproof.clone();
        bad.inner_root = MKTreeNode::new(vec![0xFF; 32]);
        assert_eq!(bad.verify(), Err(TxError::ProofVerifyFailed));
    }

    #[test]
    fn block_range_node_is_decimal_dash() {
        let n = BlockRange { start: 45, end: 60 }.to_node();
        assert_eq!(n.as_bytes(), b"45-60");
        assert_eq!(
            BlockRange { start: 0, end: 15 }.to_node().as_bytes(),
            b"0-15"
        );
    }

    // SECURITY: the guest must reject any malformed proof with `Err`, never
    // panic. These feed adversarial structured input straight at the ckb-mmr
    // verify path our code relies on; each is wrapped so a panic fails loudly.
    fn no_panic<T>(f: impl FnOnce() -> T + std::panic::UnwindSafe) -> Result<T, ()> {
        std::panic::catch_unwind(f).map_err(|_| ())
    }

    fn n(b: u8) -> MKTreeNode {
        MKTreeNode::new(vec![b; 8])
    }

    #[test]
    fn malformed_mkproof_errs_not_panics() {
        // Empty proof, a claimed leaf, bogus size — must not panic.
        let cases = vec![
            MKProof {
                inner_root: n(1),
                inner_leaves: vec![(0, n(2))],
                inner_proof_size: 0,
                inner_proof_items: vec![],
            },
            MKProof {
                inner_root: n(1),
                inner_leaves: vec![(u64::MAX, n(2))],
                inner_proof_size: u64::MAX,
                inner_proof_items: vec![n(3), n(4)],
            },
            MKProof {
                inner_root: n(1),
                inner_leaves: vec![],
                inner_proof_size: 7,
                inner_proof_items: vec![n(3)],
            },
        ];
        for (i, p) in cases.into_iter().enumerate() {
            let r = no_panic(move || p.verify());
            assert!(r.is_ok(), "MKProof::verify PANICKED on malformed case {i}");
            assert_eq!(
                r.unwrap(),
                Err(TxError::ProofVerifyFailed),
                "case {i} should reject"
            );
        }
    }

    #[test]
    fn malformed_mkmapproof_errs_not_panics() {
        let bad_master = MKProof {
            inner_root: n(1),
            inner_leaves: vec![(0, n(2))],
            inner_proof_size: 0,
            inner_proof_items: vec![],
        };
        // Master alone (no sub) is just a bad MMR proof.
        let p1 = MKMapProof {
            master_proof: bad_master.clone(),
            sub_proofs: vec![],
        };
        // With a sub-proof whose binding can't match.
        let p2 = MKMapProof {
            master_proof: bad_master.clone(),
            sub_proofs: vec![(
                BlockRange { start: 0, end: 15 },
                MKMapProof {
                    master_proof: bad_master,
                    sub_proofs: vec![],
                },
            )],
        };
        for (i, p) in [p1, p2].into_iter().enumerate() {
            let r = no_panic(move || p.verify());
            assert!(r.is_ok(), "MKMapProof::verify PANICKED on case {i}");
            assert!(r.unwrap().is_err(), "case {i} should reject");
        }
    }
}
