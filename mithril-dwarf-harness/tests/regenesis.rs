//! Re-genesis acceptance + cross-anchor soundness, on real preview fixtures.
//!
//! This is a POSITIVE test that the dwarf verifier correctly handles a Mithril
//! re-genesis — the certificate chain being re-bootstrapped under a new genesis
//! certificate. Preview is the ONLY network where this is testable: several
//! aggregator instances run on the SAME preview Cardano network, each
//! independently bootstrapped, so each has its own genesis at a different epoch.
//! They share ONE genesis verification key (preview reuses the preprod genesis
//! key — `corpus::PREVIEW_GENESIS_VK_HEX == PREPROD_GENESIS_VK_HEX`). That
//! same-key collision is what makes re-genesis observable at all; it CANNOT
//! occur on preprod/mainnet by construction. So this is a same-key re-genesis on
//! a testing-only setup, NOT a key rotation (no aggregator vkey redeploy) — that
//! distinction is settled in `corpus.rs`, no BLS vkey check is involved here.
//!
//! The two chains are genuinely DISJOINT (treated as before/after). There is no
//! cryptographic "crossing" certificate linking them — that does not exist by
//! construction; the prior chain is wiped at each re-genesis. The fixtures are
//! the best real-data anchor available: each chain's genesis + 30 descendants,
//! captured offline 2026-06-15 (see `tests/test_data/regenesis/`), so the
//! perishable live data survives the source instances' next redeploy.
//!
//! Objectives (from the test plan):
//!   1. Each chain verifies independently — genesis against the preview genesis
//!      VK, and every standard pair's AVK chain links across each epoch boundary.
//!   2. Cross-anchor soundness (the key NEGATIVE): a cert from one chain is
//!      REJECTED when anchored to the other chain's genesis — the chains share no
//!      `previous_hash` linkage, so a chain that does not terminate at the trusted
//!      genesis must not be accepted.
//!   3. Genesis at an arbitrary epoch — accepted at 1120 and 1129, i.e. genesis
//!      handling is not pinned to epoch 0 or any specific epoch.

use std::path::PathBuf;

use mithril_common::crypto_helper::ed25519::Ed25519VerificationKey;
use mithril_common::entities::Certificate;
use mithril_common::messages::CertificateMessage;
use mithril_dwarf::{certificate_from_bytes, certificate_to_bytes};
use mithril_dwarf_harness::corpus::{CorpusEntry, PREVIEW_GENESIS_VK_HEX, load_corpus};
use mithril_dwarf_harness::full_verify::{dwarf_full_verify_genesis, dwarf_full_verify_standard};
use mithril_dwarf_harness::{ErrorCategory, Outcome};

// Chain A — testing-preview aggregator, genesis @ epoch 1120.
const CHAIN_A_DIR: &str = "tests/test_data/regenesis/testing_preview_g1120";
const CHAIN_A_GENESIS_HASH: &str =
    "4377d3ab73b9ffa74303e226e95571271007c945e2648fe6c279ff857751cdae";
const CHAIN_A_GENESIS_EPOCH: u64 = 1120;

// Chain B — pre-release-preview aggregator (--network preview), genesis @ epoch 1129.
const CHAIN_B_DIR: &str = "tests/test_data/regenesis/pre_release_preview_g1129";
const CHAIN_B_GENESIS_HASH: &str =
    "d6b8be9f69f9a4c304ddaadba8c7ba18b98faf88aa1bc7c372cfc24b34c35c69";
const CHAIN_B_GENESIS_EPOCH: u64 = 1129;

fn fixture_dir(rel: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel)
}

fn to_certificate(msg: &CertificateMessage) -> Certificate {
    msg.clone()
        .try_into()
        .expect("CertificateMessage -> Certificate")
}

/// Serialize via dwarf's `certificate_to_bytes` (the zero-copy wire form the
/// verifier consumes). The returned `Vec` must outlive any `CertificateZeroCopy`
/// parsed from it (it borrows the bytes).
fn zc_bytes(msg: &CertificateMessage) -> Vec<u8> {
    certificate_to_bytes(&to_certificate(msg))
}

/// The single preview genesis VK (preprod == preview), as raw 32 bytes — the
/// trust root both re-genesis chains are anchored to.
fn preview_genesis_vk() -> [u8; 32] {
    Ed25519VerificationKey::from_json_hex(PREVIEW_GENESIS_VK_HEX)
        .expect("parse PREVIEW_GENESIS_VK_HEX")
        .as_ref()
        .try_into()
        .expect("Ed25519 VK is 32 bytes")
}

/// All `current` certs of the standard (non-genesis) pairs in a segment.
fn standard_currents(dir: &str) -> Vec<CertificateMessage> {
    load_corpus(&fixture_dir(dir))
        .entries
        .iter()
        .filter_map(|e| match e {
            CorpusEntry::Standard { current, .. } => Some(current.clone()),
            _ => None,
        })
        .collect()
}

/// Pull the genesis cert and its immediate child (the epoch gen+1 cert whose
/// `previous_hash == genesis.hash`) out of a captured re-genesis segment.
fn genesis_and_child(dir: &str) -> (CertificateMessage, CertificateMessage) {
    let load = load_corpus(&fixture_dir(dir));
    assert!(
        load.load_errors.is_empty(),
        "{dir}: corpus load errors: {:?}",
        load.load_errors
    );
    let genesis = load
        .entries
        .iter()
        .find_map(|e| match e {
            CorpusEntry::Genesis { cert } => Some(cert.clone()),
            _ => None,
        })
        .expect("a genesis entry in the segment");
    let child = load
        .entries
        .iter()
        .find_map(|e| match e {
            CorpusEntry::Standard { current, previous } if previous.hash == genesis.hash => {
                Some(current.clone())
            }
            _ => None,
        })
        .expect("the genesis child (previous_hash == genesis)");
    (genesis, child)
}

/// Objective 1 + 3: each re-genesis chain verifies independently against the one
/// preview genesis VK, with genesis sitting at its own (non-zero) epoch.
#[test]
fn each_regenesis_chain_verifies_independently() {
    let vk = preview_genesis_vk();

    for (label, dir, expected_genesis_hash, expected_genesis_epoch) in [
        (
            "ChainA",
            CHAIN_A_DIR,
            CHAIN_A_GENESIS_HASH,
            CHAIN_A_GENESIS_EPOCH,
        ),
        (
            "ChainB",
            CHAIN_B_DIR,
            CHAIN_B_GENESIS_HASH,
            CHAIN_B_GENESIS_EPOCH,
        ),
    ] {
        let load = load_corpus(&fixture_dir(dir));
        assert!(
            load.load_errors.is_empty(),
            "{label}: corpus load errors: {:?}",
            load.load_errors
        );
        // A re-bootstrapped segment is contiguous (genesis + descendants), so it
        // has exactly one root and no unlinkable certs.
        assert_eq!(
            load.genesis_count, 1,
            "{label}: exactly one genesis (the re-bootstrap root)"
        );
        assert!(
            load.orphans.is_empty(),
            "{label}: contiguous segment should have no orphans: {:?}",
            load.orphans
        );

        // Genesis: matches the captured fixture, sits at an arbitrary non-zero
        // epoch, and verifies against the preview genesis VK.
        let genesis = load
            .entries
            .iter()
            .find_map(|e| match e {
                CorpusEntry::Genesis { cert } => Some(cert.clone()),
                _ => None,
            })
            .expect("a genesis entry");
        assert_eq!(
            genesis.hash, expected_genesis_hash,
            "{label}: genesis hash matches the captured fixture"
        );
        assert_eq!(
            genesis.epoch.0, expected_genesis_epoch,
            "{label}: genesis at the expected epoch"
        );
        assert_ne!(
            genesis.epoch.0, 0,
            "{label}: genesis is NOT at epoch 0 — genesis handling is not pinned to a specific epoch"
        );

        let g_bytes = zc_bytes(&genesis);
        let g_zc = certificate_from_bytes(&g_bytes).expect("parse genesis");
        assert_eq!(
            dwarf_full_verify_genesis(&g_zc, &vk).outcome,
            Outcome::Pass,
            "{label}: genesis must verify against the preview genesis VK (genesis_signature over AVK+epoch)"
        );

        // Every standard pair verifies: real BLS multi-sig + the AVK chain links
        // through each epoch boundary in the captured segment.
        let mut standard_pairs = 0usize;
        for entry in &load.entries {
            if let CorpusEntry::Standard { current, previous } = entry {
                let c_bytes = zc_bytes(current);
                let p_bytes = zc_bytes(previous);
                let c_zc = certificate_from_bytes(&c_bytes).expect("parse current");
                let p_zc = certificate_from_bytes(&p_bytes).expect("parse previous");
                assert_eq!(
                    dwarf_full_verify_standard(&c_zc, &p_zc).outcome,
                    Outcome::Pass,
                    "{label}: standard pair {} -> {} must verify",
                    current.hash,
                    previous.hash
                );
                standard_pairs += 1;
            }
        }
        // Captured as genesis + 30 descendants ⇒ 30 standard pairs.
        assert_eq!(
            standard_pairs, 30,
            "{label}: expected 30 standard pairs (genesis + 30 descendants), got {standard_pairs}"
        );
    }
}

/// Objective 2: cross-anchor soundness. The two re-genesis chains are disjoint —
/// a cert from one is rejected when anchored to the other's genesis, because it
/// carries no `previous_hash` linkage to that foreign root. This is the
/// "crossing" case, and the main soundness property to harden: the verifier must
/// not accept a chain that does not terminate at the trusted genesis.
#[test]
fn cross_anchor_chain_does_not_link_to_a_foreign_genesis() {
    let (a_genesis, a_child) = genesis_and_child(CHAIN_A_DIR);
    let (b_genesis, b_child) = genesis_and_child(CHAIN_B_DIR);

    // Genuinely independent roots: different hashes AND different AVKs.
    assert_ne!(
        a_genesis.hash, b_genesis.hash,
        "the two re-genesis chains have distinct genesis roots"
    );
    assert_ne!(
        a_genesis.aggregate_verification_key, b_genesis.aggregate_verification_key,
        "the two re-genesis roots have distinct AVKs (independent committees)"
    );

    // Positive control: each genesis child links to ITS OWN genesis.
    for (label, child, genesis) in [
        ("ChainA", &a_child, &a_genesis),
        ("ChainB", &b_child, &b_genesis),
    ] {
        let c_bytes = zc_bytes(child);
        let g_bytes = zc_bytes(genesis);
        let c_zc = certificate_from_bytes(&c_bytes).expect("parse child");
        let g_zc = certificate_from_bytes(&g_bytes).expect("parse genesis");
        assert_eq!(
            dwarf_full_verify_standard(&c_zc, &g_zc).outcome,
            Outcome::Pass,
            "{label}: genesis child must link to its own genesis (control)"
        );
    }

    // NEGATIVE (a): the literal "anchor to foreign genesis" case — each chain's
    // genesis child paired with the OTHER chain's genesis as its predecessor.
    // MUST reject. With these fixtures the concrete cause is the epoch gap
    // (the roots are 9 epochs apart — 1120 vs 1129 — so the foreign genesis is
    // at the wrong epoch to be this child's predecessor; `verify_epoch_chaining`
    // fires before the previous-hash check). Either way it does not link.
    for (label, child, foreign_genesis) in [
        ("ChainB child @ ChainA genesis", &b_child, &a_genesis),
        ("ChainA child @ ChainB genesis", &a_child, &b_genesis),
    ] {
        let c_bytes = zc_bytes(child);
        let fg_bytes = zc_bytes(foreign_genesis);
        let c_zc = certificate_from_bytes(&c_bytes).expect("parse child");
        let fg_zc = certificate_from_bytes(&fg_bytes).expect("parse foreign genesis");
        let outcome = dwarf_full_verify_standard(&c_zc, &fg_zc).outcome;
        assert!(
            matches!(outcome, Outcome::Fail(_)),
            "cross-anchor MUST reject ({label}): a chain that does not link to the trusted \
             genesis must not be accepted — got {outcome:?}"
        );
    }

    // NEGATIVE (b): isolate the no-cross-chain-linkage property. Pick a
    // SAME-EPOCH pair across the two chains (their segments overlap on epochs
    // 1129..1150), so `verify_epoch_chaining` passes (same-epoch is a valid step)
    // and cannot mask the result. The Chain-A cert's `previous_hash` points into
    // Chain A, never at the Chain-B cert — so it rejects on the linkage check.
    let a_certs = standard_currents(CHAIN_A_DIR);
    let b_certs = standard_currents(CHAIN_B_DIR);
    let (a_cert, b_cert) = a_certs
        .iter()
        .find_map(|a| {
            b_certs
                .iter()
                .find(|b| a.epoch.0 == b.epoch.0)
                .map(|b| (a.clone(), b.clone()))
        })
        .expect("a same-epoch cross-chain pair in the overlapping range (1129..1150)");
    assert_ne!(
        a_cert.previous_hash, b_cert.hash,
        "the cross-chain pair shares no previous_hash linkage (by construction)"
    );
    let a_bytes = zc_bytes(&a_cert);
    let b_bytes = zc_bytes(&b_cert);
    let a_zc = certificate_from_bytes(&a_bytes).expect("parse chain-A cert");
    let b_zc = certificate_from_bytes(&b_bytes).expect("parse chain-B cert");
    let outcome = dwarf_full_verify_standard(&a_zc, &b_zc).outcome;
    assert_eq!(
        outcome,
        Outcome::Fail(ErrorCategory::PreviousHashMismatch),
        "epoch-adjacent cross-chain pair (A@{}, B@{}) must reject on the previous-hash linkage \
         — the chains do not cross — got {outcome:?}",
        a_cert.epoch.0,
        b_cert.epoch.0
    );
}
