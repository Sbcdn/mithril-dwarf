//! Empirical test for the oakshield per-certificate decomposition soundness
//! question (the multi-root v2 co-attestation "Critical" #1, but it applies to
//! every linkage in the chain).
//!
//! ORIGINAL MITHRIL is sound because `verify_certificate` is RECURSIVE: the
//! predecessor used for the AVK-chaining check is the *same object* that is
//! later re-verified as a `cert`, where `verify_hash_matches_content`
//! (`compute_hash() == hash`) binds its full content — INCLUDING its AVK —
//! to its hash. So a wrong AVK anywhere changes that cert's `compute_hash`,
//! breaks `previous_hash` matching, and the chain has a hole.
//!
//! OAKSHIELD reproduces `verify_standard_certificate` faithfully inside
//! `oaks_cert`, but REPLACES Mithril's recursion with the oaks_comp/oaks_proof
//! fold, which relinks per-cert proofs by the `previous_hash` FIELD only.
//! Inside a single `oaks_cert` proof, `verify_hash_matches_content` runs on the
//! current cert ONLY — never on the supplied predecessor (confirmed: the two
//! call sites in dwarf `verify_standard_certificate` are both `(cert)`).
//!
//! Consequence (what this test proves, at the dwarf level, with real preview
//! re-genesis fixtures, real crypto, no zkVM/dev-mode): a predecessor whose
//! content has been tampered so `compute_hash(P) != P.hash` is STILL accepted
//! by `verify_standard_certificate`, because its `.hash` field is taken at face
//! value and never recomputed. The AVK is one such content field — a malicious
//! prover who signs the current cert under their own AVK can supply a forged
//! predecessor carrying the genuine `.hash` but the attacker AVK, and it passes.
//!
//! The proposed fix — recompute the predecessor's hash inside `oaks_cert`
//! (`verify_hash_matches_content(prev)`), exactly the per-cert check Mithril's
//! recursion gives for free — would reject it. The test asserts both halves.

use std::path::PathBuf;

use mithril_common::entities::Certificate;
use mithril_common::messages::CertificateMessage;
use mithril_dwarf::{certificate_from_bytes, certificate_to_bytes};
use mithril_dwarf_harness::Outcome;
use mithril_dwarf_harness::corpus::{CorpusEntry, is_genesis, load_corpus};
use mithril_dwarf_harness::full_verify::dwarf_full_verify_standard;
use mithril_dwarf_harness::mutation::{Mutation, apply_mutation};

fn to_certificate(msg: &CertificateMessage) -> Certificate {
    msg.clone()
        .try_into()
        .expect("CertificateMessage -> Certificate")
}

/// Serialize via dwarf's `certificate_to_bytes`, which writes the `.hash` FIELD
/// verbatim (`writer.write_string(&cert.hash)`) — it does NOT recompute it.
/// That is precisely what lets a tampered-content / genuine-hash predecessor
/// round-trip into the verifier.
fn to_zc_bytes(msg: &CertificateMessage) -> Vec<u8> {
    certificate_to_bytes(&to_certificate(msg))
}

fn compute_hash_of(msg: &CertificateMessage) -> String {
    to_certificate(msg).compute_hash()
}

#[test]
fn predecessor_content_is_not_bound_to_its_hash_in_per_cert_verify() {
    // A real preview re-genesis chain captured offline (genesis + 30 descendants).
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/test_data/regenesis/testing_preview_g1120");
    let load = load_corpus(&dir);
    assert!(
        load.load_errors.is_empty(),
        "corpus load errors: {:?}",
        load.load_errors
    );

    // A standard/standard adjacent pair (predecessor itself non-genesis, so its
    // own `previous_hash` is a real field we can tamper).
    let (current, previous) = load
        .entries
        .iter()
        .find_map(|e| match e {
            CorpusEntry::Standard { current, previous } if !is_genesis(previous) => {
                Some((current.clone(), previous.clone()))
            }
            _ => None,
        })
        .expect("a standard/standard adjacent pair in the corpus");

    // ---- Positive control: the genuine pair verifies (real BLS + AVK chain). ----
    let c_zc_bytes = to_zc_bytes(&current);
    let p_zc_bytes = to_zc_bytes(&previous);
    let c_zc = certificate_from_bytes(&c_zc_bytes).expect("parse current");
    let p_zc = certificate_from_bytes(&p_zc_bytes).expect("parse genuine previous");
    assert_eq!(
        dwarf_full_verify_standard(&c_zc, &p_zc).outcome,
        Outcome::Pass,
        "sanity: the genuine (current, previous) pair must verify"
    );
    // ...and the genuine predecessor's stored hash matches its content.
    assert_eq!(
        compute_hash_of(&previous),
        previous.hash,
        "sanity: genuine predecessor compute_hash() == .hash"
    );

    // ---- Forge the predecessor: tamper a CONTENT field (its own previous_hash,
    // i.e. P's link to ITS parent) that is part of compute_hash() but is NOT
    // read by verify_standard_certificate(current, previous). Keep P.hash. ----
    let forged_previous = apply_mutation(&previous, &Mutation::FlipPreviousHashByte { index: 0 });
    assert_eq!(
        forged_previous.hash, previous.hash,
        "forge preserves the predecessor's .hash FIELD (so the fold's hash-linkage still matches)"
    );
    assert_ne!(
        forged_previous.previous_hash, previous.previous_hash,
        "forge actually changed the predecessor's content"
    );

    let fp_zc_bytes = to_zc_bytes(&forged_previous);
    let fp_zc = certificate_from_bytes(&fp_zc_bytes).expect("parse forged previous");

    // ---- THE GAP: the tampered predecessor is STILL accepted. ----
    // verify_standard_certificate never recomputes the predecessor's hash, so a
    // predecessor whose content no longer matches its `.hash` sails through.
    // In oakshield the journal would commit previous_hash = forged_previous.hash
    // = genuine hash, so the oaks_comp/oaks_proof fold's hash-linkage check
    // (previous_hash == next.current_hash) ALSO cannot detect it.
    assert_eq!(
        dwarf_full_verify_standard(&c_zc, &fp_zc).outcome,
        Outcome::Pass,
        "GAP CONFIRMED: verify_standard_certificate accepts a predecessor whose content \
         was tampered (compute_hash(P) != P.hash); the predecessor's hash is never recomputed"
    );

    // ---- THE FIX: recompute the predecessor's hash (Mithril's recursion does
    // this; oaks_cert would add verify_hash_matches_content(prev)). It rejects. ----
    assert_ne!(
        compute_hash_of(&forged_previous),
        forged_previous.hash,
        "FIX: compute_hash(forged_previous) != forged_previous.hash — recomputing the \
         predecessor's hash inside the proof detects the tampering and closes the gap"
    );
}
