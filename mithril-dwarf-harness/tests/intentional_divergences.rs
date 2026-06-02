//! Registry of intentional divergences between `mithril-dwarf` and
//! upstream Mithril (`mithril-common` / `mithril-stm` / `mithril-client`
//! at rev `36fd7f8818f0ff14b10336fa7f855d52698e40a8`).
//!
//! Each entry is documented in a per-divergence doc comment and asserted
//! by a pin test; the corpus-wide verdict-equivalence test confirms the
//! divergences don't change the top-level accept/reject outcome.
//!
//! If a pin fails after `cargo update -p mithril-common`, upstream has
//! moved — update or remove the entry. When introducing a new
//! divergence (a cycle optimisation that changes observable behaviour),
//! add an entry here before the optimisation lands.
//!
//! | # | Divergence                                              | Layer     | Verdict-equivalent? |
//! |---|---------------------------------------------------------|-----------|---------------------|
//! | 1 | BLS identity-point defence layer                        | crypto    | Yes (pinned)        |
//! | 3 | `verify_epoch_chaining` direction asymmetry             | check     | Conditionally       |
//! | 4 | Check ordering in `verify_standard_certificate`         | orchestr. | Yes (top-level)     |
//! | 5 | usize-vs-u64 BLS scalar index width on RISC0            | platform  | Yes (BLS math)      |
//! | 6 | NextAvk chain compare: bytewise vs structural           | check     | On real chains      |
//!
//! Closed divergences (kept here for audit trail):
//! - #2 — Ed25519 non-strict verify. Aligned with upstream by switching
//!   to `verify_strict` at the genesis-cert call site; measured cost
//!   ~74k host cycles per chain (one call per chain, genesis-only).

use mithril_dwarf::certificate_verification::VerifyError;
use mithril_dwarf_harness::{
    audit_corpus_entry, audit_standard_top_level_only, load_corpus, CorpusEntry,
    Outcome, genesis_vk_for_cert,
};
use std::path::Path;

const CORPUS_DIR: &str = "tests/test_data/certificates";

// Divergence #1 — BLS identity-point defence layer
//
// Dwarf calls `blst::min_sig::{Signature, PublicKey}::from_bytes`
// directly in `aggregate_signatures_and_keys` (complex_checks.rs); upstream
// wraps blst behind `mithril_stm::BlsSignature::from_bytes` /
// `BlsVerificationKey::from_bytes`, which reject identity-point encodings
// at deserialise.
//
// Result: upstream rejects identity-encoded certs before the verifier
// runs; dwarf parses them and rejects later via the BLS pairing equation
// inside `verify_bls_multisig` → `verify_bls_aggregate`. The verdict is
// identical (both reject); the rejection point differs.
//
// Dwarf accepts the extra cycles on hostile input in exchange for the
// per-cert savings on well-formed input. The pairing check is
// mathematically sufficient for soundness.

/// Pin: blst accepts identity at parse, AND the dwarf verify-time
/// defence rejects an identity-spliced cert. The end-to-end coverage
/// (real cert + identity splice + `verify_standard_certificate`) lives
/// in `dwarf_rejects_bls_identity_in_cert` (equivalence.rs); this pin
/// covers the algebraic precondition (blst is permissive) and the
/// blst-level pairing-with-identity behaviour that the dwarf defence
/// rides on.
#[test]
fn divergence_1_bls_identity_defence_layer_pinned() {
    use blst::min_sig::{PublicKey, Signature};

    let mut g1_identity = [0u8; 48];
    g1_identity[0] = 0xC0;
    let mut g2_identity = [0u8; 96];
    g2_identity[0] = 0xC0;

    let sig_identity = Signature::from_bytes(&g1_identity);
    let pk_identity = PublicKey::from_bytes(&g2_identity);
    assert!(
        sig_identity.is_ok(),
        "blst tightened identity rejection at Signature::from_bytes; \
         update the registry — defence is now at parse-time"
    );
    assert!(
        pk_identity.is_ok(),
        "blst tightened identity rejection at PublicKey::from_bytes; \
         update the registry"
    );

    // Algebraic half: identity-on-both-sides defeats a naive pairing
    // verify (LHS = pairing(identity, G) = RHS = identity_GT). The
    // dwarf defence relies on the surrounding Merkle batch proof to
    // reject the substituted leaf, or on a real-pk-vs-identity-sig
    // mismatch in the pairing — never on blst itself rejecting at
    // verify with `pk_is_identity=false, sig_groupcheck=false` (the
    // flags used in `verify_bls_aggregate`).
    let sig = sig_identity.expect("identity sig parsed above");
    let pk = pk_identity.expect("identity pk parsed above");
    let result = sig.verify(
        false,
        b"divergence-1 pin: arbitrary message",
        &[],
        &[],
        &pk,
        false,
    );
    assert_ne!(
        result,
        blst::BLST_ERROR::BLST_SUCCESS,
        "blst.verify accepted (sig=identity, pk=identity) without \
         the explicit identity flags. dwarf's defence in \
         `aggregate_signatures_and_keys` would then rely entirely on \
         the surrounding Merkle batch proof for the identity-VK case; \
         strengthen the registry note if so."
    );
}

// Divergence #3 — `verify_epoch_chaining` direction asymmetry
//
// Dwarf's `verify_epoch_chaining` rejects when
// `curr.epoch != prev.epoch && curr.epoch != prev.epoch + 1`. Upstream's
// `Epoch::has_gap_with` is symmetric (`abs_diff(...) > 1`), so it would
// admit the pathological `prev.epoch == curr.epoch + 1` direction that
// dwarf rejects.
//
// Mithril chains only grow forward in time, so this asymmetry is
// verdict-equivalent for every real cert pair — both reject the broken
// chain, dwarf via this check, upstream via subsequent ones. Dwarf
// keeps the single comparison for cycle reasons.

/// Pin: dwarf-side direction matrix + upstream symmetry. The earlier
/// version covered only `(curr=100, prev=101)`; this exercises the
/// full set of boundary directions so a regression that flips the
/// asymmetry, widens the accepted range, or breaks the equal-epoch
/// case trips here instead of slipping past as a per-cert oddity.
#[test]
fn divergence_3_epoch_chaining_direction_pinned() {
    use mithril_common::entities::Epoch;
    use mithril_dwarf::certificate_to_bytes;
    use mithril_dwarf::parser::byte_deserializer::{
        certificate_from_bytes, CertificateZeroCopy,
    };

    let load = load_corpus(Path::new(CORPUS_DIR));
    let (curr_msg, prev_msg) = load
        .entries
        .iter()
        .find_map(|e| match e {
            CorpusEntry::Standard { current, previous } => Some((current, previous)),
            _ => None,
        })
        .expect("corpus has a standard cert pair");

    // Direction matrix. Each row is `(curr.epoch, prev.epoch,
    // dwarf_should_accept, upstream_should_report_gap)`. The
    // divergence lives at `(prev > curr)` where dwarf rejects and
    // upstream stays silent (has_gap_with returns false).
    let cases: &[(u64, u64, bool, bool, &str)] = &[
        // equal epoch — both accept (same-epoch is a legal chain link)
        (50, 50, true, false, "equal-epoch"),
        // forward by one — both accept (canonical forward step)
        (51, 50, true, false, "forward-by-one"),
        // forward by two — both reject (real gap)
        (52, 50, false, true, "forward-gap"),
        // backward by one — dwarf rejects, upstream symmetric admits
        (100, 101, false, false, "backward-by-one (divergence)"),
        // backward by two — dwarf rejects, upstream's abs_diff reports gap
        (100, 102, false, true, "backward-gap"),
    ];

    let run = |curr_epoch: u64, prev_epoch: u64| -> Result<(), VerifyError> {
        let mut current = curr_msg.clone();
        let mut previous = prev_msg.clone();
        current.epoch = Epoch(curr_epoch);
        previous.epoch = Epoch(prev_epoch);
        let curr_typed: mithril_common::entities::Certificate =
            current.try_into().expect("curr try_into");
        let prev_typed: mithril_common::entities::Certificate =
            previous.try_into().expect("prev try_into");
        let curr_bytes = certificate_to_bytes(&curr_typed);
        let prev_bytes = certificate_to_bytes(&prev_typed);
        let curr_zc: CertificateZeroCopy =
            certificate_from_bytes(&curr_bytes).expect("parse curr");
        let prev_zc: CertificateZeroCopy =
            certificate_from_bytes(&prev_bytes).expect("parse prev");
        mithril_dwarf::certificate_verification::basic_checks::verify_epoch_chaining(
            &curr_zc, &prev_zc,
        )
    };

    for &(curr_epoch, prev_epoch, dwarf_should_accept, upstream_should_gap, label) in cases {
        let dwarf = run(curr_epoch, prev_epoch);
        let dwarf_accepts = dwarf.is_ok();
        assert_eq!(
            dwarf_accepts, dwarf_should_accept,
            "{label}: dwarf verify_epoch_chaining({curr_epoch}, {prev_epoch}) = {dwarf:?}, \
             expected accept={dwarf_should_accept}"
        );
        let upstream_gap = Epoch(curr_epoch).has_gap_with(&Epoch(prev_epoch));
        assert_eq!(
            upstream_gap, upstream_should_gap,
            "{label}: upstream Epoch::has_gap_with({curr_epoch}, {prev_epoch}) = {upstream_gap}, \
             expected gap={upstream_should_gap}. Symmetry assumption broken — \
             revisit divergence #3."
        );
    }
}

// Divergence #4 — Check ordering inside `verify_standard_certificate`
//
// Dwarf orders phases cheapest-first: basic (infinite_loop, epoch,
// epoch_chaining, previous_hash) → medium (hash, signed_message) →
// chain (AVK, protocol_params) → BLS multi-sig. Upstream orders
// infinite_loop → hash → signed_message → BLS → epoch → epoch_chain →
// previous_hash → AVK chain → params chain — BLS is fourth, not last.
//
// On a multi-defect cert (e.g. wrong hash AND wrong epoch), the two
// impls surface different `ErrorCategory` values because the earlier
// check fires first. The top-level verdict matches (both reject); the
// category differs, surfaced as a soft divergence in the harness's
// rejection-category breakdown.
//
// Divergence 4a — the same shape one layer deeper:
// `preliminary_verify` checks quorum (`NoQuorum`) before uniqueness
// (`IndexNotUnique`); upstream's `basic_verifier` checks uniqueness
// first. Multi-defect input produces the matching ErrorCategory swap.
// Covered by the parent pin; no separate test.

/// Pin: dwarf and upstream produce divergent ErrorCategory pairs on a
/// multi-defect cert. The earlier version only `eprintln!`d the pair
/// and would pass silently when the categories happened to match —
/// missing the case where one side reordered to align with the other
/// and the divergence vanished. This now asserts the mismatch.
#[test]
fn divergence_4_check_ordering_pinned() {
    let load = load_corpus(Path::new(CORPUS_DIR));
    let (curr, prev) = load
        .entries
        .iter()
        .find_map(|e| match e {
            CorpusEntry::Standard { current, previous } => Some((current, previous)),
            _ => None,
        })
        .expect("standard pair in corpus");

    // Mutate: bump current.epoch (breaks both the protocol-message
    // CurrentEpoch match AND the epoch chain — multi-defect by design).
    let mut mutated = curr.clone();
    mutated.epoch = mithril_common::entities::Epoch(mutated.epoch.0 + 100);

    let audit = audit_standard_top_level_only(
        &mutated,
        prev,
        "divergence-4-pin: multi-defect epoch bump".to_string(),
    );

    let mithril_cat = match audit.full_verify.mithril.outcome {
        Outcome::Fail(c) => Some(c),
        _ => None,
    };
    let dwarf_cat = match audit.full_verify.dwarf.outcome {
        Outcome::Fail(c) => Some(c),
        _ => None,
    };

    assert!(
        mithril_cat.is_some() && dwarf_cat.is_some(),
        "both impls must reject the multi-defect cert; \
         mithril: {:?}, dwarf: {:?}",
        audit.full_verify.mithril.outcome,
        audit.full_verify.dwarf.outcome
    );
    let (m, d) = (mithril_cat.unwrap(), dwarf_cat.unwrap());
    assert_ne!(
        m, d,
        "divergence-4: ErrorCategory match on a multi-defect cert \
         (both = {m:?}). One side reordered its checks; revisit \
         registry entry — the divergence may be closed."
    );
}

// Divergence #5 — usize-vs-u64 BLS scalar index width on RISC0
//
// `aggregate_signatures_and_keys` derives the per-signer BLS scalar
// from `Blake2b::<U16>(hashed_sigs || (index as usize).to_be_bytes())`.
// `usize` is 4 bytes on RISC0 (RV32) and 8 bytes on x86_64 hosts, so
// dwarf-on-RISC0 produces different scalar bytes than dwarf-on-host or
// upstream-on-host on the same input.
//
// Verdict-equivalence follows from BLS bilinearity: both `agg_pk` and
// `agg_sig` use the same scalars within a verifier run, so the pairing
// equation holds regardless of the scalar values. The scalars exist to
// prevent rogue-key attacks; entropy comes from `Blake2b(all_sigmas)`,
// not the index suffix.
//
// Implication: the harness's bit-equality claim is host-only;
// production correctness on RISC0 is preserved.

/// Pin: host vs guest scalar bytes actually differ on the same input,
/// not just `usize == 8`. The earlier version asserted only the host
/// width; if dwarf widened its index cast to `u64` (closing the
/// divergence at the source) the platform check would still pass
/// silently. The byte-level compare below catches that case.
#[test]
fn divergence_5_usize_index_width_pinned() {
    let width = core::mem::size_of::<usize>();
    assert_eq!(
        width, 8,
        "harness running on a non-64-bit host (usize is {width} bytes); \
         the host/guest divergence no longer applies in this build"
    );

    use blake2::{digest::consts::U16, Blake2b, Digest};

    // Same prefix on both sides; only the index encoding differs. The
    // host side mirrors what `aggregate_signatures_and_keys` produces
    // at line 520 (`(index as usize).to_be_bytes()`). The guest side
    // emulates RV32 by promoting `index` to `u32` before
    // `to_be_bytes()`.
    let base = Blake2b::<U16>::new().chain_update(b"prefix-bytes-from-all-sigmas");
    let host_scalar: [u8; 16] = base
        .clone()
        .chain_update(0usize.to_be_bytes())
        .finalize()
        .into();
    let guest_scalar: [u8; 16] = base
        .clone()
        .chain_update(0u32.to_be_bytes())
        .finalize()
        .into();
    assert_ne!(
        host_scalar, guest_scalar,
        "host (usize=8) and emulated-guest (usize=4) scalars matched on \
         index 0. Either Blake2b-128 collided on the differing index \
         suffix, or the dwarf cast widened to u64 and divergence #5 \
         closed at the source. Investigate before assuming the cycle \
         tradeoff still applies."
    );
}

// Divergence #6 — NextAvk chain compare: bytewise vs structural
//
// Upstream Mithril 2617.0 changed
// `verify_concatenation_aggregate_verification_key_chaining` to decode the
// previous cert's `protocol_message[NextAggregateVerificationKey]` string
// via `ProtocolAggregateVerificationKeyForConcatenation::try_from(&str)`
// and compare structurally to the current cert's
// `aggregate_verification_key`. Whitespace, field order, and any other
// representation-only difference in the NextAvk string is therefore
// accepted by upstream.
//
// dwarf's `verify_avk_chain` streams the current cert's AVK JSON hex into
// an `EqSink` over the previous cert's NextAvk string and rejects on any
// byte mismatch. dwarf is strictly stricter: it accepts a subset of what
// upstream accepts.
//
// On real Cardano chains the NextAvk string is produced by the aggregator
// and round-trips through serde verbatim across cert pairs, so dwarf and
// upstream produce the same verdict on every corpus cert (verified by
// `divergence_registry_verdict_equivalence_holds_on_corpus`). The
// divergence only surfaces on adversarially re-encoded inputs.
//
// Direction is safe: dwarf can reject more, never accept more.

/// Pin: upstream's `try_from(&str)` on the NextAvk string accepts a
/// pretty-printed (whitespace-padded) re-encoding AND dwarf's
/// `verify_avk_chain` rejects the same input bytewise. The earlier
/// version only checked upstream's acceptance — if dwarf became
/// permissive (e.g. routed the compare through `serde_json::Value`
/// equality) the pin would still pass and the divergence narrative
/// would silently invert. This now pins both halves.
#[test]
fn divergence_6_nextavk_structural_compare_pinned() {
    use mithril_common::crypto_helper::ProtocolAggregateVerificationKeyForConcatenation;
    use mithril_dwarf::certificate_to_bytes;
    use mithril_dwarf::parser::byte_deserializer::{
        certificate_from_bytes, CertificateZeroCopy,
    };

    let load = load_corpus(Path::new(CORPUS_DIR));
    let (curr, prev) = load
        .entries
        .iter()
        .find_map(|e| match e {
            CorpusEntry::Standard { current, previous } => Some((current, previous)),
            _ => None,
        })
        .expect("corpus has a standard pair");

    let nextavk_compact = prev
        .protocol_message
        .message_parts
        .get(&mithril_common::entities::ProtocolMessagePartKey::NextAggregateVerificationKey)
        .expect("prev has NextAvk part")
        .clone();
    let nextavk_pretty = {
        let decoded = hex::decode(&nextavk_compact).expect("hex");
        let json_value: serde_json::Value =
            serde_json::from_slice(&decoded).expect("json");
        let pretty = serde_json::to_string_pretty(&json_value).expect("pretty");
        hex::encode(pretty)
    };
    assert_ne!(
        nextavk_compact, nextavk_pretty,
        "pretty re-encoding produced the same bytes as the compact form"
    );

    // Upstream half: structural compare accepts the pretty form.
    let parsed_pretty =
        ProtocolAggregateVerificationKeyForConcatenation::try_from(nextavk_pretty.as_str());
    assert!(
        parsed_pretty.is_ok(),
        "upstream try_from rejected pretty-form NextAvk: {parsed_pretty:?}. \
         If upstream tightened to bytewise compare, remove divergence #6."
    );

    // Dwarf half: bytewise compare rejects the same pretty form when
    // it is spliced into prev's NextAvk slot. Build a synthetic
    // (curr, prev_pretty) pair where prev's NextAvk part is the
    // pretty hex; everything else is unchanged. dwarf's
    // `verify_avk_chain` should return `AVKMismatch`.
    let mut prev_pretty = prev.clone();
    prev_pretty.protocol_message.message_parts.insert(
        mithril_common::entities::ProtocolMessagePartKey::NextAggregateVerificationKey,
        nextavk_pretty.clone(),
    );

    let curr_typed: mithril_common::entities::Certificate =
        curr.clone().try_into().expect("curr try_into");
    let prev_typed: mithril_common::entities::Certificate =
        prev_pretty.try_into().expect("prev_pretty try_into");
    let curr_bytes = certificate_to_bytes(&curr_typed);
    let prev_bytes = certificate_to_bytes(&prev_typed);
    let curr_zc: CertificateZeroCopy = certificate_from_bytes(&curr_bytes).expect("parse curr");
    let prev_zc: CertificateZeroCopy = certificate_from_bytes(&prev_bytes).expect("parse prev");

    let dwarf_result =
        mithril_dwarf::certificate_verification::complex_checks::verify_avk_chain(
            &curr_zc, &prev_zc,
        );
    assert!(
        matches!(dwarf_result, Err(VerifyError::AVKMismatch)),
        "dwarf verify_avk_chain accepted a pretty-printed NextAvk \
         (or returned a non-AVKMismatch error): {dwarf_result:?}. \
         Divergence #6 has closed (or inverted) on the dwarf side — \
         the registry narrative no longer holds."
    );
}

/// Corpus-wide gate: documented divergences must preserve verdict
/// equivalence. A divergent verdict here means a registry entry has
/// soundness fallout that was missed.
#[test]
fn divergence_registry_verdict_equivalence_holds_on_corpus() {
    let load = load_corpus(Path::new(CORPUS_DIR));
    assert!(
        load.load_errors.is_empty(),
        "corpus load errors: {:?}",
        load.load_errors
    );

    let mut divergent: Vec<String> = Vec::new();
    for entry in &load.entries {
        let cert = entry.primary_cert();
        let vk = genesis_vk_for_cert(cert).unwrap_or_else(|| {
            panic!(
                "no genesis VK registered for network {:?} (cert {}). \
                 Extend genesis_vk_for_cert in corpus.rs.",
                cert.metadata.network, cert.hash
            )
        });
        let audit = audit_corpus_entry(entry, vk);
        let mithril_pass = matches!(audit.full_verify.mithril.outcome, Outcome::Pass);
        let dwarf_pass = matches!(audit.full_verify.dwarf.outcome, Outcome::Pass);
        if mithril_pass != dwarf_pass {
            divergent.push(format!(
                "{}: mithril={:?}, dwarf={:?}",
                audit.cert_label, audit.full_verify.mithril.outcome, audit.full_verify.dwarf.outcome
            ));
        }
    }

    assert!(
        divergent.is_empty(),
        "verdict equivalence failed on positive corpus:\n{}",
        divergent.join("\n")
    );
}
