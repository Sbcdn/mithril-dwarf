//! Bitwise equivalence harness: `mithril-dwarf` vs upstream Mithril.
//!
//! Two top-level assertions:
//!
//! 1. Every certificate in the corpus is parsed and audited; every
//!    per-check and top-level result must bitwise-match upstream.
//! 2. The mutation suite must produce equivalent verdicts on at least
//!    one cert per mutation. A false positive (dwarf accepts what
//!    upstream rejects), a soundness regression (dwarf rejects what
//!    upstream accepts), or a fully no-op mutation all fail the test.
//!
//! Both impls rejecting with different `ErrorCategory` values is a
//! soft divergence — reported but not fatal; the security contract is
//! both impls saying "no".

use std::path::Path;

use mithril_dwarf_harness::{
    AppliedMutation, CertAudit, CorpusEntry, ErrorCategory, Outcome,
    applied_mutation_label, apply_mutation, audit_corpus_entry, audit_mutated_top_level_only,
    audit_standard_top_level_only, genesis_vk_for_cert, load_corpus, render_report,
    standard_mutations,
};

const CORPUS_DIR: &str = "tests/test_data/certificates";

/// Per-(mutation × cert) outcome class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MutationOutcome {
    /// Both impls rejected. The category pair is captured for the
    /// rejection-category breakdown; matching categories are ideal,
    /// differing categories are a soft divergence.
    BothReject,
    /// Both impls accepted. The mutation was a no-op on this cert;
    /// must reject on at least one other cert (checked after the loop).
    BothAccept,
    /// Hard failure: upstream rejected, dwarf accepted.
    Critical,
    /// Hard failure: dwarf rejected, upstream accepted.
    SoundnessRegression,
    /// Reserved for documented design tradeoffs; no variants assigned today.
    IntentionalDivergence,
}

fn outcome_category(o: Outcome) -> Option<ErrorCategory> {
    match o {
        Outcome::Fail(c) => Some(c),
        Outcome::Pass | Outcome::NotApplicable => None,
    }
}

/// Classify a single mutation audit and return the outcome category.
/// Hard failures (Critical, SoundnessRegression) are also pushed onto
/// `failures` for end-of-run reporting; the BothAccept aggregation
/// across corpus certs happens after the loop in
/// `mutations_are_rejected_equivalently`.
fn classify_mutation_outcome(
    applied: &AppliedMutation,
    audit: CertAudit,
    failures: &mut Vec<(AppliedMutation, CertAudit, &'static str)>,
    all_mutated: &mut Vec<CertAudit>,
) -> MutationOutcome {
    let mithril_pass = matches!(audit.full_verify.mithril.outcome, Outcome::Pass);
    let dwarf_pass = matches!(audit.full_verify.dwarf.outcome, Outcome::Pass);
    let outcome = match (mithril_pass, dwarf_pass) {
        (false, true) => {
            if audit.mutation_intentionally_diverges {
                MutationOutcome::IntentionalDivergence
            } else {
                failures.push((
                    applied.clone(),
                    audit.clone(),
                    "CRITICAL — MITHRIL REJECTED, DWARF ACCEPTED (false positive)",
                ));
                MutationOutcome::Critical
            }
        }
        (true, false) => {
            failures.push((
                applied.clone(),
                audit.clone(),
                "SOUNDNESS REGRESSION — DWARF REJECTED, MITHRIL ACCEPTED",
            ));
            MutationOutcome::SoundnessRegression
        }
        (true, true) => MutationOutcome::BothAccept,
        (false, false) => MutationOutcome::BothReject,
    };
    all_mutated.push(audit);
    outcome
}

#[test]
fn corpus_positive_audit_bitwise_match() {
    let load = load_corpus(Path::new(CORPUS_DIR));
    assert!(
        load.load_errors.is_empty(),
        "corpus load errors: {:?}",
        load.load_errors
    );
    assert!(
        !load.entries.is_empty(),
        "corpus at {CORPUS_DIR} is empty — populate via fetch_certificates"
    );
    assert!(
        load.genesis_count >= 1,
        "corpus must contain a genesis cert to exercise the Ed25519 path"
    );
    assert!(
        load.standard_diff_epoch >= 1,
        "corpus must contain at least one cross-epoch standard pair to exercise the AVK chain path"
    );

    let mut diverged: Vec<CertAudit> = Vec::new();
    for entry in &load.entries {
        // Pick the right genesis VK per entry's network (mainnet vs
        // preprod / preview). Standard entries don't use the VK, so
        // any value works; genesis entries need the matching network's
        // VK or genesis verification will diverge between dwarf and
        // upstream.
        let cert = entry.primary_cert();
        let vk = genesis_vk_for_cert(cert).unwrap_or_else(|| {
            panic!(
                "no genesis VK registered for network {:?} (cert {}). \
                 Update genesis_vk_for_cert in corpus.rs to cover this \
                 network — silent fallback to mainnet would mask the miss.",
                cert.metadata.network, cert.hash
            )
        });
        let audit = audit_corpus_entry(entry, vk);
        if !audit.all_match() {
            diverged.push(audit);
        }
    }

    if !diverged.is_empty() {
        let (report, _) = render_report(&diverged, &[]);
        panic!("bitwise divergence on positive corpus:\n{report}");
    }
}

#[test]
fn mutations_are_rejected_equivalently() {
    let load = load_corpus(Path::new(CORPUS_DIR));
    assert!(
        load.load_errors.is_empty(),
        "corpus load errors: {:?}",
        load.load_errors
    );
    // Scale: apply every applicable mutation against EVERY standard
    // cert in the corpus, not just the first. Coverage was previously
    // ~22 cross-impl assertions per run (1 cert × ~22 mutations); now
    // it is `N(standard certs) × ~22 mutations`, growing the
    // adversarial cross-impl surface in proportion to the corpus.
    let standard_bases: Vec<&CorpusEntry> = load
        .entries
        .iter()
        .filter(|e| matches!(e, CorpusEntry::Standard { .. }))
        .collect();
    assert!(
        !standard_bases.is_empty(),
        "no standard cert in corpus to mutate"
    );

    let mutations = standard_mutations();
    let mut failures: Vec<(AppliedMutation, CertAudit, &'static str)> = Vec::new();
    let mut all_mutated: Vec<CertAudit> = Vec::new();
    // Per-mutation tally of (BothReject, BothAccept) counts across the
    // corpus. After the loop, every mutation must have produced at
    // least one BothReject somewhere — otherwise it's structurally
    // broken (e.g. an applicability filter that lets the mutation
    // through but produces a no-op on every cert). Per-cert no-ops
    // are expected variation: a previous-target NextAvk mutation is
    // genuinely a no-op on same-epoch pairs because neither verifier
    // reads `prev.protocol_message[NextAvk]` on that path.
    use std::collections::BTreeMap;
    let mut per_mutation_tally: BTreeMap<String, (usize, usize)> = BTreeMap::new();
    // Rejection-category pair tally: matching pair = tight rejection;
    // differing pair = soft divergence (still verdict-equivalent).
    let mut category_pair_tally: BTreeMap<(ErrorCategory, ErrorCategory), usize> = BTreeMap::new();

    for base in &standard_bases {
        let base_cert = match base {
            CorpusEntry::Standard { current, .. } => current,
            _ => unreachable!("filtered above"),
        };
        let applicable: Vec<AppliedMutation> = mutations
            .iter()
            .filter(|am| am.mutation.is_applicable_to(base_cert))
            .cloned()
            .collect();
        for applied in &applicable {
            // Top-level-only audit: 12× cheaper than the full per-check
            // audit; the security contract is on the top-level verdict
            // pair, not the per-check pairs (those are
            // diagnostic-quality and covered by
            // corpus_positive_audit_bitwise_match).
            let base_cert_ref = base.primary_cert();
            let vk = genesis_vk_for_cert(base_cert_ref).unwrap_or_else(|| {
                panic!(
                    "no genesis VK registered for network {:?} (cert {}). \
                     Extend genesis_vk_for_cert in corpus.rs.",
                    base_cert_ref.metadata.network, base_cert_ref.hash
                )
            });
            let audit = audit_mutated_top_level_only(base, applied, vk);
            // Capture the category pair BEFORE moving `audit` into the
            // classifier (which consumes it via Clone into `failures`
            // / `all_mutated`).
            let mithril_cat = outcome_category(audit.full_verify.mithril.outcome);
            let dwarf_cat = outcome_category(audit.full_verify.dwarf.outcome);
            let outcome =
                classify_mutation_outcome(applied, audit, &mut failures, &mut all_mutated);
            let tally = per_mutation_tally
                .entry(applied_mutation_label(applied))
                .or_insert((0, 0));
            match outcome {
                MutationOutcome::BothReject => {
                    tally.0 += 1;
                    if let (Some(m), Some(d)) = (mithril_cat, dwarf_cat) {
                        *category_pair_tally.entry((m, d)).or_insert(0) += 1;
                    }
                }
                MutationOutcome::BothAccept => tally.1 += 1,
                _ => {}
            }
        }
    }

    // Aggregated insufficient check: a mutation that produced ZERO
    // rejections across the entire corpus is structurally broken.
    // Per-cert no-ops are tolerated as long as the same mutation
    // attacked at least one other cert successfully.
    let structurally_insufficient: Vec<(String, usize)> = per_mutation_tally
        .iter()
        .filter_map(|(label, (rejects, accepts))| {
            if *rejects == 0 && *accepts > 0 {
                Some((label.clone(), *accepts))
            } else {
                None
            }
        })
        .collect();

    let total_assertions: usize = per_mutation_tally
        .values()
        .map(|(r, a)| r + a)
        .sum();
    let total_rejects: usize = per_mutation_tally.values().map(|(r, _)| *r).sum();
    let total_accepts: usize = per_mutation_tally.values().map(|(_, a)| *a).sum();
    eprintln!(
        "mutations_are_rejected_equivalently: {total_assertions} cross-impl assertions across \
         {} corpus certs × {} unique mutations — both_reject={total_rejects}, \
         both_accept={total_accepts} (acceptable per-cert no-ops), \
         critical=0 hard-fail-tolerated, soundness=0 hard-fail-tolerated. \
         {} mutations were no-ops on every corpus cert (structural failure).",
        standard_bases.len(),
        per_mutation_tally.len(),
        structurally_insufficient.len(),
    );

    // Rejection-category breakdown, top entries sorted by count.
    let matching_pairs: usize = category_pair_tally
        .iter()
        .filter(|((m, d), _)| m == d)
        .map(|(_, c)| *c)
        .sum();
    let diverging_pairs: usize = total_rejects.saturating_sub(matching_pairs);
    eprintln!(
        "  category breakdown: {matching_pairs} tight (mithril_cat == dwarf_cat), \
         {diverging_pairs} soft (different categories, both reject)."
    );
    let mut sorted_pairs: Vec<_> = category_pair_tally.iter().collect();
    sorted_pairs.sort_by(|a, b| b.1.cmp(a.1));
    for ((mithril_cat, dwarf_cat), count) in sorted_pairs.iter().take(10) {
        let tag = if mithril_cat == dwarf_cat { "tight" } else { "soft " };
        eprintln!(
            "    {tag}  {count:5}× ({mithril_cat:?}, {dwarf_cat:?})",
        );
    }

    if !failures.is_empty() || !structurally_insufficient.is_empty() {
        let mut details = String::from("\nmutation suite failures:\n");
        for (applied, audit, reason) in &failures {
            details.push_str(&format!(
                "\n  [{reason}]\n    mutation: {}\n    mithril outcome: {:?}\n    dwarf   outcome: {:?}\n    label: {}\n",
                applied_mutation_label(applied),
                audit.full_verify.mithril.outcome,
                audit.full_verify.dwarf.outcome,
                audit.cert_label,
            ));
        }
        for (label, count) in &structurally_insufficient {
            details.push_str(&format!(
                "\n  [STRUCTURALLY INSUFFICIENT — mutation was a no-op on all {count} applicable corpus certs]\n    mutation: {label}\n",
            ));
        }
        let (full_report, _) = render_report(&[], &all_mutated);
        panic!("{details}\nFull report:\n{full_report}");
    }
}

/// Adversarial-precondition gate for the mutation suite.
///
/// `mutations_are_rejected_equivalently` derives its signal from the
/// claim "mutating a legitimate cert produces a rejected cert". That
/// claim only carries weight if the unmutated baseline is independently
/// accepted by both impls — otherwise "rejection after mutation" is
/// vacuously true (the cert was already rejected before the mutation).
///
/// `corpus_positive_audit_bitwise_match` is not a substitute: it
/// confirms per-check bitwise match between the impls, which is
/// satisfied even when both produce `Fail` outcomes (a bitwise-matching
/// double rejection). This gate adds the missing constraint: at the
/// top level, both impls must `Pass` on every cert the mutation suite
/// will use as a base.
///
/// Failure here means "the mutation suite is testing something other
/// than what its name claims". Fix the corpus (drop the offending
/// entry or fix its source) before drawing conclusions from
/// `mutations_are_rejected_equivalently`.
#[test]
fn mutation_suite_baseline_preconditions_hold() {
    let load = load_corpus(Path::new(CORPUS_DIR));
    assert!(
        load.load_errors.is_empty(),
        "corpus load errors: {:?}",
        load.load_errors
    );
    let standard_bases: Vec<&CorpusEntry> = load
        .entries
        .iter()
        .filter(|e| matches!(e, CorpusEntry::Standard { .. }))
        .collect();
    assert!(
        !standard_bases.is_empty(),
        "no standard cert in corpus — mutation suite would have no bases"
    );

    let mut vacuous: Vec<String> = Vec::new();
    for base in &standard_bases {
        let cert = base.primary_cert();
        let vk = genesis_vk_for_cert(cert).unwrap_or_else(|| {
            panic!(
                "no genesis VK for network {:?} (cert {})",
                cert.metadata.network, cert.hash
            )
        });
        let audit = audit_corpus_entry(base, vk);
        let m_pass = matches!(audit.full_verify.mithril.outcome, Outcome::Pass);
        let d_pass = matches!(audit.full_verify.dwarf.outcome, Outcome::Pass);
        if !(m_pass && d_pass) {
            vacuous.push(format!(
                "  {}: mithril={:?}, dwarf={:?}",
                audit.cert_label,
                audit.full_verify.mithril.outcome,
                audit.full_verify.dwarf.outcome
            ));
        }
    }

    assert!(
        vacuous.is_empty(),
        "mutation-suite baseline broken — these corpus entries are not \
         accepted by both impls in their unmutated state, so any \
         rejection after mutation is vacuous:\n{}\n\n\
         Refresh the corpus via `fetch_certificates`, or remove the \
         offending entries before relying on \
         `mutations_are_rejected_equivalently`.",
        vacuous.join("\n")
    );

    // Mutation-set integrity: every mutation must produce a behavioural
    // change on at least one base. "Behavioural change" means either
    // byte-different output after round-tripping through the
    // host serializer, OR the mutated form failed `try_into()` (which
    // counts: the mutation had bite at the type-conversion boundary).
    // Two distinct failure modes are reported separately so the user
    // can tell whether to fix a mutation (byte no-op) or the corpus
    // (mutation never applies).
    use mithril_dwarf::certificate_to_bytes;
    let mutations = standard_mutations();
    let mut dead_mutations: Vec<(String, &'static str)> = Vec::new();
    for applied in &mutations {
        let mut applicable_count = 0usize;
        let mut produced_change = false;
        for base in &standard_bases {
            let base_cert = match base {
                CorpusEntry::Standard { current, .. } => current,
                _ => unreachable!(),
            };
            if !applied.mutation.is_applicable_to(base_cert) {
                continue;
            }
            applicable_count += 1;
            let original_typed: mithril_common::entities::Certificate =
                base_cert.clone().try_into().expect("base try_into");
            let original_bytes = certificate_to_bytes(&original_typed);
            let mutated_msg = apply_mutation(base_cert, &applied.mutation);
            let mutated_typed: Result<mithril_common::entities::Certificate, _> =
                mutated_msg.try_into();
            let mutated_bytes = match mutated_typed {
                Ok(t) => certificate_to_bytes(&t),
                Err(_) => {
                    produced_change = true;
                    break;
                }
            };
            if original_bytes != mutated_bytes {
                produced_change = true;
                break;
            }
        }
        if applicable_count == 0 {
            dead_mutations.push((
                applied_mutation_label(applied),
                "no applicable base in corpus — extend corpus or drop the mutation",
            ));
        } else if !produced_change {
            dead_mutations.push((
                applied_mutation_label(applied),
                "byte-identical output on every applicable base — mutation is a no-op",
            ));
        }
    }
    if !dead_mutations.is_empty() {
        let detail = dead_mutations
            .iter()
            .map(|(m, why)| format!("  - {m}\n      {why}"))
            .collect::<Vec<_>>()
            .join("\n");
        panic!(
            "mutation-set integrity broken — these mutations would let \
             `mutations_are_rejected_equivalently` claim coverage they \
             do not have:\n{detail}"
        );
    }
}

/// Differential byte-fuzz over the real corpus.
///
/// The "PROVE not assume" gate: take every standard cert in the
/// corpus, programmatically flip ASCII-hex chars at many positions
/// across every hex-encoded field of the `CertificateMessage`
/// (`hash`, `previous_hash`, `signed_message`,
/// `aggregate_verification_key`, `multi_signature`), and for each
/// resulting mutated message:
///
///   - feed to UPSTREAM via `try_into() → verify`
///   - feed to DWARF via `certificate_to_bytes() → verify`
///   - assert the two verdicts AGREE
///
/// Verdict equivalence is the contract: both-accept (the mutation
/// was a no-op at that byte position, e.g. inside slack JSON
/// whitespace) and both-reject are equivalent. The hard failure
/// modes are:
///
///   - CRITICAL: upstream rejects, dwarf accepts. Soundness break.
///   - SOUNDNESS REGRESSION: upstream accepts, dwarf rejects.
///     Operational break (proofs that should succeed don't).
///
/// Unlike `mutations_are_rejected_equivalently` (hand-picked
/// semantic mutations), this exercises the dense byte-level
/// adversarial surface — many more assertions per run, generated
/// programmatically from real corpus data. Unlike
/// `dwarf_parser_rejects_byte_mutated_input` (one-sided
/// parser-robustness test), every assertion here is a cross-impl
/// equivalence check.
#[test]
fn cross_impl_byte_fuzz_on_real_certs() {
    let load = load_corpus(Path::new(CORPUS_DIR));
    assert!(
        load.load_errors.is_empty(),
        "corpus load errors: {:?}",
        load.load_errors
    );
    let standard_bases: Vec<(&CorpusEntry, &mithril_common::messages::CertificateMessage,
                              &mithril_common::messages::CertificateMessage)> = load
        .entries
        .iter()
        .filter_map(|e| match e {
            CorpusEntry::Standard { current, previous } => Some((e, current, previous)),
            _ => None,
        })
        .collect();
    assert!(
        !standard_bases.is_empty(),
        "no standard cert in corpus to fuzz"
    );

    // Positions to flip per field. Sparse coverage across each field's
    // length — every position is a distinct cross-impl assertion. Total
    // assertions per run: N(corpus certs) × sum(positions per field).
    let small_field_positions: &[usize] = &[0, 1, 7, 15, 31, 47, 63];
    let large_field_positions: &[usize] = &[
        0, 1, 7, 16, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768,
    ];

    let mut critical: Vec<String> = Vec::new();
    let mut soundness: Vec<String> = Vec::new();
    let mut both_accept = 0usize;
    let mut both_reject = 0usize;
    let mut total = 0usize;
    // Non-hex positions (JSON syntax inside hex-encoded envelopes,
    // padding) silently no-op; count them separately so the headline
    // assertion total reflects only real mutations.
    let mut skipped_nonhex = 0usize;
    use std::collections::BTreeMap;
    let mut category_pair_tally: BTreeMap<(ErrorCategory, ErrorCategory), usize> = BTreeMap::new();

    for (base, current, _previous) in &standard_bases {
        // Iterate (field_name, positions) tuples. Each clone-and-flip
        // produces one mutated CertificateMessage; we route it through
        // both impls via audit_standard_with_mutated_msgs.
        let field_targets: &[(&str, &[usize])] = &[
            ("hash", small_field_positions),
            ("previous_hash", small_field_positions),
            ("signed_message", small_field_positions),
            ("aggregate_verification_key", large_field_positions),
            ("multi_signature", large_field_positions),
        ];

        for (field_name, positions) in field_targets {
            for &pos in *positions {
                let mut mutated = (*current).clone();
                let flip = flip_one_hex_char(&mut mutated, field_name, pos);

                // Three cases. Only `Flipped` counts as a real cross-impl
                // assertion. `SkippedNonHex` is recorded separately so
                // the headline assertion total reflects only real
                // mutations. `OutOfRange` is just "pos beyond field".
                match flip {
                    FlipResult::Flipped => {}
                    FlipResult::SkippedNonHex => {
                        skipped_nonhex += 1;
                        continue;
                    }
                    FlipResult::OutOfRange => continue,
                }
                total += 1;

                let prev = match base {
                    CorpusEntry::Standard { previous, .. } => previous.clone(),
                    _ => unreachable!(),
                };
                let label = format!("flip {field_name}[{pos}]");
                let audit = audit_standard_top_level_only(&mutated, &prev, label.clone());

                let mithril_pass = matches!(audit.full_verify.mithril.outcome, Outcome::Pass);
                let dwarf_pass = matches!(audit.full_verify.dwarf.outcome, Outcome::Pass);
                let mithril_cat = outcome_category(audit.full_verify.mithril.outcome);
                let dwarf_cat = outcome_category(audit.full_verify.dwarf.outcome);

                match (mithril_pass, dwarf_pass) {
                    (false, true) => critical.push(format!(
                        "CRITICAL: {label} on {} — upstream REJECTED, dwarf ACCEPTED",
                        audit.cert_label
                    )),
                    (true, false) => soundness.push(format!(
                        "SOUNDNESS REGRESSION: {label} on {} — upstream ACCEPTED, dwarf REJECTED",
                        audit.cert_label
                    )),
                    (true, true) => both_accept += 1,
                    (false, false) => {
                        both_reject += 1;
                        if let (Some(m), Some(d)) = (mithril_cat, dwarf_cat) {
                            *category_pair_tally.entry((m, d)).or_insert(0) += 1;
                        }
                    }
                }
            }
        }
    }

    eprintln!(
        "cross_impl_byte_fuzz_on_real_certs: {total} REAL cross-impl assertions across \
         {} corpus certs — both_reject={both_reject}, both_accept={both_accept}, \
         critical={}, soundness={}. Plus {skipped_nonhex} positions skipped \
         (non-hex byte at position — JSON syntax inside hex-encoded envelope, \
         padding, etc.; no mutation applied, not counted as assertion).",
        standard_bases.len(),
        critical.len(),
        soundness.len()
    );
    // Skewed distributions (e.g. >95% HashMismatch) signal the fuzz is
    // catching the cheap cert-hash check before the verifier reaches
    // AVK / BLS / protocol-params paths.
    let matching_pairs: usize = category_pair_tally
        .iter()
        .filter(|((m, d), _)| m == d)
        .map(|(_, c)| *c)
        .sum();
    let diverging_pairs: usize = both_reject.saturating_sub(matching_pairs);
    eprintln!(
        "  category breakdown: {matching_pairs} tight, {diverging_pairs} soft."
    );
    let mut sorted_pairs: Vec<_> = category_pair_tally.iter().collect();
    sorted_pairs.sort_by(|a, b| b.1.cmp(a.1));
    for ((mithril_cat, dwarf_cat), count) in sorted_pairs.iter().take(10) {
        let tag = if mithril_cat == dwarf_cat { "tight" } else { "soft " };
        eprintln!(
            "    {tag}  {count:5}× ({mithril_cat:?}, {dwarf_cat:?})",
        );
    }

    if !critical.is_empty() || !soundness.is_empty() {
        let mut details = String::from("\ndifferential fuzz failures:\n");
        for line in critical.iter().chain(soundness.iter()) {
            details.push_str("  ");
            details.push_str(line);
            details.push('\n');
        }
        panic!("{details}");
    }
}

/// Flip one ASCII-hex character in the given field of `msg`. Returns
/// the original byte that was replaced, or `None` if the field is
/// empty or `pos` is out of range. The toggle table maps each ASCII
/// hex digit to an adjacent digit (`0↔1`, `2↔3`, …, `a↔b`, `c↔d`,
/// `e↔f`, same for uppercase) — the result is still a well-formed
/// hex digit, preserving the JSON-hex envelope's validity while
/// changing the cryptographic payload it encodes.
///
/// Field names map to `CertificateMessage` fields; unknown names panic
/// with a clear scaffolding-bug message (so a typo in the test driver
/// surfaces immediately, not as a silent skip).
/// Outcome of `flip_one_hex_char`. The three explicit cases prevent
/// non-hex no-ops (JSON syntax like `,{}[]:"` inside hex envelopes,
/// padding bytes) from silently inflating the assertion total.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FlipResult {
    /// Byte at `pos` was a hex digit and got toggled to a different
    /// hex digit. A real adversarial mutation.
    Flipped,
    /// Byte at `pos` was NOT a hex digit. No mutation applied; the
    /// position contributes no adversarial signal. Counted in a
    /// separate `skipped_nonhex` bucket, not the assertion total.
    SkippedNonHex,
    /// `pos` is beyond the field's length.
    OutOfRange,
}

fn flip_one_hex_char(
    msg: &mut mithril_common::messages::CertificateMessage,
    field_name: &str,
    pos: usize,
) -> FlipResult {
    let s: &mut String = match field_name {
        "hash" => &mut msg.hash,
        "previous_hash" => &mut msg.previous_hash,
        "signed_message" => &mut msg.signed_message,
        "aggregate_verification_key" => &mut msg.aggregate_verification_key,
        "multi_signature" => &mut msg.multi_signature,
        "genesis_signature" => &mut msg.genesis_signature,
        other => panic!("flip_one_hex_char: unknown field {other:?}"),
    };
    if pos >= s.len() {
        return FlipResult::OutOfRange;
    }
    // SAFETY: ASCII hex toggle maps a single-byte ASCII char to another
    // single-byte ASCII char (UTF-8 1-byte → UTF-8 1-byte); the byte
    // boundary at `pos` is preserved. Mirrors the harness's existing
    // `mutation::flip_hex_char` helper.
    let bytes = unsafe { s.as_bytes_mut() };
    let original = bytes[pos];
    let toggled = match original {
        b'0' => b'1', b'1' => b'0',
        b'2' => b'3', b'3' => b'2',
        b'4' => b'5', b'5' => b'4',
        b'6' => b'7', b'7' => b'6',
        b'8' => b'9', b'9' => b'8',
        b'a' => b'b', b'b' => b'a',
        b'c' => b'd', b'd' => b'c',
        b'e' => b'f', b'f' => b'e',
        b'A' => b'B', b'B' => b'A',
        b'C' => b'D', b'D' => b'C',
        b'E' => b'F', b'F' => b'E',
        // Non-hex byte: explicitly skipped so the test driver doesn't
        // count it as a real assertion.
        _ => return FlipResult::SkippedNonHex,
    };
    bytes[pos] = toggled;
    FlipResult::Flipped
}

/// One-sided parser-robustness test. Models the in-guest threat: the
/// host hands raw bytes directly to dwarf with no upstream gatekeeper,
/// so this test bypasses upstream entirely and asserts dwarf rejects
/// arbitrary byte flips.
///
/// `dwarf_leader_upstream_oracle_equivalence` covers the cross-impl
/// semantic-mutation case; this covers the wire-byte case.
///
/// Both "fails to parse" and "parses but fails to verify" count as
/// rejection. Acceptance is a CRITICAL security failure. Panics are
/// caught and counted separately — a panic on adversarial bytes is
/// not a security failure (the cert is rejected) but is a DoS
/// concern inside a zkVM and is surfaced in the test output.
#[test]
fn dwarf_parser_rejects_byte_mutated_input() {
    use mithril_common::entities::Certificate;
    use mithril_dwarf::{certificate_from_bytes, certificate_to_bytes};

    let load = load_corpus(Path::new(CORPUS_DIR));
    let standard = load
        .entries
        .iter()
        .find_map(|e| match e {
            CorpusEntry::Standard { current, previous } => Some((current, previous)),
            _ => None,
        })
        .expect("no standard cert in corpus");

    let curr: Certificate = standard.0.clone().try_into().expect("try_into");
    let prev: Certificate = standard.1.clone().try_into().expect("try_into");
    let valid_curr_bytes = certificate_to_bytes(&curr);
    let valid_prev_bytes = certificate_to_bytes(&prev);
    let prev_zc = certificate_from_bytes(&valid_prev_bytes).expect("prev parses");

    // Sample byte positions across the wire: start, near-start, deep
    // middle, near-end, end. Plus an explicit "all bits flipped" target
    // at the dead-middle which is statistically inside the BLS payload.
    let len = valid_curr_bytes.len();
    let positions: &[usize] = &[
        0,
        4,
        16,
        128,
        len / 8,
        len / 4,
        len / 2,
        (3 * len) / 4,
        len.saturating_sub(64),
        len.saturating_sub(1),
    ];

    let mut accepts: Vec<(usize, u8)> = Vec::new();
    let mut panics: Vec<(usize, u8)> = Vec::new();

    for &pos in positions {
        if pos >= len {
            continue;
        }
        // Two perturbations per position: low-bit toggle and all-bit flip.
        for mask in [0x01u8, 0xFFu8] {
            let mut mutated = valid_curr_bytes.clone();
            mutated[pos] ^= mask;

            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                match certificate_from_bytes(&mutated) {
                    Ok(curr_zc) => mithril_dwarf::verify_standard_certificate(&curr_zc, &prev_zc),
                    Err(_) => {
                        Err(mithril_dwarf::certificate_verification::VerifyError::FormatError)
                    }
                }
            }));

            match result {
                Ok(Ok(())) => accepts.push((pos, mask)),
                Ok(Err(_)) => { /* rejected via verify error — fine */ }
                Err(_) => panics.push((pos, mask)),
            }
        }
    }

    if !accepts.is_empty() {
        panic!(
            "CRITICAL: dwarf accepted byte-mutated input (len {len}). Mask 0x01 = low-bit toggle, 0xFF = invert byte. Accepts: {accepts:?}"
        );
    }
    // Panics don't fail the test (the cert is still rejected, which is the
    // security contract) but they're a DoS concern in a zkVM and worth
    // surfacing. Print to stderr; cargo test shows it on failure or with
    // `--nocapture`.
    if !panics.is_empty() {
        eprintln!(
            "note: dwarf panicked on {} byte-mutated input(s) (rejected but DoS-able): {panics:?}",
            panics.len()
        );
    }
}

/// Pins dwarf's BLS-identity rejection through the full parse + verify
/// pipeline. Consolidates the three former tests:
///
///   * `bls_identity_point_rejection_proven` — the blst dependency pin
///     moved to `intentional_divergences.rs::divergence_1_bls_identity_defence_layer_pinned`
///     (where it belongs: it documents WHY dwarf needs a verify-time
///     defence — blst accepts identity at parse).
///   * `bls_identity_sigma_rejected_by_dwarf_verify`
///   * `bls_identity_vk_rejected_by_dwarf_verify`
///
/// Both splice tests collapsed into one parameterised loop over
/// (sigma slot, vk slot). The upstream-side `try_into()` assertion
/// was dropped: it was calling blst through mithril-stm wrappers —
/// the SAME blst entry point as the dependency pin — so it added no
/// impl-vs-impl distinguishing power. The registry's blst pin covers
/// what those assertions tested.
///
/// What this test PROVES that nothing else does:
///   * dwarf's full parse -> verify pipeline rejects bytes whose
///     `signatures[0].sigma` is the G1 identity point.
///   * Same for `signatures[0].(RegisteredParty.vk)` G2 identity.
///   * Rejection happens AT THE PAIRING CHECK in dwarf, not at parse
///     (the parser doesn't validate BLS structure).
///
/// CRITICAL if it ever passes the cert through dwarf: an attacker
/// could harvest lottery wins from a non-signing party (identity
/// sigma) or harvest lottery wins for free (identity VK contributes
/// 0 to agg_pk so the pairing reduces to honest signers + extra
/// lottery slot).
#[test]
fn dwarf_rejects_bls_identity_in_cert() {
    use mithril_common::entities::Certificate;
    use mithril_dwarf::parser::byte_deserializer::{
        SignatureBasicZeroCopy, certificate_from_bytes,
    };
    use mithril_dwarf::{certificate_to_bytes, verify_standard_certificate};

    let load = load_corpus(Path::new(CORPUS_DIR));
    let standard = load
        .entries
        .iter()
        .find_map(|e| match e {
            CorpusEntry::Standard { current, previous } => Some((current, previous)),
            _ => None,
        })
        .expect("no standard cert in corpus");

    let curr: Certificate = standard.0.clone().try_into().expect("try_into current");
    let prev: Certificate = standard.1.clone().try_into().expect("try_into previous");
    let curr_bytes_clean = certificate_to_bytes(&curr);
    let prev_bytes = certificate_to_bytes(&prev);

    let parsed = certificate_from_bytes(&curr_bytes_clean).expect("parse clean curr");
    let (original_sigma, original_vk): ([u8; 48], [u8; 96]) = match parsed.signature {
        SignatureBasicZeroCopy::Multi { signature, .. } => {
            let first = signature
                .signatures
                .first()
                .expect("at least one signer in standard cert");
            (*first.sigma_bytes, *first.vk_bytes)
        }
        SignatureBasicZeroCopy::Genesis { .. } => {
            panic!("expected a standard (Multi) cert, got Genesis")
        }
    };

    // Sub-case driver: splice `identity_bytes` over `original_bytes`'s
    // unique occurrence in the wire and assert dwarf's verifier rejects.
    let run_splice = |label: &str, original_bytes: &[u8], identity_bytes: &[u8]| {
        let n = original_bytes.len();
        assert_eq!(n, identity_bytes.len(), "identity length must match original");

        let mut occurrences = 0usize;
        let mut splice_at: Option<usize> = None;
        for window_start in 0..=(curr_bytes_clean.len().saturating_sub(n)) {
            if &curr_bytes_clean[window_start..window_start + n] == original_bytes {
                occurrences += 1;
                splice_at = Some(window_start);
            }
        }
        assert_eq!(
            occurrences, 1,
            "{label}: expected exactly one occurrence of the original {n}-byte blob \
             in the wire, found {occurrences} - corpus cert may be degenerate."
        );
        let splice_at = splice_at.expect("splice offset");

        let mut mutated = curr_bytes_clean.clone();
        mutated[splice_at..splice_at + n].copy_from_slice(identity_bytes);

        let curr_zc = certificate_from_bytes(&mutated).unwrap_or_else(|_| {
            panic!(
                "{label}: dwarf parser must accept identity-encoded bytes \
                 (parser does not validate BLS structure)"
            )
        });
        let prev_zc = certificate_from_bytes(&prev_bytes).expect("parse prev");

        let result = verify_standard_certificate(&curr_zc, &prev_zc);
        assert!(
            result.is_err(),
            "CRITICAL: dwarf accepted a cert with BLS identity at {label}. \
             Got Ok from verify_standard_certificate. \
             An attacker could harvest lottery wins from a non-signing party."
        );
    };

    // G1 identity: 48 bytes, [0xC0, 0x00, ..., 0x00].
    let mut g1_identity = [0u8; 48];
    g1_identity[0] = 0xC0;
    run_splice("signatures[0].sigma (G1)", &original_sigma, &g1_identity);

    // G2 identity: 96 bytes, same encoding shape.
    let mut g2_identity = [0u8; 96];
    g2_identity[0] = 0xC0;
    run_splice("signatures[0].vk (G2)", &original_vk, &g2_identity);
}

/// Dwarf-as-leader, upstream-as-oracle. Reverses the direction of the
/// other equivalence tests: take dwarf wire bytes, parse with dwarf,
/// run the parsed view back through the host converter to an upstream
/// `Certificate`, verify with upstream, and compare verdicts against
/// dwarf's verifier on the same view.
///
/// Pins that the host converter and the dwarf parser agree on the
/// wire layout; a converter regression that drops a verification-
/// relevant field shows up as a verdict divergence. Negative coverage
/// piggybacks on `standard_mutations` for the adversarial-input arm.
#[test]
fn dwarf_leader_upstream_oracle_equivalence() {
    use mithril_common::entities::Certificate;
    use mithril_dwarf::parser::byte_deserializer::certificate_from_bytes;
    use mithril_dwarf::parser::minimal_converter::certificate_from_zerocopy;
    use mithril_dwarf::{certificate_to_bytes, verify_standard_certificate};
    use mithril_dwarf_harness::{apply_mutation, MutationTarget};

    let load = load_corpus(Path::new(CORPUS_DIR));
    assert!(
        load.load_errors.is_empty(),
        "corpus load errors: {:?}",
        load.load_errors
    );

    let standard_bases: Vec<(&mithril_common::messages::CertificateMessage,
                              &mithril_common::messages::CertificateMessage)> = load
        .entries
        .iter()
        .filter_map(|e| match e {
            CorpusEntry::Standard { current, previous } => Some((current, previous)),
            _ => None,
        })
        .collect();
    assert!(
        !standard_bases.is_empty(),
        "no standard cert in corpus for dwarf-leader path"
    );

    // Closure: given current + previous CertificateMessages, run both
    // pipelines and assert verdict equivalence. Returns (mithril_pass,
    // dwarf_pass) for caller-side stats.
    let run_pair = |curr_msg: &mithril_common::messages::CertificateMessage,
                    prev_msg: &mithril_common::messages::CertificateMessage,
                    label: &str|
     -> (bool, bool) {
        // Upstream try_into can fail on adversarially-mutated certs
        // (mithril-stm wrappers reject malformed BLS, etc.). When it
        // does, dwarf never gets bytes to parse — both impls reject
        // upstream-side. Skip the pair; the scaled mutation suite
        // already covers this scenario through audit_mutated.
        let Ok(curr_typed): Result<Certificate, _> = curr_msg.clone().try_into() else {
            return (false, false);
        };
        let Ok(prev_typed): Result<Certificate, _> = prev_msg.clone().try_into() else {
            return (false, false);
        };

        // Canonical dwarf wire bytes.
        let curr_bytes = certificate_to_bytes(&curr_typed);
        let prev_bytes = certificate_to_bytes(&prev_typed);

        // PATH A: dwarf parse → dwarf verify. The production zkVM path.
        let Ok(curr_zc) = certificate_from_bytes(&curr_bytes) else {
            // dwarf rejected at parse — production verdict is "reject".
            // For the oracle side, upstream try_into already succeeded,
            // so upstream would have ACCEPTED via the CertificateMessage
            // path. That is a divergence ON THE WIRE LAYER (dwarf can't
            // parse what upstream accepts) — but it's specifically the
            // "dwarf reject, upstream accept" direction = SOUNDNESS
            // REGRESSION. Flag.
            panic!(
                "{label}: dwarf parser rejected bytes that round-tripped from \
                 a valid upstream Certificate — SOUNDNESS REGRESSION on the wire path."
            );
        };
        let Ok(prev_zc) = certificate_from_bytes(&prev_bytes) else {
            panic!("{label}: dwarf parser rejected previous-cert bytes");
        };
        let dwarf_verdict = verify_standard_certificate(&curr_zc, &prev_zc);
        let dwarf_pass = dwarf_verdict.is_ok();

        // PATH B: dwarf parse → host converter → upstream verify.
        // Re-parse to get a fresh zero-copy (certificate_from_zerocopy
        // consumes by value, and dwarf_verify above already borrowed).
        let curr_zc_for_convert = certificate_from_bytes(&curr_bytes)
            .expect("re-parse for converter must succeed (same bytes)");
        let prev_zc_for_convert = certificate_from_bytes(&prev_bytes)
            .expect("re-parse for converter must succeed (same bytes)");
        let Ok(curr_via_converter) = certificate_from_zerocopy(curr_zc_for_convert) else {
            panic!(
                "{label}: host converter failed on a dwarf zero-copy view of valid \
                 upstream bytes — converter rejects what dwarf accepted at parse."
            );
        };
        let Ok(prev_via_converter) = certificate_from_zerocopy(prev_zc_for_convert) else {
            panic!("{label}: host converter failed on previous cert");
        };

        // Run upstream's full verifier on the converted Certificate.
        let upstream_check =
            mithril_dwarf_harness::full_verify::mithril_full_verify_standard(
                &curr_via_converter,
                &prev_via_converter,
            );
        let upstream_pass = matches!(upstream_check.outcome, Outcome::Pass);

        (upstream_pass, dwarf_pass)
    };

    let mut critical: Vec<String> = Vec::new();
    let mut soundness: Vec<String> = Vec::new();
    let mut both_accept = 0usize;
    let mut both_reject = 0usize;
    let mut total = 0usize;

    // POSITIVE corpus pass: every standard cert should accept on both
    // pipelines. This is the strongest claim — dwarf-leader path
    // matches upstream-canonical path on real data.
    for (curr, prev) in &standard_bases {
        let label = format!("positive: {}", short_label(curr));
        let (upstream, dwarf) = run_pair(curr, prev, &label);
        total += 1;
        classify(&label, upstream, dwarf, &mut critical, &mut soundness, &mut both_accept, &mut both_reject);
    }

    // NEGATIVE coverage: apply every applicable standard mutation to
    // each corpus cert and route through the dwarf-leader path. This
    // gives N(corpus) × N(applicable mutations) cross-impl assertions
    // through the host-converter path — independent coverage from the
    // existing audit_mutated path.
    let mutations = standard_mutations();
    for (curr, prev) in &standard_bases {
        for am in mutations
            .iter()
            .filter(|am| am.mutation.is_applicable_to(curr))
        {
            let (mutated_curr, mutated_prev) = match am.target {
                MutationTarget::Current => (apply_mutation(curr, &am.mutation), (*prev).clone()),
                MutationTarget::Previous => ((*curr).clone(), apply_mutation(prev, &am.mutation)),
            };
            let label = format!(
                "mutated {}: {}",
                match am.target {
                    MutationTarget::Current => "current",
                    MutationTarget::Previous => "previous",
                },
                applied_mutation_label(am)
            );
            let (upstream, dwarf) = run_pair(&mutated_curr, &mutated_prev, &label);
            total += 1;
            classify(&label, upstream, dwarf, &mut critical, &mut soundness, &mut both_accept, &mut both_reject);
        }
    }

    eprintln!(
        "dwarf_leader_upstream_oracle_equivalence: {total} cross-impl assertions \
         on the dwarf-leader path — both_accept={both_accept} (positive corpus + \
         mutation no-ops), both_reject={both_reject} (adversarial mutations), \
         critical={}, soundness={}",
        critical.len(),
        soundness.len()
    );

    if !critical.is_empty() || !soundness.is_empty() {
        let mut details = String::from("\ndwarf-leader equivalence failures:\n");
        for line in critical.iter().chain(soundness.iter()) {
            details.push_str("  ");
            details.push_str(line);
            details.push('\n');
        }
        panic!("{details}");
    }
}

fn short_label(msg: &mithril_common::messages::CertificateMessage) -> String {
    format!(
        "{} (epoch {}, signers {})",
        msg.hash.chars().take(16).collect::<String>(),
        msg.epoch.0,
        msg.metadata.signers.len()
    )
}

fn classify(
    label: &str,
    upstream: bool,
    dwarf: bool,
    critical: &mut Vec<String>,
    soundness: &mut Vec<String>,
    both_accept: &mut usize,
    both_reject: &mut usize,
) {
    match (upstream, dwarf) {
        (false, true) => critical.push(format!(
            "CRITICAL: {label} — upstream REJECTED, dwarf ACCEPTED"
        )),
        (true, false) => soundness.push(format!(
            "SOUNDNESS REGRESSION: {label} — upstream ACCEPTED, dwarf REJECTED"
        )),
        (true, true) => *both_accept += 1,
        (false, false) => *both_reject += 1,
    }
}

/// Pin the upstream `ProtocolMessagePartKey` discriminant layout
/// against dwarf's `protocol_message_key_to_string` table.
///
/// `compute_protocol_message_digest` streams
/// `protocol_message_key_to_string(*key as u8) || value` per part. The
/// discriminant depends on the upstream enum's declaration order; if
/// upstream inserts a variant mid-enum, every later discriminant
/// shifts and dwarf silently hashes the wrong key string. A
/// version bump would mask the drift in the bit-equivalence harness
/// (corpus certs would be produced against the new mapping and still
/// round-trip), so this test is the dedicated gate.
///
/// Pins the (variant, discriminant, snake_case_serde_name) tuple per
/// upstream variant and asserts:
///
///   * `(variant as u8) == expected_discriminant`
///   * `serde_json::to_value(variant).as_str() == expected_string`
///     (the serde rename upstream uses for JSON serialisation)
///   * `dwarf::protocol_message_key_to_string(expected_discriminant)
///      == expected_string`
///
/// Any upstream change that reorders, renames, or adds a variant trips
/// this test before the harness reports false equivalence.
#[test]
fn protocol_message_part_key_discriminants_pinned() {
    use mithril_common::entities::ProtocolMessagePartKey;
    use mithril_dwarf::certificate_verification::medium_checks::protocol_message_key_to_string;

    // Hardcoded expected layout. If any of these triples drifts,
    // either upstream changed (update with care) or dwarf's mapping
    // table drifted (bug — investigate).
    // Pinned to upstream Mithril 2617.0 declaration order. 2537.0 had only
    // 9 variants (0..=8); 2617.0 inserted CardanoBlocksTransactionsMerkleRoot,
    // CardanoBlocksTransactionsBlockNumberOffset, and NextSnarkAggregateVerificationKey,
    // shifting every prior NextAVK / NextProtocolParameters / CurrentEpoch /
    // LatestBlockNumber / CardanoStake* / CardanoDatabase position.
    let expected: &[(ProtocolMessagePartKey, u8, &str)] = &[
        (ProtocolMessagePartKey::SnapshotDigest, 0, "snapshot_digest"),
        (
            ProtocolMessagePartKey::CardanoTransactionsMerkleRoot,
            1,
            "cardano_transactions_merkle_root",
        ),
        (
            ProtocolMessagePartKey::CardanoBlocksTransactionsMerkleRoot,
            2,
            "cardano_blocks_transactions_merkle_root",
        ),
        (
            ProtocolMessagePartKey::NextAggregateVerificationKey,
            3,
            "next_aggregate_verification_key",
        ),
        (
            ProtocolMessagePartKey::NextProtocolParameters,
            4,
            "next_protocol_parameters",
        ),
        (ProtocolMessagePartKey::CurrentEpoch, 5, "current_epoch"),
        (
            ProtocolMessagePartKey::LatestBlockNumber,
            6,
            "latest_block_number",
        ),
        (
            ProtocolMessagePartKey::CardanoBlocksTransactionsBlockNumberOffset,
            7,
            "cardano_blocks_transactions_block_number_offset",
        ),
        (
            ProtocolMessagePartKey::CardanoStakeDistributionEpoch,
            8,
            "cardano_stake_distribution_epoch",
        ),
        (
            ProtocolMessagePartKey::CardanoStakeDistributionMerkleRoot,
            9,
            "cardano_stake_distribution_merkle_root",
        ),
        (
            ProtocolMessagePartKey::CardanoDatabaseMerkleRoot,
            10,
            "cardano_database_merkle_root",
        ),
        (
            ProtocolMessagePartKey::NextSnarkAggregateVerificationKey,
            11,
            "next_aggregate_verification_key_snark",
        ),
    ];

    for (variant, expected_discriminant, expected_string) in expected {
        let actual_discriminant = *variant as u8;
        assert_eq!(
            actual_discriminant, *expected_discriminant,
            "upstream ProtocolMessagePartKey::{variant:?} discriminant drifted: \
             expected {expected_discriminant}, got {actual_discriminant}. \
             Upstream likely reordered or inserted a variant — dwarf's \
             discriminant table in protocol_message_key_to_string MUST be updated \
             to match, or the cert hash will silently diverge."
        );

        let serde_string = serde_json::to_value(variant)
            .expect("ProtocolMessagePartKey serializes")
            .as_str()
            .expect("serde encodes as JSON string")
            .to_string();
        assert_eq!(
            serde_string, *expected_string,
            "upstream serde rename for {variant:?} drifted: \
             expected {expected_string:?}, got {serde_string:?}. \
             dwarf's protocol_message_key_to_string MUST be updated to match \
             the new serde name or the SHA-256 protocol-message hash will diverge."
        );

        let dwarf_string = protocol_message_key_to_string(*expected_discriminant);
        assert_eq!(
            dwarf_string, *expected_string,
            "dwarf's protocol_message_key_to_string({expected_discriminant}) = {dwarf_string:?} \
             but serde-renamed upstream string is {expected_string:?}. \
             Either dwarf's table is wrong or upstream renamed the variant."
        );
    }

    // Exhaustiveness: dwarf must return "unknown" for ALL discriminants
    // outside 0..=11. Pin the unknown-fallback so any future upstream
    // expansion trips here before silently hashing "unknown" for valid input.
    for d in 12u8..=255 {
        let s = protocol_message_key_to_string(d);
        assert_eq!(
            s, "unknown",
            "dwarf's protocol_message_key_to_string({d}) returned {s:?}, expected \"unknown\". \
             A new variant has been added to dwarf's table without expanding the \
             pinned expected[] above — update both."
        );
    }
}

/// Canonicalization-erasure diagnostic.
///
/// Some `standard_mutations()` entries can be silently erased by the
/// `CertificateMessage → Certificate → certificate_to_bytes → dwarf
/// zero-copy` round-trip the harness uses (e.g. a flipped char that
/// lands on tolerated JSON whitespace, or a timestamp bump that round-
/// trips through chrono unchanged). This test asserts each susceptible
/// mutation produces a real wire-bytes diff on at least one corpus cert;
/// otherwise the rejection it claims to drive isn't actually exercised.
///
/// Surfaces the diagnostic per (mutation, corpus cert) in the
/// eprintln output. Fails only if a canonicalization-susceptible
/// mutation produces zero diff across the ENTIRE corpus (signals
/// a real coverage gap).
#[test]
fn canonicalization_erasure_diagnostic() {
    use mithril_common::entities::Certificate;
    use mithril_dwarf::certificate_to_bytes;
    use mithril_dwarf_harness::{apply_mutation, Mutation};

    let load = load_corpus(Path::new(CORPUS_DIR));
    let standard_bases: Vec<&mithril_common::messages::CertificateMessage> = load
        .entries
        .iter()
        .filter_map(|e| match e {
            CorpusEntry::Standard { current, .. } => Some(current),
            _ => None,
        })
        .collect();
    assert!(!standard_bases.is_empty(), "no standard cert in corpus");

    // Canonicalization-susceptible mutations. Each must produce
    // post-round-trip wire bytes that differ from baseline on at
    // least one corpus cert; if none survive on any cert the mutation
    // is structurally erased and should be removed or replaced.
    let susceptible: &[(&str, Mutation)] = &[
        (
            "ScrambleSignatureField",
            Mutation::ScrambleSignatureField,
        ),
        ("ScrambleAvkEnvelope", Mutation::ScrambleAvkEnvelope),
        (
            "BumpInitiatedAtTimestamp",
            Mutation::BumpInitiatedAtTimestamp,
        ),
    ];

    let mut erased_everywhere: Vec<String> = Vec::new();

    for (name, mutation) in susceptible {
        let mut preserves = 0usize;
        let mut erases = 0usize;
        for cert_msg in &standard_bases {
            // Baseline: round-trip the unmutated cert.
            let Ok(baseline_typed): Result<Certificate, _> =
                (*cert_msg).clone().try_into()
            else {
                continue; // some corpus entry that's unparseable; skip
            };
            let baseline_bytes = certificate_to_bytes(&baseline_typed);

            // Mutated: apply mutation, round-trip, capture bytes.
            let mutated_msg = apply_mutation(cert_msg, mutation);
            let Ok(mutated_typed): Result<Certificate, _> = mutated_msg.try_into() else {
                // try_into rejected — mutation visible at the
                // upstream-side decoder. NOT canonicalization erasure
                // (rejection at decode is a strong signal). Count as
                // preserved.
                preserves += 1;
                continue;
            };
            let mutated_bytes = certificate_to_bytes(&mutated_typed);

            if mutated_bytes == baseline_bytes {
                erases += 1;
            } else {
                preserves += 1;
            }
        }
        let total = preserves + erases;
        eprintln!(
            "canonicalization_erasure_diagnostic: {name} - preserved on \
             {preserves}/{total} corpus certs, erased on {erases}/{total}."
        );
        if preserves == 0 && erases > 0 {
            erased_everywhere.push(format!(
                "{name}: structurally erased on EVERY applicable corpus cert. \
                 The mutation produces no observable change on the dwarf wire \
                 path; rejection in the mutation suite comes from a different \
                 source (cert hash recompute on a no-op input, perhaps?). \
                 Remove or replace this mutation."
            ));
        }
    }

    if !erased_everywhere.is_empty() {
        panic!(
            "Canonicalization erasure detected:\n  {}",
            erased_everywhere.join("\n  ")
        );
    }
}

/// Corpus diversity report with hard floors. Prints the variant,
/// signer-count, epoch, and network distributions, and fails the test
/// if any axis falls below the floors the fetcher script targets.
#[test]
fn corpus_diversity_report() {
    use mithril_common::entities::SignedEntityType;
    use std::collections::BTreeMap;

    let load = load_corpus(Path::new(CORPUS_DIR));

    let standard: Vec<&mithril_common::messages::CertificateMessage> = load
        .entries
        .iter()
        .filter_map(|e| match e {
            CorpusEntry::Standard { current, .. } => Some(current),
            _ => None,
        })
        .collect();
    assert!(!standard.is_empty(), "corpus has no standard certs");

    // SignedEntityType variant distribution.
    let mut entity_type_counts: BTreeMap<String, usize> = BTreeMap::new();
    for cert in &standard {
        let label = match cert.signed_entity_type {
            SignedEntityType::MithrilStakeDistribution(_) => "MithrilStakeDistribution",
            SignedEntityType::CardanoStakeDistribution(_) => "CardanoStakeDistribution",
            SignedEntityType::CardanoImmutableFilesFull(_) => "CardanoImmutableFilesFull",
            SignedEntityType::CardanoTransactions(_, _) => "CardanoTransactions",
            SignedEntityType::CardanoDatabase(_) => "CardanoDatabase",
            SignedEntityType::CardanoBlocksTransactions(_, _, _) => "CardanoBlocksTransactions",
        };
        *entity_type_counts.entry(label.to_string()).or_insert(0) += 1;
    }

    // Signer-count distribution.
    let signer_counts: Vec<usize> = standard.iter().map(|c| c.metadata.signers.len()).collect();
    let min_signers = *signer_counts.iter().min().unwrap_or(&0);
    let max_signers = *signer_counts.iter().max().unwrap_or(&0);
    let mean_signers = if signer_counts.is_empty() {
        0
    } else {
        signer_counts.iter().sum::<usize>() / signer_counts.len()
    };

    // Epoch range.
    let epochs: Vec<u64> = standard.iter().map(|c| c.epoch.0).collect();
    let min_epoch = *epochs.iter().min().unwrap_or(&0);
    let max_epoch = *epochs.iter().max().unwrap_or(&0);
    let epoch_span = max_epoch.saturating_sub(min_epoch);

    // Network: detected via metadata.network (each cert carries this).
    let mut networks: BTreeMap<String, usize> = BTreeMap::new();
    for cert in &standard {
        *networks.entry(cert.metadata.network.clone()).or_insert(0) += 1;
    }

    // Same-epoch vs cross-epoch pairs (already counted by the loader,
    // but re-report for visibility).
    eprintln!("=== Corpus diversity report ===");
    eprintln!(
        "Entries: {} total | standard {} | genesis {}",
        load.entries.len(),
        standard.len(),
        load.genesis_count
    );
    eprintln!(
        "Pair shapes: same_epoch {} | cross_epoch {}",
        load.standard_same_epoch, load.standard_diff_epoch
    );
    eprintln!("SignedEntityType distribution:");
    for (label, count) in &entity_type_counts {
        eprintln!("  {:30} {:4}", label, count);
    }
    eprintln!(
        "Signer count: min={min_signers} | mean={mean_signers} | max={max_signers}"
    );
    eprintln!(
        "Epoch range: min={min_epoch} | max={max_epoch} | span={epoch_span}"
    );
    eprintln!("Network distribution:");
    for (network, count) in &networks {
        eprintln!("  {:30} {:4}", network, count);
    }
    eprintln!("=== End diversity report ===");

    // Minimum-coverage assertions. ALL hard now — a silent corpus
    // shrink that takes us below these floors must fail the harness
    // run, not just print a WARN. The fetcher script
    // (fetch_diverse_corpus.sh) is the source of truth for what we
    // expect to be present; these asserts pin the shape it produces.

    assert!(
        epoch_span >= 1,
        "Corpus diversity: epoch span is {epoch_span} — every cert is from \
         the same epoch. Cross-epoch path verification is not exercised."
    );

    assert!(
        max_signers >= 50,
        "Corpus diversity: max signers per cert is {max_signers} — too small \
         to exercise the production multi-signer BLS path. Need at least one \
         cert with 50+ signers."
    );

    // All 5 SignedEntityType variants must be represented. The fetcher
    // walks one chain per variant; missing one means the fetch lost a
    // chain (mainnet aggregator drift, fetcher bug) and feed_hash bytes
    // for that variant are no longer cross-verified.
    let expected_variants = [
        "MithrilStakeDistribution",
        "CardanoStakeDistribution",
        "CardanoImmutableFilesFull",
        "CardanoTransactions",
        "CardanoDatabase",
    ];
    let missing_variants: Vec<&str> = expected_variants
        .iter()
        .filter(|v| !entity_type_counts.contains_key(**v))
        .copied()
        .collect();
    assert!(
        missing_variants.is_empty(),
        "Corpus diversity: SignedEntityType variants {missing_variants:?} \
         have ZERO samples. feed_entity_type_hash bytes for those variants \
         are unverified. Re-run fetch_diverse_corpus.sh to restore coverage."
    );

    // Per-variant floor. 2 samples per variant is the honest floor
    // for the corpus we currently ship — most variants land at 4
    // via the fetcher's head + siblings pattern, but
    // CardanoTransactions is harder to amplify (the /certificates
    // feed is CT-dense so head walks dominate one variant; the
    // /artifact/cardano-transactions endpoint amends this). 2 is
    // enough to catch a fully-missing variant; raise to 4 once
    // fetch_diverse_corpus.sh has been re-run with the CT siblings
    // step (TODO in the fetcher).
    let per_variant_floor = 2;
    let under_floor: Vec<(String, usize)> = entity_type_counts
        .iter()
        .filter(|&(_, &c)| c < per_variant_floor)
        .map(|(k, &v)| (k.clone(), v))
        .collect();
    assert!(
        under_floor.is_empty(),
        "Corpus diversity: variants under per-variant floor of \
         {per_variant_floor}: {under_floor:?}. The variant axis is \
         not robustly exercised — re-run fetch_diverse_corpus.sh."
    );

    // Multi-network coverage. Gap 3 plumbing (genesis_vk_for_cert)
    // routes per cert.metadata.network; if the corpus collapses to
    // a single network the per-network VK plumbing is untested.
    assert!(
        networks.len() >= 2,
        "Corpus diversity: only {} network(s) represented {:?}. \
         genesis_vk_for_cert per-network routing is not exercised. \
         Re-run fetch_diverse_corpus.sh (it pulls a preprod chain).",
        networks.len(),
        networks.keys().collect::<Vec<_>>()
    );

    // Same-epoch pairs exercise basic_checks::verify_avk_same_epoch
    // (and the protocol-params same-epoch check). Zero same-epoch
    // pairs leaves a positive-corpus blind spot.
    assert!(
        load.standard_same_epoch >= 1,
        "Corpus diversity: zero same-epoch pairs. \
         basic_checks::verify_avk_same_epoch / verify_protocol_params_same_epoch \
         are not exercised in the positive corpus."
    );
}


/// Per-variant audit (Part 2 Step 2a — proper) — pin the
/// `SignedEntityType` discriminant layout and field-byte sequence
/// fed to SHA-256 by dwarf's `feed_entity_type_hash` against
/// upstream's `feed_hash`.
///
/// AUDIT FINDING (Part 2 Step 2a) that motivates this test:
/// upstream Mithril maintains TWO different mappings for the
/// `SignedEntityType` variants:
///
///   1. **Declaration order** (used by Rust's `*key as u8` cast and
///      by dwarf's wire format): MSD=0, CSD=1, CIF=2, CD=3, CT=4.
///   2. **`SignedEntityType::index()` method** (used for upstream's
///      database storage): MSD=0, CSD=1, CIF=2, CT=3, CD=4. Note
///      CT and CD are SWAPPED relative to declaration order.
///
/// dwarf's wire format (`byte_serializer.rs:241-267`) uses
/// declaration-order values via `*key as u8` semantics —
/// MSD=0..CT=4. dwarf's hash side
/// (`feed_entity_type_hash`, medium_checks.rs:763) does NOT feed
/// the discriminant byte into SHA-256 at all: only the inner field
/// values are hashed. Upstream's `feed_hash`
/// (signed_entity_type.rs:137) ALSO does not feed the discriminant
/// — only field values. So the divergence in `index()` is
/// IRRELEVANT for hash equivalence, but the *wire format*
/// (parser + serializer + harness round-trip) depends on the
/// declaration order being stable.
///
/// If upstream reorders the `SignedEntityType` enum on a future
/// version bump, every dwarf cert serialisation/deserialisation
/// would silently use the wrong discriminant, with no harness
/// failure on a regenerated corpus (because both impls would be
/// wrong consistently). This pin test catches that drift before
/// it can land.
///
/// What's pinned:
///   1. For each upstream variant, `(variant as u8)` equals the
///      expected declaration-order discriminant.
///   2. For each variant, dwarf's `byte_serializer` `write_u8` value
///      matches.
///   3. For two-field variants (CIF/CD/CT), the field order in
///      `feed_hash` matches upstream — both feed (epoch, second_field)
///      where second_field is `immutable_file_number` for CIF/CD and
///      `block_number` for CT.
///   4. Zero discriminant byte in either hash (both impls feed
///      field values only).
#[test]
fn signed_entity_type_discriminant_pinned() {
    use mithril_common::entities::{
        BlockNumber, CardanoDbBeacon, Epoch, ImmutableFileNumber, SignedEntityType,
    };

    // Pinned (variant, expected_discriminant) per upstream
    // declaration order. Synthetic field values chosen to be
    // unmistakable in the hashed bytes.
    // 2617.0 adds CardanoBlocksTransactions at declaration position 5
    // (a three-field variant). dwarf's wire format does not yet support
    // it (the host serializer panics), so the harness omits it from the
    // round-trip cases below; the discriminant value is still pinned via
    // the explicit assertion further down.
    let cases: &[(SignedEntityType, u8, &str)] = &[
        (
            SignedEntityType::MithrilStakeDistribution(Epoch(100)),
            0,
            "MithrilStakeDistribution",
        ),
        (
            SignedEntityType::CardanoStakeDistribution(Epoch(101)),
            1,
            "CardanoStakeDistribution",
        ),
        (
            SignedEntityType::CardanoImmutableFilesFull(CardanoDbBeacon {
                epoch: Epoch(102),
                immutable_file_number: 8000 as ImmutableFileNumber,
            }),
            2,
            "CardanoImmutableFilesFull",
        ),
        (
            SignedEntityType::CardanoDatabase(CardanoDbBeacon {
                epoch: Epoch(103),
                immutable_file_number: 8100 as ImmutableFileNumber,
            }),
            3,
            "CardanoDatabase",
        ),
        (
            SignedEntityType::CardanoTransactions(Epoch(104), BlockNumber(900_000)),
            4,
            "CardanoTransactions",
        ),
    ];

    for (variant, expected_disc, label) in cases {
        // Pin 1: as u8 cast matches declaration order.
        let actual_disc = unsafe {
            // We don't have a stable way to ask Rust for "enum tag
            // as u8" without unsafe transmute (`as` on enum requires
            // C-repr or fieldless). Use `index()` to confirm dwarf's
            // assumption, then separately verify the wire byte.
            *(variant as *const SignedEntityType as *const u8)
        };
        assert_eq!(
            actual_disc, *expected_disc,
            "{label}: variant discriminant (Rust enum tag at offset 0) drifted: \
             expected {expected_disc}, got {actual_disc}. Upstream may have \
             reordered the SignedEntityType enum. dwarf's wire format would \
             silently encode the wrong discriminant byte."
        );

        // Pin 2: dwarf's byte_serializer writes the same discriminant.
        // Build a minimal certificate signature section and verify the
        // serialised discriminant byte matches.
        use mithril_dwarf::parser::byte_deserializer::{
            certificate_from_bytes, SignatureBasicZeroCopy,
        };
        // Construct a synthetic CertificateMessage with this entity type
        // and run it through certificate_to_bytes. We need a full cert,
        // but we can reuse a corpus cert and just mutate the
        // signed_entity_type field.
        let load = load_corpus(Path::new(CORPUS_DIR));
        let base_msg = load
            .entries
            .iter()
            .find_map(|e| match e {
                CorpusEntry::Standard { current, .. } => Some(current),
                _ => None,
            })
            .expect("corpus has a standard cert");

        let mut mutated = base_msg.clone();
        mutated.signed_entity_type = variant.clone();
        let typed: mithril_common::entities::Certificate = mutated
            .try_into()
            .expect("synthetic cert with variant try_into");
        let wire_bytes = mithril_dwarf::certificate_to_bytes(&typed);
        // Parse with dwarf and extract the discriminant.
        let parsed = certificate_from_bytes(&wire_bytes)
            .expect("dwarf parses the synthetic cert");
        let dwarf_disc = match parsed.signature {
            SignatureBasicZeroCopy::Multi {
                entity_type_discriminant,
                ..
            } => entity_type_discriminant,
            SignatureBasicZeroCopy::Genesis { .. } => {
                panic!("synthetic cert came out genesis — unexpected")
            }
        };
        assert_eq!(
            dwarf_disc, *expected_disc,
            "{label}: dwarf serializer wrote discriminant {dwarf_disc}, expected {expected_disc}. \
             byte_serializer.rs:241-267 has drifted from upstream's declaration order."
        );
    }
}

/// Per-variant audit (Part 2 Step 2a) — pin that dwarf's
/// `feed_entity_type_hash` produces the EXACT same SHA-256 input
/// bytes as upstream's `SignedEntityType::feed_hash` for every
/// variant + field shape combination.
///
/// Both impls are claimed to feed ONLY the field values (no
/// discriminant) into the hasher. This test runs that claim
/// against each variant and asserts byte equality of the hasher
/// inputs.
#[test]
fn signed_entity_type_feed_hash_bytes_pinned() {
    use mithril_common::entities::{
        BlockNumber, CardanoDbBeacon, Epoch, ImmutableFileNumber, SignedEntityType,
    };
    use sha2::{Digest, Sha256};

    // Closure: feed an upstream variant through upstream's
    // (private) feed_hash by emulating it inline — feed_hash is
    // `pub(crate)` so we re-implement it here using upstream's
    // documented per-variant byte sequence (signed_entity_type.rs:137).
    let upstream_feed = |variant: &SignedEntityType, hasher: &mut Sha256| {
        match variant {
            SignedEntityType::MithrilStakeDistribution(epoch)
            | SignedEntityType::CardanoStakeDistribution(epoch) => {
                hasher.update(&epoch.to_be_bytes());
            }
            SignedEntityType::CardanoImmutableFilesFull(b)
            | SignedEntityType::CardanoDatabase(b) => {
                hasher.update(&b.epoch.to_be_bytes());
                hasher.update(&b.immutable_file_number.to_be_bytes());
            }
            SignedEntityType::CardanoTransactions(epoch, block_number) => {
                hasher.update(&epoch.to_be_bytes());
                hasher.update(&block_number.to_be_bytes());
            }
            SignedEntityType::CardanoBlocksTransactions(_, _, _) => {
                panic!(
                    "test does not yet exercise CardanoBlocksTransactions (added in Mithril 2617.0)"
                );
            }
        }
    };

    // Cases — same as discriminant pin.
    let cases: &[(SignedEntityType, u8, [u64; 2], &str)] = &[
        (
            SignedEntityType::MithrilStakeDistribution(Epoch(100)),
            0,
            [100, 0],
            "MithrilStakeDistribution",
        ),
        (
            SignedEntityType::CardanoStakeDistribution(Epoch(101)),
            1,
            [101, 0],
            "CardanoStakeDistribution",
        ),
        (
            SignedEntityType::CardanoImmutableFilesFull(CardanoDbBeacon {
                epoch: Epoch(102),
                immutable_file_number: 8000 as ImmutableFileNumber,
            }),
            2,
            [102, 8000],
            "CardanoImmutableFilesFull",
        ),
        (
            SignedEntityType::CardanoDatabase(CardanoDbBeacon {
                epoch: Epoch(103),
                immutable_file_number: 8100 as ImmutableFileNumber,
            }),
            3,
            [103, 8100],
            "CardanoDatabase",
        ),
        (
            SignedEntityType::CardanoTransactions(Epoch(104), BlockNumber(900_000)),
            4,
            [104, 900_000],
            "CardanoTransactions",
        ),
    ];

    for (variant, discriminant, data, label) in cases {
        // Upstream side: feed_hash on the variant.
        let mut upstream_hasher = Sha256::new();
        upstream_feed(variant, &mut upstream_hasher);
        let upstream_digest = upstream_hasher.finalize();

        // Dwarf side: feed_entity_type_hash on the discriminant + data.
        use mithril_dwarf::certificate_verification::medium_checks::feed_entity_type_hash;
        use mithril_dwarf::certificate_verification::Sha256Sink;
        let mut dwarf_sink = Sha256Sink::new();
        feed_entity_type_hash(&mut dwarf_sink, *discriminant, data);
        let dwarf_digest = dwarf_sink.finalize();

        assert_eq!(
            <[u8; 32]>::from(upstream_digest), dwarf_digest,
            "{label}: SHA-256 digest of feed_hash bytes diverged. \
             upstream emits field values only (no discriminant); dwarf \
             must do the same. If this assertion fires, either dwarf \
             started emitting a discriminant byte, the field order \
             changed, or to_be_bytes encoding drifted."
        );
    }
}


/// Gap 1 closer (Part 2 Step 3) — cross-impl equivalence on N ≥ 3
/// cert chains.
///
/// Every other test in the harness verifies exactly one cert PAIR
/// (current + previous). Bugs in dwarf's
/// `verify_certificate_chain` orchestrator iteration —
/// off-by-one in the `for i in 0..certificates.len()` loop, wrong
/// genesis-cert handling at the tail, repeated-cert handling that
/// differs from upstream's `fetch_previous_certificate` walk —
/// would not surface.
///
/// This test:
///   1. Walks the corpus to find the longest available linear
///      chain (newest-to-oldest via `previous_hash` matching).
///      Requires at least 3 certs to exercise the orchestrator's
///      multi-step iteration.
///   2. Verifies the chain via dwarf's
///      `verify_certificate_chain(&[...])`.
///   3. Verifies the same chain via upstream's
///      `MithrilCertificateVerifier::verify_certificate_chain`
///      (driven by a multi-cert mock retriever that mirrors the
///      production aggregator's `get_certificate_details`
///      interface).
///   4. Asserts both produce equivalent verdicts on:
///      a. The clean positive chain (both must accept).
///      b. A chain with a MIDDLE cert's `previous_hash` flipped —
///         both must reject. The break lands at index
///         `len/2`, so the rejection fires during the middle of
///         dwarf's iteration loop (and the middle of upstream's
///         recursive retriever walk), catching bugs that only
///         surface when the bad link is neither first nor last.
#[test]
fn cross_impl_chain_verification() {
    use mithril_common::crypto_helper::ProtocolGenesisVerificationKey;
    use mithril_common::certificate_chain::{
        CertificateRetriever, CertificateRetrieverError, CertificateVerifier,
        MithrilCertificateVerifier,
    };
    use mithril_common::entities::Certificate;
    use mithril_dwarf::parser::byte_deserializer::certificate_from_bytes;
    use mithril_dwarf::{certificate_to_bytes, verify_certificate_chain};
    use std::collections::HashMap;
    use std::sync::Arc;

    let load = load_corpus(Path::new(CORPUS_DIR));
    assert!(load.load_errors.is_empty(), "corpus load errors");

    let is_genesis = |c: &mithril_common::messages::CertificateMessage| {
        c.previous_hash.is_empty()
            || c.previous_hash == "0000000000000000000000000000000000000000000000000000000000000000"
    };

    // Build a hash → CertificateMessage map of every cert in the
    // corpus (genesis + standards).
    let mut all_msgs: HashMap<String, mithril_common::messages::CertificateMessage> =
        HashMap::new();
    for entry in &load.entries {
        match entry {
            CorpusEntry::Standard { current, previous } => {
                all_msgs.insert(current.hash.clone(), current.clone());
                all_msgs.insert(previous.hash.clone(), previous.clone());
            }
            CorpusEntry::Genesis { cert } => {
                all_msgs.insert(cert.hash.clone(), cert.clone());
            }
        }
    }

    // Find the longest linear chain (newest-to-oldest). Start from
    // each cert, walk previous_hash until we hit a cert not in the
    // corpus or the genesis null-hash sentinel.
    let mut longest_chain: Vec<mithril_common::messages::CertificateMessage> = Vec::new();
    for start_msg in all_msgs.values() {
        let mut chain = vec![start_msg.clone()];
        let mut cursor = start_msg.previous_hash.clone();
        // The genesis cert's previous_hash is empty or all-zero; stop there.
        while !cursor.is_empty()
            && cursor != "0000000000000000000000000000000000000000000000000000000000000000"
        {
            if let Some(prev) = all_msgs.get(&cursor) {
                chain.push(prev.clone());
                cursor = prev.previous_hash.clone();
            } else {
                break;
            }
        }
        if chain.len() > longest_chain.len() {
            longest_chain = chain;
        }
    }

    assert!(
        longest_chain.len() >= 3,
        "corpus must yield a chain of at least 3 linked certs to exercise \
         the multi-step iteration in `verify_certificate_chain`; got {}",
        longest_chain.len()
    );

    eprintln!(
        "cross_impl_chain_verification: longest linear chain length = {}",
        longest_chain.len()
    );

    // dwarf's `verify_certificate_chain` treats each cert with
    // prev=None as needing genesis verification — the chain MUST
    // terminate at a genesis cert. Verify that prerequisite.
    assert!(
        is_genesis(longest_chain.last().unwrap()),
        "longest linear chain ({} certs) does not terminate at a genesis \
         cert — `verify_certificate_chain` requires that. Re-fetch a chain \
         that reaches genesis (use fetch_diverse_corpus.sh).",
        longest_chain.len()
    );

    // Use the full chain — exercises every iteration of dwarf's
    // loop + upstream's recursion. Length is corpus-dependent
    // (the diverse-fetcher script keeps it in the low hundreds).
    let chain_msgs: Vec<&mithril_common::messages::CertificateMessage> =
        longest_chain.iter().collect();
    eprintln!(
        "cross_impl_chain_verification: verifying chain of {} certs ending at genesis",
        chain_msgs.len()
    );

    // ----- DWARF side: convert each cert to wire bytes, parse into
    //       CertificateZeroCopy, run chain verifier.

    let chain_typed: Vec<Certificate> = chain_msgs
        .iter()
        .map(|m| (**m).clone().try_into().expect("try_into for chain cert"))
        .collect();
    let chain_bytes: Vec<Vec<u8>> = chain_typed
        .iter()
        .map(|c| certificate_to_bytes(c))
        .collect();
    let chain_zc: Vec<_> = chain_bytes
        .iter()
        .map(|b| certificate_from_bytes(b).expect("dwarf parse chain cert"))
        .collect();

    // Pick the genesis VK for whatever network the chain actually lives
    // on (the longest linear chain may be mainnet OR preprod depending
    // on which network's fetch reached genesis first).
    let chain_genesis_vk_hex = genesis_vk_for_cert(longest_chain.last().unwrap())
        .expect("network supported by genesis_vk_for_cert");
    let genesis_vk_bytes: [u8; 32] = {
        use mithril_common::crypto_helper::ed25519::Ed25519VerificationKey;
        Ed25519VerificationKey::from_json_hex(chain_genesis_vk_hex)
            .expect("chain genesis VK parses")
            .as_ref()
            .try_into()
            .expect("Ed25519 VK is 32 bytes")
    };

    let dwarf_positive = verify_certificate_chain(&chain_zc, Some(&genesis_vk_bytes));
    assert!(
        dwarf_positive.is_ok(),
        "dwarf chain verify should ACCEPT a valid 3-cert positive chain. \
         Got: {dwarf_positive:?}"
    );

    // ----- UPSTREAM side: a hash → Certificate retriever covering the chain.

    struct MultiRetriever {
        by_hash: HashMap<String, Certificate>,
    }
    #[async_trait::async_trait]
    impl CertificateRetriever for MultiRetriever {
        async fn get_certificate_details(
            &self,
            hash: &str,
        ) -> Result<Certificate, CertificateRetrieverError> {
            self.by_hash.get(hash).cloned().ok_or_else(|| {
                CertificateRetrieverError(anyhow::anyhow!(
                    "MultiRetriever: hash {hash} not in chain"
                ))
            })
        }
    }

    let retriever = MultiRetriever {
        by_hash: chain_typed
            .iter()
            .map(|c| (c.hash.clone(), c.clone()))
            .collect(),
    };
    let verifier = MithrilCertificateVerifier::new(
        slog::Logger::root(slog::Discard, slog::o!()),
        Arc::new(retriever),
    );
    let genesis_vk_strict = ProtocolGenesisVerificationKey::from_json_hex(chain_genesis_vk_hex)
        .expect("chain genesis VK parses (strict)");

    let upstream_positive = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime")
        .block_on(
            verifier.verify_certificate_chain(chain_typed[0].clone(), &genesis_vk_strict),
        );
    assert!(
        upstream_positive.is_ok(),
        "upstream chain verify should ACCEPT the same chain. Got: {upstream_positive:?}"
    );

    // ----- NEGATIVE: break a MIDDLE link. Both impls must REJECT.

    // Flip a hex char of cert[mid].previous_hash. Now the link
    // cert[mid] -> cert[mid+1] is broken (cert[mid].previous_hash
    // no longer matches cert[mid+1].hash). The break lands inside
    // both walkers' middle iteration: dwarf rejects when the loop
    // reaches index `mid`; upstream rejects when its recursive
    // retriever lookup at depth `mid` queries a hash that isn't
    // in the chain. This is what the test's scope claim promises —
    // exercising the orchestrator's mid-walk path, not just its
    // first or last step.
    let mut tampered_msgs: Vec<mithril_common::messages::CertificateMessage> =
        chain_msgs.iter().map(|m| (**m).clone()).collect();
    let mid = tampered_msgs.len() / 2;
    assert!(
        mid > 0 && mid < tampered_msgs.len() - 1,
        "mid index {} must be neither head nor genesis for this test \
         to exercise the orchestrator's middle iteration (chain len {})",
        mid,
        tampered_msgs.len()
    );
    let mut bytes = tampered_msgs[mid].previous_hash.clone().into_bytes();
    bytes[0] = if bytes[0] == b'0' { b'1' } else { b'0' };
    tampered_msgs[mid].previous_hash = String::from_utf8(bytes).unwrap();

    let tampered_typed: Vec<Certificate> = tampered_msgs
        .iter()
        .map(|m| {
            m.clone()
                .try_into()
                .expect("try_into for tampered chain cert")
        })
        .collect();
    let tampered_bytes: Vec<Vec<u8>> = tampered_typed
        .iter()
        .map(|c| certificate_to_bytes(c))
        .collect();
    let tampered_zc: Vec<_> = tampered_bytes
        .iter()
        .map(|b| certificate_from_bytes(b).expect("dwarf parse tampered chain"))
        .collect();

    let dwarf_negative = verify_certificate_chain(&tampered_zc, Some(&genesis_vk_bytes));
    assert!(
        dwarf_negative.is_err(),
        "dwarf chain verify should REJECT a chain with the middle cert's \
         previous_hash flipped (mid index {mid}). Got: {dwarf_negative:?}"
    );

    let retriever_neg = MultiRetriever {
        by_hash: tampered_typed
            .iter()
            .map(|c| (c.hash.clone(), c.clone()))
            .collect(),
    };
    let verifier_neg = MithrilCertificateVerifier::new(
        slog::Logger::root(slog::Discard, slog::o!()),
        Arc::new(retriever_neg),
    );
    let upstream_negative = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime")
        .block_on(
            verifier_neg
                .verify_certificate_chain(tampered_typed[0].clone(), &genesis_vk_strict),
        );
    assert!(
        upstream_negative.is_err(),
        "upstream chain verify should REJECT the same tampered chain. \
         Got: {upstream_negative:?}"
    );

    eprintln!(
        "cross_impl_chain_verification: positive accept = (dwarf:Ok, upstream:Ok); \
         negative reject = (dwarf:{}, upstream:{})",
        if dwarf_negative.is_err() { "Err" } else { "Ok" },
        if upstream_negative.is_err() { "Err" } else { "Ok" }
    );
}
