//! Per-cert audit driver: run every check pair, then the full-verify pair,
//! and return a fully-populated [`CertAudit`].

use mithril_common::crypto_helper::ProtocolGenesisVerificationKey;
use mithril_common::crypto_helper::ed25519::Ed25519VerificationKey;
use mithril_common::entities::Certificate;
use mithril_common::messages::CertificateMessage;
use mithril_dwarf::{certificate_from_bytes, certificate_to_bytes};

use std::panic::{AssertUnwindSafe, catch_unwind};

use crate::checks_genesis as g;
use crate::checks_standard as s;
use crate::corpus::CorpusEntry;
use crate::full_verify;
use crate::mutation::{AppliedMutation, MutationTarget};
use crate::types::{CertAudit, CertKind, CheckComparison, CheckResult, ErrorCategory};

/// Run a verifier check and convert any panic into a `Panicked`
/// CheckResult. Neither dwarf nor upstream Mithril is documented as
/// panic-free on adversarial input (the underlying `mithril-stm` /
/// `crypto-ratio` machinery can overflow on pathological lottery
/// arguments, for instance). The harness's contract is that any
/// divergence — including panics — is surfaced in the report rather than
/// crashing the test; if both impls panic on the same input, that is a
/// "both reject" outcome which satisfies the security contract.
fn catch_panics<F: FnOnce() -> CheckResult>(f: F) -> CheckResult {
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(r) => r,
        Err(_) => CheckResult::fail(ErrorCategory::Panicked, Vec::new()),
    }
}

pub fn audit_corpus_entry(entry: &CorpusEntry, genesis_vk_hex: &str) -> CertAudit {
    match entry {
        CorpusEntry::Standard { current, previous } => {
            audit_standard(current, previous, audit_label_standard(current, previous))
        }
        CorpusEntry::Genesis { cert } => {
            audit_genesis(cert, genesis_vk_hex, audit_label_genesis(cert))
        }
    }
}

/// Audit a standard cert pair where the caller has already produced
/// the mutated `current` / `previous` `CertificateMessage`s
/// programmatically (i.e. not via the [`AppliedMutation`] enum). Used
/// by the differential byte-fuzzer in `tests/equivalence.rs` to feed
/// arbitrary mutations through the same cross-impl audit machinery the
/// hand-picked mutation suite uses. Both impls see the same source
/// data — the cross-impl verdict comparison is exactly the gate the
/// "PROVE not assume" principle requires.
///
/// `label` is the test-side display string for the mutation; the audit
/// driver doesn't interpret it.
pub fn audit_standard_with_mutated_msgs(
    mutated_current: &CertificateMessage,
    mutated_previous: &CertificateMessage,
    label: String,
) -> CertAudit {
    audit_standard(mutated_current, mutated_previous, label)
}

/// Lightweight variant of [`audit_standard_with_mutated_msgs`]: runs
/// ONLY the top-level `verify_standard_certificate` pair (one
/// `MithrilCertificateVerifier::verify_standard_certificate` call,
/// one `mithril_dwarf::verify_standard_certificate` call), skipping
/// the 11 per-check cross-impl pairs.
///
/// Cost: ~12× cheaper than the full audit. Used for scaled mutation
/// suites and the differential byte-fuzzer where the per-check
/// granularity isn't needed (the security contract is on the
/// top-level verdict pair). The hand-picked single-cert
/// `mutations_are_rejected_equivalently` pass and
/// `corpus_positive_audit_bitwise_match` continue to use the full
/// audit, which keeps per-check diagnostic detail in the bitwise
/// equivalence gates.
///
/// The returned `CertAudit.per_check` is empty; `full_verify` is the
/// only populated comparison.
pub fn audit_standard_top_level_only(
    mutated_current: &CertificateMessage,
    mutated_previous: &CertificateMessage,
    label: String,
) -> CertAudit {
    let mithril_curr_opt: Option<Certificate> = mutated_current.clone().try_into().ok();
    let mithril_prev_opt: Option<Certificate> = mutated_previous.clone().try_into().ok();

    let dwarf_curr_bytes: Option<Vec<u8>> =
        mithril_curr_opt.as_ref().map(|c| certificate_to_bytes(c));
    let dwarf_prev_bytes: Option<Vec<u8>> =
        mithril_prev_opt.as_ref().map(|c| certificate_to_bytes(c));

    let dwarf_curr_zc = dwarf_curr_bytes
        .as_deref()
        .and_then(|b| certificate_from_bytes(b).ok());
    let dwarf_prev_zc = dwarf_prev_bytes
        .as_deref()
        .and_then(|b| certificate_from_bytes(b).ok());

    let mithril = match (&mithril_curr_opt, &mithril_prev_opt) {
        (Some(c), Some(p)) => catch_panics(|| full_verify::mithril_full_verify_standard(c, p)),
        _ => CheckResult::fail(ErrorCategory::StructuralError, Vec::new()),
    };
    let dwarf = match (&dwarf_curr_zc, &dwarf_prev_zc) {
        (Some(c), Some(p)) => catch_panics(|| full_verify::dwarf_full_verify_standard(c, p)),
        _ => CheckResult::fail(ErrorCategory::StructuralError, Vec::new()),
    };

    CertAudit {
        cert_label: label,
        kind: CertKind::Standard,
        per_check: Vec::new(),
        full_verify: CheckComparison::new(
            "verify_standard_certificate (top-level)",
            "MithrilCertificateVerifier::verify_standard_certificate  vs  mithril_dwarf::verify_standard_certificate",
            mithril,
            dwarf,
        ),
        mutation_intentionally_diverges: false,
    }
}

/// Lightweight variant of [`audit_mutated`]: runs only the top-level
/// `verify_standard_certificate` pair (no per-check pairs). For
/// genesis bases the full audit is used since genesis only has 4
/// checks total; the cost-saving target is the BLS-heavy standard
/// path. See [`audit_standard_top_level_only`] for the cost rationale.
pub fn audit_mutated_top_level_only(
    base: &CorpusEntry,
    applied: &AppliedMutation,
    genesis_vk_hex: &str,
) -> CertAudit {
    let mutation_text = crate::mutation::applied_mutation_label(applied);
    let intentional = applied.mutation.intentionally_diverges_from_upstream();
    let mut audit = match base {
        CorpusEntry::Standard { current, previous } => {
            let (current_m, previous_m) = match applied.target {
                MutationTarget::Current => (
                    crate::mutation::apply_mutation(current, &applied.mutation),
                    previous.clone(),
                ),
                MutationTarget::Previous => (
                    current.clone(),
                    crate::mutation::apply_mutation(previous, &applied.mutation),
                ),
            };
            let label = format!(
                "{}  [mutation: {}]",
                audit_label_standard(current, previous),
                mutation_text
            );
            audit_standard_top_level_only(&current_m, &previous_m, label)
        }
        CorpusEntry::Genesis { cert } => {
            // Genesis is cheap (4 checks total) — fall back to the
            // full audit; no perf reason to add a separate lightweight
            // genesis variant.
            let mutated = crate::mutation::apply_mutation(cert, &applied.mutation);
            let label = format!(
                "{}  [mutation: {}]",
                audit_label_genesis(cert),
                mutation_text
            );
            audit_genesis(&mutated, genesis_vk_hex, label)
        }
    };
    audit.mutation_intentionally_diverges = intentional;
    audit
}

pub fn audit_mutated(
    base: &CorpusEntry,
    applied: &AppliedMutation,
    genesis_vk_hex: &str,
) -> CertAudit {
    let mutation_text = crate::mutation::applied_mutation_label(applied);
    let intentional = applied
        .mutation
        .intentionally_diverges_from_upstream();
    let mut audit = match base {
        CorpusEntry::Standard { current, previous } => {
            let (current_m, previous_m) = match applied.target {
                MutationTarget::Current => (
                    crate::mutation::apply_mutation(current, &applied.mutation),
                    previous.clone(),
                ),
                MutationTarget::Previous => (
                    current.clone(),
                    crate::mutation::apply_mutation(previous, &applied.mutation),
                ),
            };
            let label = format!(
                "{}  [mutation: {}]",
                audit_label_standard(current, previous),
                mutation_text
            );
            audit_standard(&current_m, &previous_m, label)
        }
        CorpusEntry::Genesis { cert } => {
            // Genesis has no previous cert; previous-target mutations are
            // applied to the genesis cert itself (the chain root) — same as
            // Current. Document this in case a future caller relies on the
            // distinction.
            let mutated = crate::mutation::apply_mutation(cert, &applied.mutation);
            let label = format!(
                "{}  [mutation: {}]",
                audit_label_genesis(cert),
                mutation_text
            );
            audit_genesis(&mutated, genesis_vk_hex, label)
        }
    };
    audit.mutation_intentionally_diverges = intentional;
    audit
}

fn audit_label_standard(current: &CertificateMessage, _previous: &CertificateMessage) -> String {
    format!(
        "standard cert {} (epoch {}, signers {})",
        short_hash(&current.hash),
        current.epoch.0,
        current.metadata.signers.len()
    )
}

fn audit_label_genesis(cert: &CertificateMessage) -> String {
    format!(
        "genesis cert {} (epoch {})",
        short_hash(&cert.hash),
        cert.epoch.0
    )
}

fn short_hash(hash: &str) -> String {
    hash.chars().take(16).collect()
}

fn audit_standard(
    current: &CertificateMessage,
    previous: &CertificateMessage,
    label: String,
) -> CertAudit {
    // Convert to both impls' types. Parse failures count as per-check
    // structural divergence — the cert can't be fed into dwarf if the
    // mithril -> dwarf wire conversion can't even produce bytes.
    let mithril_curr_opt: Option<Certificate> = current.clone().try_into().ok();
    let mithril_prev_opt: Option<Certificate> = previous.clone().try_into().ok();

    let dwarf_curr_bytes: Option<Vec<u8>> =
        mithril_curr_opt.as_ref().map(|c| certificate_to_bytes(c));
    let dwarf_prev_bytes: Option<Vec<u8>> =
        mithril_prev_opt.as_ref().map(|c| certificate_to_bytes(c));

    let dwarf_curr_zc = dwarf_curr_bytes
        .as_deref()
        .and_then(|b| certificate_from_bytes(b).ok());
    let dwarf_prev_zc = dwarf_prev_bytes
        .as_deref()
        .and_then(|b| certificate_from_bytes(b).ok());

    let mut per_check = Vec::with_capacity(s::SPECS.len());

    // For each spec, build a CheckComparison. If either side can't be
    // parsed, that check produces a StructuralError so the comparison
    // remains well-defined.
    macro_rules! pair {
        ($idx:expr, $mithril_fn:expr, $dwarf_fn:expr) => {{
            let (id, description) = s::SPECS[$idx];
            let mithril = match (&mithril_curr_opt, &mithril_prev_opt) {
                (Some(c), Some(p)) => catch_panics(|| $mithril_fn(c, p)),
                _ => CheckResult::fail(ErrorCategory::StructuralError, Vec::new()),
            };
            let dwarf = match (&dwarf_curr_zc, &dwarf_prev_zc) {
                (Some(c), Some(p)) => catch_panics(|| $dwarf_fn(c, p)),
                _ => CheckResult::fail(ErrorCategory::StructuralError, Vec::new()),
            };
            per_check.push(CheckComparison::new(id, description, mithril, dwarf));
        }};
    }

    // The macro takes (current, prev) closures uniformly. For checks
    // that only need `current`, the `prev` arg is discarded.
    pair!(
        0,
        |c: &Certificate, _: &Certificate| s::mithril_not_infinite_loop(c),
        |c: &_, _: &_| s::dwarf_not_infinite_loop(c)
    );
    pair!(
        1,
        |c: &Certificate, _: &Certificate| s::mithril_certificate_hash_matches_content(c),
        |c: &_, _: &_| s::dwarf_certificate_hash_matches_content(c)
    );
    pair!(
        2,
        |c: &Certificate, _: &Certificate| s::mithril_signed_message_matches_protocol_message(c),
        |c: &_, _: &_| s::dwarf_signed_message_matches_protocol_message(c)
    );
    pair!(
        3,
        |c: &Certificate, _: &Certificate| s::mithril_multi_signature_verifies(c),
        |c: &_, _: &_| s::dwarf_multi_signature_verifies(c)
    );
    pair!(
        4,
        |c: &Certificate, _: &Certificate| s::mithril_epoch_matches_protocol_message(c),
        |c: &_, _: &_| s::dwarf_epoch_matches_protocol_message(c)
    );
    pair!(5, s::mithril_epoch_chaining, s::dwarf_epoch_chaining);
    pair!(
        6,
        s::mithril_previous_hash_matches,
        s::dwarf_previous_hash_matches
    );
    pair!(7, s::mithril_avk_same_epoch, s::dwarf_avk_same_epoch);
    pair!(8, s::mithril_avk_chain, s::dwarf_avk_chain);
    pair!(
        9,
        s::mithril_protocol_params_same_epoch,
        s::dwarf_protocol_params_same_epoch
    );
    pair!(
        10,
        s::mithril_protocol_params_chain,
        s::dwarf_protocol_params_chain
    );

    let full_verify = {
        let mithril = match (&mithril_curr_opt, &mithril_prev_opt) {
            (Some(c), Some(p)) => catch_panics(|| full_verify::mithril_full_verify_standard(c, p)),
            _ => CheckResult::fail(ErrorCategory::StructuralError, Vec::new()),
        };
        let dwarf = match (&dwarf_curr_zc, &dwarf_prev_zc) {
            (Some(c), Some(p)) => catch_panics(|| full_verify::dwarf_full_verify_standard(c, p)),
            _ => CheckResult::fail(ErrorCategory::StructuralError, Vec::new()),
        };
        CheckComparison::new(
            "verify_standard_certificate (top-level)",
            "MithrilCertificateVerifier::verify_standard_certificate  vs  mithril_dwarf::verify_standard_certificate",
            mithril,
            dwarf,
        )
    };

    CertAudit {
        cert_label: label,
        kind: CertKind::Standard,
        per_check,
        full_verify,
        mutation_intentionally_diverges: false,
    }
}

fn audit_genesis(cert: &CertificateMessage, genesis_vk_hex: &str, label: String) -> CertAudit {
    let mithril_cert_opt: Option<Certificate> = cert.clone().try_into().ok();
    let dwarf_bytes: Option<Vec<u8>> = mithril_cert_opt.as_ref().map(|c| certificate_to_bytes(c));
    let dwarf_zc = dwarf_bytes
        .as_deref()
        .and_then(|b| certificate_from_bytes(b).ok());

    let genesis_vk_bytes: Option<[u8; 32]> = Ed25519VerificationKey::from_json_hex(genesis_vk_hex)
        .ok()
        .and_then(|vk| vk.as_ref().try_into().ok());
    let genesis_vk_strict: Option<ProtocolGenesisVerificationKey> =
        ProtocolGenesisVerificationKey::from_json_hex(genesis_vk_hex).ok();

    let mut per_check = Vec::with_capacity(g::SPECS.len());

    macro_rules! pair_g {
        ($idx:expr, $mithril_fn:expr, $dwarf_fn:expr) => {{
            let (id, description) = g::SPECS[$idx];
            let mithril = match &mithril_cert_opt {
                Some(c) => catch_panics(|| $mithril_fn(c)),
                None => CheckResult::fail(ErrorCategory::StructuralError, Vec::new()),
            };
            let dwarf = match &dwarf_zc {
                Some(c) => catch_panics(|| $dwarf_fn(c)),
                None => CheckResult::fail(ErrorCategory::StructuralError, Vec::new()),
            };
            per_check.push(CheckComparison::new(id, description, mithril, dwarf));
        }};
    }

    pair_g!(
        0,
        g::mithril_certificate_hash_matches_content,
        g::dwarf_certificate_hash_matches_content
    );
    pair_g!(
        1,
        g::mithril_signed_message_matches_protocol_message,
        g::dwarf_signed_message_matches_protocol_message
    );
    pair_g!(
        2,
        g::mithril_epoch_matches_protocol_message,
        g::dwarf_epoch_matches_protocol_message
    );

    // ed25519_verify needs the VK; do it as a special-case pair. The
    // Mithril side uses `ProtocolGenesisVerificationKey::verify` (strict);
    // the dwarf side uses dwarf's `verify_genesis_certificate`.
    {
        let (id, description) = g::SPECS[3];
        let mithril = match (&mithril_cert_opt, genesis_vk_strict.as_ref()) {
            (Some(c), Some(vk)) => catch_panics(|| g::mithril_ed25519_verify(c, vk)),
            _ => CheckResult::fail(ErrorCategory::StructuralError, Vec::new()),
        };
        let dwarf = match (&dwarf_zc, genesis_vk_bytes.as_ref()) {
            (Some(c), Some(vk)) => catch_panics(|| g::dwarf_ed25519_verify(c, vk)),
            _ => CheckResult::fail(ErrorCategory::StructuralError, Vec::new()),
        };
        per_check.push(CheckComparison::new(id, description, mithril, dwarf));
    }

    let full_verify = {
        let mithril = match &mithril_cert_opt {
            Some(c) => catch_panics(|| full_verify::mithril_full_verify_genesis(c, genesis_vk_hex)),
            None => CheckResult::fail(ErrorCategory::StructuralError, Vec::new()),
        };
        let dwarf = match (&dwarf_zc, genesis_vk_bytes.as_ref()) {
            (Some(c), Some(vk)) => catch_panics(|| full_verify::dwarf_full_verify_genesis(c, vk)),
            _ => CheckResult::fail(ErrorCategory::StructuralError, Vec::new()),
        };
        CheckComparison::new(
            "verify_genesis_certificate (top-level)",
            "MithrilCertificateVerifier::verify_genesis_certificate  vs  mithril_dwarf::verify_genesis_certificate",
            mithril,
            dwarf,
        )
    };

    CertAudit {
        cert_label: label,
        kind: CertKind::Genesis,
        per_check,
        full_verify,
        mutation_intentionally_diverges: false,
    }
}
