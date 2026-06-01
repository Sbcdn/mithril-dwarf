//! Text-format report rendering.
//!
//! Every report section spells out, for each check:
//! - the check `id` and description (what is being asserted)
//! - the canonical bytes Mithril produced
//! - the canonical bytes dwarf produced
//! - the bitwise comparison verdict
//! - the high-level semantic outcome (Pass / Fail(category) / N/A) on each side
//!
//! The same shape is used for the full-verify step at the bottom of each
//! cert, and for the mutation rejection sections.

use crate::types::{CertAudit, CertKind, CheckComparison, Outcome};

#[derive(Debug, Clone)]
pub struct ReportSummary {
    pub certs: usize,
    pub total_checks: usize,
    pub checks_matching: usize,
    pub checks_diverging: usize,
    pub mutations_run: usize,
    /// Both impls rejected the mutated cert. Either bitwise-equal
    /// (`rejected_bitwise_equal`) or with a soft category divergence
    /// (`rejected_soft_divergence`) — both counts add up to here.
    pub mutations_rejected_equivalently: usize,
    /// Sub-count: both impls rejected with byte-identical
    /// `ErrorCategory`.
    pub mutations_rejected_bitwise_equal: usize,
    /// Sub-count: both impls rejected but with different
    /// `ErrorCategory` values (e.g., dwarf fail-fast caught the bug at
    /// a different checkpoint). Counts as "rejected equivalently" for
    /// the security contract but is surfaced in the report.
    pub mutations_rejected_soft_divergence: usize,
    /// CRITICAL: Mithril rejected, dwarf accepted. Fails the test.
    pub mutations_critical_false_positive: usize,
    /// Soundness regression: dwarf rejected, Mithril accepted. Fails the test.
    pub mutations_soundness_regression: usize,
    /// Both impls accepted the mutated cert — the mutation isn't
    /// actually adversarial. Fails the test.
    pub mutations_insufficient: usize,
    /// Mithril rejected, dwarf accepted — but the mutation is tagged
    /// as a **known intentional divergence** (currently only
    /// `Ed25519MalleabilityTwin`, reflecting dwarf's cycle-saving
    /// non-strict ed25519 verify). Does NOT fail the test — the
    /// counter exists so the cost-of-safety tradeoff is visible in
    /// every harness run.
    pub mutations_intentional_divergence: usize,
}

impl ReportSummary {
    /// Total count of mutation cases that fail the test contract:
    /// CRITICAL false positives + soundness regressions + insufficient mutations.
    /// Does NOT include the `mutations_intentional_divergence` bucket
    /// — those are by-design tradeoffs, surfaced but not failed.
    pub fn hard_failures(&self) -> usize {
        self.mutations_critical_false_positive
            + self.mutations_soundness_regression
            + self.mutations_insufficient
    }
}

pub fn render_report(audits: &[CertAudit], mutated: &[CertAudit]) -> (String, ReportSummary) {
    let mut out = String::new();
    let mut total_checks = 0usize;
    let mut checks_matching = 0usize;

    out.push_str("=============================================================\n");
    out.push_str(" mithril-dwarf vs upstream Mithril — bitwise equivalence audit\n");
    out.push_str("=============================================================\n\n");

    out.push_str(&format!(
        "Positive corpus: {} certificate(s)\n",
        audits.len()
    ));
    out.push_str(&format!(
        "Mutated certs:   {} variant(s)\n\n",
        mutated.len()
    ));

    for a in audits {
        render_audit_section(&mut out, a);
        total_checks += a.per_check.len() + 1;
        checks_matching += a.per_check.iter().filter(|c| c.matches_bitwise).count();
        if a.full_verify.matches_bitwise {
            checks_matching += 1;
        }
    }

    let mut critical = 0usize;
    let mut soundness = 0usize;
    let mut insufficient = 0usize;
    let mut rejected_bitwise = 0usize;
    let mut rejected_soft = 0usize;
    let mut intentional_divergence = 0usize;

    if !mutated.is_empty() {
        out.push_str("\n");
        out.push_str("=============================================================\n");
        out.push_str(" Mutated certificates (negative tests)\n");
        out.push_str("=============================================================\n\n");
        out.push_str(
            "Contract: dwarf must reject every cert Mithril would reject.\n\
             - CRITICAL              Mithril rejected, dwarf accepted (false positive)\n\
             - SOUNDNESS             dwarf rejected, Mithril accepted (regression)\n\
             - INSUFFICIENT          both accepted (mutation isn't adversarial)\n\
             - REJECTED              both rejected, byte-identical category (ideal)\n\
             - SOFT DIVERGENCE       both rejected, different categories\n\
                                     (security contract satisfied, surfaced for visibility)\n\
             - INTENTIONAL DIVERGENCE Mithril rejected, dwarf accepted, BY DESIGN\n\
                                     (cycle-saving tradeoff explicitly approved at\n\
                                      design time, e.g. non-strict ed25519 verify)\n\n",
        );

        for a in mutated {
            render_audit_section(&mut out, a);
            total_checks += a.per_check.len() + 1;
            checks_matching += a.per_check.iter().filter(|c| c.matches_bitwise).count();
            if a.full_verify.matches_bitwise {
                checks_matching += 1;
            }
            let mithril_pass = matches!(a.full_verify.mithril.outcome, Outcome::Pass);
            let dwarf_pass = matches!(a.full_verify.dwarf.outcome, Outcome::Pass);
            match (mithril_pass, dwarf_pass) {
                (false, true) => {
                    if a.mutation_intentionally_diverges {
                        intentional_divergence += 1;
                    } else {
                        critical += 1;
                    }
                }
                (true, false) => soundness += 1,
                (true, true) => insufficient += 1,
                (false, false) => {
                    if a.full_verify.matches_bitwise {
                        rejected_bitwise += 1;
                    } else {
                        rejected_soft += 1;
                    }
                }
            }
        }
    }

    let summary = ReportSummary {
        certs: audits.len(),
        total_checks,
        checks_matching,
        checks_diverging: total_checks.saturating_sub(checks_matching),
        mutations_run: mutated.len(),
        mutations_rejected_equivalently: rejected_bitwise + rejected_soft,
        mutations_rejected_bitwise_equal: rejected_bitwise,
        mutations_rejected_soft_divergence: rejected_soft,
        mutations_critical_false_positive: critical,
        mutations_soundness_regression: soundness,
        mutations_insufficient: insufficient,
        mutations_intentional_divergence: intentional_divergence,
    };

    out.push_str("\n=============================================================\n");
    out.push_str(" Summary\n");
    out.push_str("=============================================================\n");
    out.push_str(&format!(
        "Positive certs compared:        {}\n",
        summary.certs
    ));
    out.push_str(&format!(
        "Per-check + full-verify total:  {}\n",
        summary.total_checks
    ));
    out.push_str(&format!(
        "Bitwise matches:                {}\n",
        summary.checks_matching
    ));
    out.push_str(&format!(
        "Bitwise divergences:            {}\n",
        summary.checks_diverging
    ));
    if summary.mutations_run > 0 {
        out.push_str(&format!(
            "Mutations run:                  {}\n",
            summary.mutations_run
        ));
        out.push_str(&format!(
            "  Rejected bitwise-identical:   {}\n",
            summary.mutations_rejected_bitwise_equal
        ));
        out.push_str(&format!(
            "  Rejected soft divergence:     {}  (both reject, different ErrorCategory)\n",
            summary.mutations_rejected_soft_divergence
        ));
        out.push_str(&format!(
            "  CRITICAL false positive:      {}  (Mithril rejected, dwarf accepted)\n",
            summary.mutations_critical_false_positive
        ));
        out.push_str(&format!(
            "  Soundness regression:         {}  (dwarf rejected, Mithril accepted)\n",
            summary.mutations_soundness_regression
        ));
        out.push_str(&format!(
            "  Mutation insufficient:        {}  (both accepted)\n",
            summary.mutations_insufficient
        ));
        out.push_str(&format!(
            "  Intentional divergence:       {}  (Mithril rejected, dwarf accepted by design)\n",
            summary.mutations_intentional_divergence
        ));
    }
    let status = if summary.checks_diverging == 0 && summary.hard_failures() == 0 {
        "[OK]   all comparisons satisfy the contract"
    } else {
        "[FAIL] one or more divergences"
    };
    out.push_str(&format!("Verdict:                        {status}\n"));

    (out, summary)
}

fn render_audit_section(out: &mut String, audit: &CertAudit) {
    let kind = match audit.kind {
        CertKind::Standard => "STANDARD",
        CertKind::Genesis => "GENESIS",
    };
    out.push_str(&format!("--- {} | {} ---\n", kind, audit.cert_label));
    for cmp in &audit.per_check {
        render_check_comparison(out, cmp);
    }
    out.push_str("  --- top-level verify ---\n");
    render_check_comparison(out, &audit.full_verify);
    let verdict = if audit.all_match() {
        "  [OK]   every check bitwise-equal\n"
    } else {
        "  [FAIL] one or more checks diverged (see [XX] markers above)\n"
    };
    out.push_str(verdict);
    out.push('\n');
}

fn render_check_comparison(out: &mut String, cmp: &CheckComparison) {
    let mark = if cmp.matches_bitwise { "[ok]" } else { "[XX]" };
    out.push_str(&format!("  {mark} {} — {}\n", cmp.id, cmp.description));
    out.push_str(&format!(
        "       mithril bytes ({:>3}B): {}  -> {}\n",
        cmp.mithril.bytes.len(),
        hex_repr(&cmp.mithril.bytes),
        outcome_str(cmp.mithril.outcome),
    ));
    out.push_str(&format!(
        "       dwarf   bytes ({:>3}B): {}  -> {}\n",
        cmp.dwarf.bytes.len(),
        hex_repr(&cmp.dwarf.bytes),
        outcome_str(cmp.dwarf.outcome),
    ));
}

fn outcome_str(o: Outcome) -> String {
    match o {
        Outcome::Pass => "Pass".to_string(),
        Outcome::Fail(c) => format!("Fail({:?})", c),
        Outcome::NotApplicable => "N/A".to_string(),
    }
}

fn hex_repr(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        "(empty)".to_string()
    } else if bytes.len() <= 33 {
        hex::encode(bytes)
    } else {
        format!(
            "{}…{}",
            hex::encode(&bytes[..8]),
            hex::encode(&bytes[bytes.len() - 8..])
        )
    }
}
