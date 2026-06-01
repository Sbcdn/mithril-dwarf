//! Equivalence harness for `mithril-dwarf` vs upstream Mithril.
//!
//! Per cert: run every Mithril check and the matching dwarf check,
//! bitwise-compare the canonical byte streams, then bitwise-compare
//! the top-level `verify_*_certificate` results. A mutation suite then
//! perturbs the cert and re-runs both impls; the harness fails the
//! test on a false positive (dwarf accepts what Mithril rejects), a
//! soundness regression (the reverse), or a no-op mutation. Both impls
//! rejecting with different `ErrorCategory` is a soft divergence —
//! reported but not fatal.

pub mod audit;
pub mod check_helpers;
pub mod checks_genesis;
pub mod checks_standard;
pub mod corpus;
pub mod full_verify;
pub mod mutation;
pub mod report;
pub mod types;

pub use audit::{
    audit_corpus_entry, audit_mutated, audit_mutated_top_level_only,
    audit_standard_top_level_only, audit_standard_with_mutated_msgs,
};
pub use corpus::{
    CorpusEntry, CorpusLoad, LoadError, MAINNET_GENESIS_VK_HEX, PREPROD_GENESIS_VK_HEX,
    PREVIEW_GENESIS_VK_HEX, genesis_vk_for_cert, load_corpus,
};
pub use mutation::{
    AppliedMutation, Mutation, MutationTarget, applied_mutation_label, apply_mutation,
    mutation_label, standard_mutations,
};
pub use report::{ReportSummary, render_report};
pub use types::{CertAudit, CertKind, CheckComparison, CheckResult, ErrorCategory, Outcome};
