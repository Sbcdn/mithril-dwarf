//! Audit binary: bitwise-equivalence report of mithril-dwarf vs upstream Mithril.
//!
//! For each certificate in the corpus, runs every Mithril check + every
//! dwarf check, bitwise-compares the canonical bytes, then runs the
//! top-level verifier on both sides and bitwise-compares those too.
//! Then runs a curated mutation set against a representative cert and
//! asserts both implementations reject the mutated cert in the same way.
//!
//! Exit code: 0 if every comparison matches and every mutation is
//! rejected equivalently; 1 otherwise.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;
use mithril_dwarf_harness::corpus::{CorpusEntry, CorpusLoad, load_corpus};
use mithril_dwarf_harness::{
    MAINNET_GENESIS_VK_HEX, audit_corpus_entry, audit_mutated, render_report, standard_mutations,
};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Directory of `.cert` bincode files (populate via `fetch_certificates`).
    #[arg(
        long,
        default_value = "mithril-dwarf-harness/tests/test_data/certificates"
    )]
    corpus: PathBuf,

    /// Skip the mutation suite. Useful for fast on-corpus-only diagnostics.
    #[arg(long)]
    no_mutations: bool,
}

fn main() -> ExitCode {
    let args = Args::parse();

    let load = load_corpus(&args.corpus);
    if let Some(code) = report_load_problems(&load, &args.corpus) {
        return code;
    }

    let mut positive_audits = Vec::with_capacity(load.entries.len());
    for entry in &load.entries {
        positive_audits.push(audit_corpus_entry(entry, MAINNET_GENESIS_VK_HEX));
    }

    let mut mutated_audits = Vec::new();
    if !args.no_mutations {
        // Pick the first standard cert as the negative-test target. Genesis
        // is also worth mutating but the standard cert exercises more checks.
        if let Some(base) = load
            .entries
            .iter()
            .find(|e| matches!(e, CorpusEntry::Standard { .. }))
        {
            let base_cert = match base {
                CorpusEntry::Standard { current, .. } => current,
                _ => unreachable!("filtered just above"),
            };
            for applied in standard_mutations() {
                if !applied.mutation.is_applicable_to(base_cert) {
                    continue;
                }
                mutated_audits.push(audit_mutated(base, &applied, MAINNET_GENESIS_VK_HEX));
            }
        } else {
            eprintln!("warning: no standard cert in corpus to mutate; mutation suite skipped");
        }
    }

    let (report, summary) = render_report(&positive_audits, &mutated_audits);
    println!("{}", report);

    // Exit code: 0 if every comparison satisfies the harness contract.
    // The contract treats per-check bitwise mismatches and the three hard
    // failure mutation classes (CRITICAL, soundness regression,
    // insufficient) as failures; soft category divergence on a rejected
    // mutation is reported but does not flip the exit code (both impls
    // still reject, which is the security guarantee).
    if summary.checks_diverging == 0 && summary.hard_failures() == 0 {
        ExitCode::from(0)
    } else {
        ExitCode::from(1)
    }
}

fn report_load_problems(load: &CorpusLoad, corpus_dir: &PathBuf) -> Option<ExitCode> {
    if !load.load_errors.is_empty() {
        eprintln!("Corpus load errors:");
        for e in &load.load_errors {
            eprintln!("  {}: {}", e.path.display(), e.reason);
        }
    }
    if !load.orphans.is_empty() {
        eprintln!(
            "Corpus orphans (cert present but previous_hash unresolved, skipped): {}",
            load.orphans.len()
        );
        for o in load.orphans.iter().take(5) {
            eprintln!("  {}", o);
        }
    }
    if load.entries.is_empty() {
        eprintln!(
            "Corpus at {} is empty after filtering. Populate via:\n  cargo run -p mithril-dwarf-harness --bin fetch_certificates -- \\\n      --network mainnet --certificate-hash <hash>",
            corpus_dir.display()
        );
        return Some(ExitCode::from(2));
    }
    eprintln!(
        "Loaded {} corpus entries (genesis: {}, standard same-epoch: {}, standard diff-epoch: {}, orphans: {}, load errors: {})",
        load.entries.len(),
        load.genesis_count,
        load.standard_same_epoch,
        load.standard_diff_epoch,
        load.orphans.len(),
        load.load_errors.len(),
    );
    None
}
