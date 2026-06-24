//! Live-data gate for the exact-`from_float` lottery change, run against the
//! corpus's real **preview** certificates specifically.
//!
//! Preview is where the lottery arithmetic is stressed: a few large pools hold
//! most of the stake, so `w = stake/total` is large, `x = -w·ln(1-phi_f)` is
//! wide, and the per-index Taylor series runs deep (the regime that motivated
//! the U512→U2048 wide fallback and where exact-`c`'s denominator matters most).
//! Mainnet/preprod, with stake spread thin, never exercise this. So we assert
//! dwarf's verdict is bit-equivalent to upstream on every real preview cert, and
//! that the corpus actually contains preview certs (no silent empty pass).
//!
//! Corpus-dependent (fetched, gitignored) → local-only, like `equivalence`.

use mithril_dwarf_harness::{
    audit_corpus_entry, genesis_vk_for_cert, load_corpus, render_report,
};
use std::path::Path;

const CORPUS_DIR: &str = "tests/test_data/certificates";

#[test]
fn preview_certs_verify_bitwise_equivalent_to_upstream() {
    let load = load_corpus(Path::new(CORPUS_DIR));
    assert!(load.load_errors.is_empty(), "corpus load errors: {:?}", load.load_errors);

    let preview: Vec<_> = load
        .entries
        .iter()
        .filter(|e| e.primary_cert().metadata.network == "preview")
        .collect();

    // Structural floor: the change is only meaningfully exercised if real
    // preview vectors are present. Fetch the corpus if this trips.
    assert!(
        !preview.is_empty(),
        "no preview certs in the corpus — the exact-from_float change would be \
         unexercised on its target network. Run fetch_diverse_corpus.sh."
    );

    let mut diverged = Vec::new();
    for entry in &preview {
        let cert = entry.primary_cert();
        let vk = genesis_vk_for_cert(cert).expect("preview genesis VK registered");
        let audit = audit_corpus_entry(entry, vk);
        eprintln!(
            "preview {} | network={} | signers={} | phi_f={} | dwarf={:?} mithril={:?} | bitwise={}",
            &cert.hash[..16.min(cert.hash.len())],
            cert.metadata.network,
            cert.metadata.signers.len(),
            cert.metadata.protocol_parameters.phi_f,
            audit.full_verify.dwarf.outcome,
            audit.full_verify.mithril.outcome,
            audit.all_match(),
        );
        if !audit.all_match() {
            diverged.push(audit);
        }
    }

    if !diverged.is_empty() {
        let (report, _) = render_report(&diverged, &[]);
        panic!("dwarf diverged from upstream on real preview certs:\n{report}");
    }
    eprintln!("OK: {} preview cert(s) bit-equivalent to upstream", preview.len());
}
