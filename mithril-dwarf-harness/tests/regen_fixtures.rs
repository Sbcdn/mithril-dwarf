//! Regenerator for `testdata/cert_current.bin` — the dwarf-wire serialization of
//! a real MithrilStakeDistribution certificate that the unit test
//! `complex_checks::real_cert_per_index_decisions_match_reference` parses.
//!
//! Re-run this after any change to the dwarf certificate wire format (e.g. the
//! u8 -> u32 winning-index count, which made the old fixture unparseable):
//!
//!   cargo test -p mithril-dwarf-harness --test regen_fixtures --release \
//!       -- --ignored --nocapture
//!
//! Requires a fetched corpus (tests/test_data/fetch_diverse_corpus.sh).

use mithril_common::entities::{Certificate, SignedEntityType};
use mithril_dwarf::certificate_to_bytes;
use mithril_dwarf_harness::{CorpusEntry, load_corpus};
use std::path::Path;

const CORPUS_DIR: &str = "tests/test_data/certificates";

#[test]
#[ignore = "fixture regenerator; run explicitly after a wire-format change"]
fn regenerate_cert_current_fixture() {
    let load = load_corpus(Path::new(CORPUS_DIR));
    // Deterministic pick: the MithrilStakeDistribution standard cert with the
    // most signers (deepest per-index lottery coverage), ties broken by hash so
    // the choice is stable across machines.
    let mut sd: Vec<_> = load
        .entries
        .iter()
        .filter_map(|e| match e {
            CorpusEntry::Standard { current, .. }
                if matches!(
                    current.signed_entity_type,
                    SignedEntityType::MithrilStakeDistribution(_)
                ) && (current.metadata.protocol_parameters.phi_f - 1.0).abs() >= f64::EPSILON =>
            {
                Some(current)
            }
            _ => None,
        })
        .collect();
    assert!(!sd.is_empty(), "no MithrilStakeDistribution cert in the corpus");
    sd.sort_by(|a, b| {
        b.metadata
            .signers
            .len()
            .cmp(&a.metadata.signers.len())
            .then(a.hash.cmp(&b.hash))
    });
    let cert = sd[0];

    let typed: Certificate = cert
        .clone()
        .try_into()
        .expect("CertificateMessage -> Certificate");
    let bytes = certificate_to_bytes(&typed);

    // Keep the src-side fixture and its harness mirror identical.
    let manifest = env!("CARGO_MANIFEST_DIR");
    for p in [
        format!("{manifest}/../testdata/cert_current.bin"),
        format!("{manifest}/tests/test_data/cert_current.bin"),
    ] {
        std::fs::write(&p, &bytes).unwrap_or_else(|e| panic!("write {p}: {e}"));
        eprintln!("wrote {} bytes -> {p}", bytes.len());
    }
    eprintln!(
        "regenerated cert_current.bin from cert {} ({} signers, phi_f={})",
        cert.hash,
        cert.metadata.signers.len(),
        cert.metadata.protocol_parameters.phi_f
    );
}
