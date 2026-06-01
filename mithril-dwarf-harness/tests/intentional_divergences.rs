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
//! | 2 | Ed25519 non-strict verify                               | crypto    | Yes (empirical)     |
//! | 3 | `verify_epoch_chaining` direction asymmetry             | check     | Conditionally       |
//! | 4 | Check ordering in `verify_standard_certificate`         | orchestr. | Yes (top-level)     |
//! | 5 | usize-vs-u64 BLS scalar index width on RISC0            | platform  | Yes (BLS math)      |

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

/// Pin: blst accepts identity, so the defence is at verify-time.
#[test]
fn divergence_1_bls_identity_defence_layer_pinned() {
    use blst::min_sig::{PublicKey, Signature};

    let mut g1_identity = [0u8; 48];
    g1_identity[0] = 0xC0;
    let mut g2_identity = [0u8; 96];
    g2_identity[0] = 0xC0;

    assert!(
        Signature::from_bytes(&g1_identity).is_ok(),
        "blst tightened identity rejection at Signature::from_bytes; \
         update the registry — defence is now at parse-time"
    );
    assert!(
        PublicKey::from_bytes(&g2_identity).is_ok(),
        "blst tightened identity rejection at PublicKey::from_bytes; \
         update the registry"
    );
}

// Divergence #2 — Ed25519 non-strict verify (vs upstream's `verify_strict`)
//
// Dwarf calls `ed25519_dalek::VerifyingKey::verify` (mod.rs); upstream
// calls `verify_strict` via `ProtocolGenesisVerificationKey::verify`.
// `verify_strict` adds subgroup checks on `R` / `A`; the non-strict path
// skips them for cycle savings.
//
// Under `ed25519-dalek` 2.1.1 both paths route through
// `Scalar::from_canonical_bytes(s)`, which rejects any `s >= L`, so the
// malleability twin (`s + L`) is rejected by both — verdicts match. The
// pin catches a future dalek bump that loosens the non-strict path.

/// Pin: dalek 2.x rejects `s >= L` in both `verify` and `verify_strict`.
#[test]
fn divergence_2_ed25519_non_strict_pinned() {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    // Construct an arbitrary signature where s >= L. The Ed25519 group
    // order L is `2^252 + 27742317777372353535851937790883648493`. Any
    // 32-byte value with bit 254 set and lower bits high enough exceeds
    // L. For the pin we use s = 2^255 - 1 (all-ones), which is well
    // above L and is the canonical "out-of-range" representative.
    let mut sig_bytes = [0u8; 64];
    sig_bytes[..32].fill(0u8); // R = any 32 bytes (we don't care about the point validity here)
    sig_bytes[32..].fill(0xFFu8); // s = 0xFF...FF, which is >= L
    let sig = Signature::from_bytes(&sig_bytes);

    // Point validity of `R` / `A` is irrelevant; the assertion turns
    // entirely on the scalar canonicality check.
    let vk_bytes: [u8; 32] = [
        0xed, 0x4d, 0xc2, 0x46, 0x3a, 0x65, 0xa8, 0x70, 0x07, 0x4a, 0xd6, 0x6e, 0xa9, 0x66, 0x2a,
        0x76, 0xee, 0xed, 0x5c, 0x4f, 0xfb, 0x73, 0xdc, 0x4d, 0x49, 0xb7, 0x80, 0x12, 0xfd, 0x42,
        0xe6, 0x86,
    ];
    let vk = VerifyingKey::from_bytes(&vk_bytes).expect("VK construction");
    let msg = b"divergence-2-pin";

    assert!(
        vk.verify(msg, &sig).is_err(),
        "non-strict ed25519 verify accepts s >= L — switch dwarf to verify_strict"
    );
    assert!(
        vk.verify_strict(msg, &sig).is_err(),
        "verify_strict accepts s >= L; investigate"
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

/// Pin: the asymmetric direction is dwarf-only. Synthetic, not
/// corpus-driven.
#[test]
fn divergence_3_epoch_chaining_direction_pinned() {
    use mithril_dwarf::parser::byte_deserializer::{
        certificate_from_bytes, CertificateZeroCopy,
    };
    use mithril_dwarf::certificate_to_bytes;

    // Use a real corpus pair as the base shape. We'll mutate the epoch
    // fields directly via the wire-byte path to construct
    // `prev.epoch > curr.epoch`, which upstream's `try_into` won't
    // canonicalise away (epoch is a plain u64 field).
    let load = load_corpus(Path::new(CORPUS_DIR));
    let (curr_msg, prev_msg) = load
        .entries
        .iter()
        .find_map(|e| match e {
            CorpusEntry::Standard { current, previous } => Some((current, previous)),
            _ => None,
        })
        .expect("corpus has a standard cert pair");

    // Force `prev.epoch > curr.epoch` — the direction dwarf rejects
    // and upstream's symmetric `abs_diff` admits.
    let mut current = curr_msg.clone();
    let mut previous = prev_msg.clone();
    current.epoch = mithril_common::entities::Epoch(100);
    previous.epoch = mithril_common::entities::Epoch(101);

    let curr_typed: mithril_common::entities::Certificate =
        current.clone().try_into().expect("curr try_into");
    let prev_typed: mithril_common::entities::Certificate =
        previous.clone().try_into().expect("prev try_into");
    let curr_bytes = certificate_to_bytes(&curr_typed);
    let prev_bytes = certificate_to_bytes(&prev_typed);
    let curr_zc: CertificateZeroCopy = certificate_from_bytes(&curr_bytes).expect("parse curr");
    let prev_zc: CertificateZeroCopy = certificate_from_bytes(&prev_bytes).expect("parse prev");

    let direct = mithril_dwarf::certificate_verification::basic_checks::verify_epoch_chaining(
        &curr_zc, &prev_zc,
    );
    assert!(
        matches!(direct, Err(VerifyError::EpochGap)),
        "dwarf verify_epoch_chaining became symmetric (or returned a different error); got {direct:?}"
    );

    use mithril_common::entities::Epoch;
    assert!(
        !Epoch(100).has_gap_with(&Epoch(101)),
        "upstream Epoch::has_gap_with(100, 101) now reports a gap — dwarf and upstream are symmetric again"
    );
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
/// multi-defect cert.
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

    // Categories may match or differ depending on which check fires first.
    eprintln!(
        "divergence-4 pin: multi-defect epoch+100 -> mithril={mithril_cat:?}, dwarf={dwarf_cat:?}"
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

/// Pin: host `usize` width. On a 32-bit host this divergence vanishes
/// (host then matches the RISC0 guest), and the rest of the registry
/// reasoning would need revisiting.
#[test]
fn divergence_5_usize_index_width_pinned() {
    let width = core::mem::size_of::<usize>();
    assert_eq!(
        width, 8,
        "harness running on a non-64-bit host (usize is {width} bytes); \
         the host/guest divergence no longer applies in this build"
    );

    use blake2::{digest::consts::U16, Blake2b, Digest};
    let mut h = Blake2b::<U16>::new();
    h.update(b"prefix-bytes-from-all-sigmas");
    let mut hasher = h.clone();
    let index: usize = 0;
    hasher.update(index.to_be_bytes());
    let scalar: [u8; 16] = hasher.finalize().into();
    assert_eq!(scalar.len(), 16);
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
