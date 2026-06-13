//! `script_hash` pinned to real on-chain script hashes (Koios `/script_info`).
//!
//! Each fixture row is `type \t tag \t onchain_script_hash \t script_bytes_hex`,
//! where `onchain_script_hash` is the ledger's hash. The assertion is that
//! dwarf reproduces it from the raw script bytes — pinning the language tag and
//! the raw-bytes (not CBOR-wrapped) preimage semantics against ground truth.

use mithril_dwarf::tx_parsing::{ScriptLanguage, script_hash};

fn lang(s: &str) -> ScriptLanguage {
    match s {
        "plutusV1" => ScriptLanguage::PlutusV1,
        "plutusV2" => ScriptLanguage::PlutusV2,
        "plutusV3" => ScriptLanguage::PlutusV3,
        _ => ScriptLanguage::Native,
    }
}

#[test]
fn script_hash_matches_real_onchain() {
    let tsv = include_str!("test_data/tx_scripts/script_hashes.tsv");
    let mut n = 0;
    for line in tsv.lines().filter(|l| !l.is_empty()) {
        let mut f = line.split('\t');
        let typ = f.next().unwrap();
        let _tag = f.next().unwrap();
        let onchain = f.next().unwrap();
        let bytes = hex::decode(f.next().unwrap()).unwrap();
        assert_eq!(
            hex::encode(script_hash(lang(typ), &bytes)),
            onchain,
            "script_hash mismatch for {typ}",
        );
        n += 1;
    }
    assert!(n >= 3, "expected >= 3 script vectors, got {n}");
}
