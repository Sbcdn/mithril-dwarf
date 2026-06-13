//! Corpus sweep: run `locate` over many real mainnet txs (Koios `/tx_cbor`),
//! keyed by their on-chain txid (the file name). The point is real-world variety
//! — to find a transaction shape that panics or breaks an invariant that the
//! hand-picked fixtures don't. For every tx under its real txid: `locate` must
//! succeed without panic, every component must be a byte-exact sub-slice with a
//! self-consistent hash locator, and a wrong txid must reject.

use mithril_dwarf::tx_parsing::{ScriptLanguage, locate_tx_components, script_hash};

fn h32(s: &str) -> [u8; 32] {
    hex::decode(s).unwrap().try_into().unwrap()
}

fn lang(tag: u8) -> ScriptLanguage {
    match tag {
        1 => ScriptLanguage::PlutusV1,
        2 => ScriptLanguage::PlutusV2,
        3 => ScriptLanguage::PlutusV3,
        _ => ScriptLanguage::Native,
    }
}

#[test]
fn corpus_sweep_holds_invariants() {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/test_data/tx_corpus");
    let mut n = 0;
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_stem().unwrap().to_str().unwrap().to_string();
        let txid = h32(&name);
        let tx = hex::decode(std::fs::read_to_string(&path).unwrap().trim()).unwrap();

        // Real tx under its real txid: locate without panic.
        let comps = match std::panic::catch_unwind(|| locate_tx_components(&tx, &txid, None)) {
            Ok(Ok(c)) => c,
            Ok(Err(e)) => panic!("real tx {name} failed to locate: {e:?}"),
            Err(_) => panic!("panicked locating {name}"),
        };

        for c in &comps {
            // A `0x05` script's component_bytes is `lang_tag ‖ script_bytes`; the
            // synthetic tag prefix isn't in the tx, the script bytes are.
            let on_chain: &[u8] = if c.component_type == 0x05 {
                &c.component_bytes[1..]
            } else {
                &c.component_bytes
            };
            assert!(
                tx.windows(on_chain.len()).any(|w| w == on_chain),
                "component not a byte-exact sub-slice in {name}",
            );
            if c.component_type == 0x05 {
                assert_eq!(
                    script_hash(lang(c.component_bytes[0]), on_chain).to_vec(),
                    c.locator,
                    "script locator not self-consistent in {name}",
                );
            }
            if c.component_type == 0x03 {
                assert_eq!(
                    c.component_bytes.len(),
                    32,
                    "datum-hash not 32 bytes in {name}"
                );
            }
        }

        // Wrong txid: rejected before any extraction.
        let mut wrong = txid;
        wrong[0] ^= 1;
        assert!(
            locate_tx_components(&tx, &wrong, None).is_err(),
            "wrong txid accepted for {name}",
        );
        n += 1;
    }
    assert!(n >= 30, "corpus too small ({n})");
}
