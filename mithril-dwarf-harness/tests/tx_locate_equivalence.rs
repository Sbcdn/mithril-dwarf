//! `locate_tx_components` against real txs (Koios `/tx_cbor`). Each component's
//! bytes are a byte-exact sub-slice of the tx CBOR; hash locators (`0x04`/`0x05`)
//! equal the real on-chain hash; `0x01`/`0x04` are emitted only behind the
//! verified `script_data_hash` binding. Covers all five §5 component types.

use mithril_dwarf::tx_parsing::{
    ScriptLanguage, cost_models_to_wire, datum_hash, locate_tx_components, script_hash,
};

const C_REDEEMER: u8 = 0x01;
const C_DATUM_INLINE: u8 = 0x02;
const C_DATUM_HASH: u8 = 0x03;
const C_WITNESS_DATUM: u8 = 0x04;
const C_SCRIPT: u8 = 0x05;

fn v1_costs() -> Vec<i64> {
    serde_json::from_str(include_str!("test_data/tx_scripts/epoch297_v1_costs.json")).unwrap()
}

#[test]
fn locate_extracts_real_witness_script() {
    let tx = hex::decode(include_str!("test_data/tx_scripts/plutus_tx.hex").trim()).unwrap();
    let onchain = include_str!("test_data/tx_scripts/plutus_tx_v1_script.hex").trim();

    let components = locate_tx_components(&tx, None).expect("decode real plutus tx");
    let scripts: Vec<_> = components
        .iter()
        .filter(|c| c.component_type == C_SCRIPT)
        .collect();
    assert_eq!(scripts.len(), 1, "expected exactly one witness script");

    let s = scripts[0];
    // component_bytes = language_tag ‖ script_bytes.
    assert_eq!(
        s.component_bytes[0],
        ScriptLanguage::PlutusV1 as u8,
        "wrong language tag"
    );
    let script_bytes = &s.component_bytes[1..];

    // Byte-exact: the script bytes appear verbatim in the tx CBOR.
    assert!(
        tx.windows(script_bytes.len()).any(|w| w == script_bytes),
        "script bytes are not a sub-slice of tx_bytes",
    );

    // Locator is the real on-chain script hash, and is self-certifying.
    assert_eq!(
        hex::encode(&s.locator),
        onchain,
        "locator != on-chain script hash"
    );
    assert_eq!(
        script_hash(ScriptLanguage::PlutusV1, script_bytes).to_vec(),
        s.locator,
        "locator != blake2b224(language ‖ script_bytes)",
    );
}

#[test]
fn locate_extracts_real_redeemers_behind_binding() {
    let tx = hex::decode(include_str!("test_data/tx_scripts/plutus_tx.hex").trim()).unwrap();
    let wire = cost_models_to_wire(&[(0u8, v1_costs())]);

    // With cost models: the script_data binding passes, redeemers are emitted.
    let components = locate_tx_components(&tx, Some(&wire)).expect("locate with cost models");
    let redeemers: Vec<_> = components
        .iter()
        .filter(|c| c.component_type == C_REDEEMER)
        .collect();
    assert!(!redeemers.is_empty(), "expected at least one redeemer");
    for r in &redeemers {
        // locator = tag:u8 ‖ index:u32-le.
        assert_eq!(r.locator.len(), 5, "redeemer locator must be 5 bytes");
        // byte-exact: the redeemer data CBOR appears verbatim in the tx.
        assert!(
            tx.windows(r.component_bytes.len())
                .any(|w| w == r.component_bytes),
            "redeemer data is not a sub-slice of tx_bytes",
        );
    }

    // Without cost models: no redeemers emitted (only txid-authenticated parts).
    let no_cm = locate_tx_components(&tx, None).unwrap();
    assert!(no_cm.iter().all(|c| c.component_type != C_REDEEMER));

    // Wrong cost model: the folded binding fails, nothing is emitted.
    let mut bad = v1_costs();
    bad[0] += 1;
    assert!(locate_tx_components(&tx, Some(&cost_models_to_wire(&[(0u8, bad)]))).is_err());
}

#[test]
fn locate_extracts_real_witness_datum() {
    let tx = hex::decode(include_str!("test_data/tx_scripts/datum_tx.hex").trim()).unwrap();
    let v1: Vec<i64> = serde_json::from_str(include_str!(
        "test_data/tx_scripts/datum_tx_epoch327_v1_costs.json"
    ))
    .unwrap();
    let onchain = include_str!("test_data/tx_scripts/datum_tx_witness_datum_hash.hex").trim();
    let wire = cost_models_to_wire(&[(0u8, v1)]);

    let components = locate_tx_components(&tx, Some(&wire)).expect("locate datum tx");
    let datums: Vec<_> = components
        .iter()
        .filter(|c| c.component_type == C_WITNESS_DATUM)
        .collect();
    assert_eq!(datums.len(), 1, "expected one witness datum");

    let d = datums[0];
    // byte-exact: the datum CBOR appears verbatim in the tx.
    assert!(
        tx.windows(d.component_bytes.len())
            .any(|w| w == d.component_bytes),
        "datum is not a sub-slice of tx_bytes",
    );
    // locator = the real on-chain datum hash, and is self-certifying.
    assert_eq!(
        hex::encode(&d.locator),
        onchain,
        "locator != on-chain datum hash"
    );
    assert_eq!(
        datum_hash(&d.component_bytes).to_vec(),
        d.locator,
        "locator != blake2b256(datum)",
    );
}

#[test]
fn locate_extracts_real_output_datums() {
    let tx = hex::decode(include_str!("test_data/tx_scripts/output_datum_tx.hex").trim()).unwrap();
    // Output datums are body-resident (txid-committed) — no cost models needed.
    let components = locate_tx_components(&tx, None).expect("locate output-datum tx");

    let inline: Vec<_> = components
        .iter()
        .filter(|c| c.component_type == C_DATUM_INLINE)
        .collect();
    let dhash: Vec<_> = components
        .iter()
        .filter(|c| c.component_type == C_DATUM_HASH)
        .collect();
    assert_eq!(inline.len(), 2, "expected 2 inline datums");
    assert_eq!(dhash.len(), 1, "expected 1 output datum-hash");

    for c in inline.iter().chain(dhash.iter()) {
        // locator is the u32-le output index.
        assert_eq!(c.locator.len(), 4, "output-datum locator is a u32 index");
        // byte-exact: the bytes appear verbatim in the tx.
        assert!(
            tx.windows(c.component_bytes.len())
                .any(|w| w == c.component_bytes),
            "output datum is not a sub-slice of tx_bytes",
        );
    }
    // a datum-hash component is exactly the 32-byte hash.
    assert_eq!(dhash[0].component_bytes.len(), 32);
}

#[test]
fn locate_rejects_garbage() {
    assert!(locate_tx_components(&[0xff, 0x00, 0x13], None).is_err());
    assert!(locate_tx_components(&[], None).is_err());
}
