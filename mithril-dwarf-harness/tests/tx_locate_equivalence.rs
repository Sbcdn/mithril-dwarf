//! `locate_tx_components` against a real Plutus tx (Koios `/tx_cbor`).
//!
//! `0x05` scripts: located bytes are a byte-exact sub-slice of the tx CBOR and
//! the locator equals the real on-chain script hash. `0x01` redeemers: emitted
//! only with cost models, behind the `script_data_hash` binding, byte-exact.

use mithril_dwarf::tx_parsing::{
    ScriptLanguage, cost_models_to_wire, locate_tx_components, script_hash,
};

const C_REDEEMER: u8 = 0x01;
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
fn locate_rejects_garbage() {
    assert!(locate_tx_components(&[0xff, 0x00, 0x13], None).is_err());
    assert!(locate_tx_components(&[], None).is_err());
}
