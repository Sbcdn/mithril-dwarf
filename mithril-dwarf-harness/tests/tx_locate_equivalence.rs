//! `locate_tx_components` against a real Plutus tx (Koios `/tx_cbor`).
//!
//! Currently covers `0x05` scripts: the located script bytes must be a byte-exact
//! sub-slice of the tx CBOR, and its locator must equal the real on-chain script
//! hash. (Datums / redeemers / script_data_hash binding land in later commits.)

use mithril_dwarf::tx_parsing::{ScriptLanguage, locate_tx_components, script_hash};

const C_SCRIPT: u8 = 0x05;

#[test]
fn locate_extracts_real_witness_script() {
    let tx = hex::decode(include_str!("test_data/tx_scripts/plutus_tx.hex").trim()).unwrap();
    let onchain = include_str!("test_data/tx_scripts/plutus_tx_v1_script.hex").trim();

    let components = locate_tx_components(&tx).expect("decode real plutus tx");
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
fn locate_rejects_garbage() {
    assert!(locate_tx_components(&[0xff, 0x00, 0x13]).is_err());
    assert!(locate_tx_components(&[]).is_err());
}
