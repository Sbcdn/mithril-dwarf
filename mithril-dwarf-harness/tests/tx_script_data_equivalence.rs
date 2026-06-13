//! `verify_script_data` against a real on-chain `script_data_hash`.
//!
//! The tx (Koios `/tx_cbor`) is PlutusV1 with redeemers; recomputing its
//! script_data_hash from the real epoch cost model must equal the body field —
//! and a wrong cost model / language / malformed wire must reject. This pins the
//! finicky `language_views` encoding against ground truth.

use mithril_dwarf::tx_parsing::{TxParseError, cost_models_to_wire, verify_script_data};

fn v1_costs() -> Vec<i64> {
    serde_json::from_str(include_str!("test_data/tx_scripts/epoch297_v1_costs.json")).unwrap()
}

#[test]
fn verify_script_data_matches_real_onchain() {
    let tx = hex::decode(include_str!("test_data/tx_scripts/plutus_tx.hex").trim()).unwrap();
    let v1 = v1_costs();

    // Correct PlutusV1 cost model -> recomputed hash equals the on-chain field.
    let wire = cost_models_to_wire(&[(0u8, v1.clone())]);
    assert_eq!(verify_script_data(&tx, &wire), Ok(()));

    // One wrong cost entry -> mismatch.
    let mut bad = v1.clone();
    bad[0] += 1;
    assert_eq!(
        verify_script_data(&tx, &cost_models_to_wire(&[(0u8, bad)])),
        Err(TxParseError::ScriptDataMismatch),
    );

    // Wrong language id -> mismatch.
    assert_eq!(
        verify_script_data(&tx, &cost_models_to_wire(&[(2u8, v1)])),
        Err(TxParseError::ScriptDataMismatch),
    );

    // Malformed cost-model wire -> CostModelWire, never a panic.
    assert_eq!(
        verify_script_data(&tx, &[0xff]),
        Err(TxParseError::CostModelWire)
    );
    assert!(verify_script_data(&[0x00, 0x13], &[]).is_err());
}
