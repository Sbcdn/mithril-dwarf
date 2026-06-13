//! `locate_tx_components` against real txs (Koios `/tx_cbor`). Each component's
//! bytes are a byte-exact sub-slice of the tx CBOR; hash locators (`0x04`/`0x05`)
//! equal the real on-chain hash; the tx is bound to its proven txid, and
//! `0x01`/`0x04` sit behind the verified `script_data_hash` binding. Covers all
//! five §5 component types.

use mithril_dwarf::tx_parsing::{
    ScriptLanguage, TxParseError, cost_models_to_wire, datum_hash, locate_tx_components,
    script_hash,
};

const C_REDEEMER: u8 = 0x01;
const C_DATUM_INLINE: u8 = 0x02;
const C_DATUM_HASH: u8 = 0x03;
const C_WITNESS_DATUM: u8 = 0x04;
const C_SCRIPT: u8 = 0x05;

// On-chain txids of the fixtures (the hashes they were fetched by).
const PLUTUS_TXID: &str = "f8f7f35d9d383db586f86cca89abe9cf1592b8c93e34146a6c6757261218cccb";
const DATUM_TXID: &str = "fe79a789efb774f97df074d3c9ff9228316e2f26e9e37d2a9831f5a32971d863";
const OUTPUT_DATUM_TXID: &str = "8ecb7f970bd3eebada2d98b3e59f34f6ecf10cc708bdcd92a1dac0900205ea8d";

fn h32(s: &str) -> [u8; 32] {
    hex::decode(s).unwrap().try_into().unwrap()
}

fn v1_costs() -> Vec<i64> {
    serde_json::from_str(include_str!("test_data/tx_scripts/epoch297_v1_costs.json")).unwrap()
}

#[test]
fn locate_extracts_bound_mint_script() {
    // A native minting script: its hash IS a mint policy id in the body, so it's
    // T-locally bound and emitted as a `0x05` component.
    let tx = hex::decode(include_str!("test_data/tx_scripts/mint_tx.hex").trim()).unwrap();
    let txid = h32(include_str!("test_data/tx_scripts/mint_tx_txid.hex").trim());
    let policy = include_str!("test_data/tx_scripts/mint_tx_policy.hex").trim();

    let components = locate_tx_components(&tx, &txid, None).expect("locate mint tx");
    let scripts: Vec<_> = components
        .iter()
        .filter(|c| c.component_type == C_SCRIPT)
        .collect();
    assert_eq!(scripts.len(), 1, "expected the bound native mint script");

    let s = scripts[0];
    assert_eq!(
        s.component_bytes[0],
        ScriptLanguage::Native as u8,
        "wrong language tag"
    );
    let script_bytes = &s.component_bytes[1..];
    assert!(
        tx.windows(script_bytes.len()).any(|w| w == script_bytes),
        "script bytes are not a sub-slice of tx_bytes",
    );
    assert_eq!(hex::encode(&s.locator), policy, "locator != mint policy id");
    assert_eq!(
        script_hash(ScriptLanguage::Native, script_bytes).to_vec(),
        s.locator,
        "locator != blake2b224(0x00 ‖ native_cbor)",
    );
}

#[test]
fn locate_binds_to_expected_txid() {
    let tx = hex::decode(include_str!("test_data/tx_scripts/plutus_tx.hex").trim()).unwrap();
    // Correct txid: succeeds.
    assert!(locate_tx_components(&tx, &h32(PLUTUS_TXID), None).is_ok());
    // Any other txid: the folded binding rejects before extracting anything.
    let mut wrong = h32(PLUTUS_TXID);
    wrong[0] ^= 1;
    assert_eq!(
        locate_tx_components(&tx, &wrong, None),
        Err(TxParseError::TxidMismatch),
    );
}

#[test]
fn locate_extracts_real_redeemers_behind_binding() {
    let tx = hex::decode(include_str!("test_data/tx_scripts/plutus_tx.hex").trim()).unwrap();
    let txid = h32(PLUTUS_TXID);
    let wire = cost_models_to_wire(&[(0u8, v1_costs())]);

    let components =
        locate_tx_components(&tx, &txid, Some(&wire)).expect("locate with cost models");
    let redeemers: Vec<_> = components
        .iter()
        .filter(|c| c.component_type == C_REDEEMER)
        .collect();
    assert!(!redeemers.is_empty(), "expected at least one redeemer");
    for r in &redeemers {
        assert_eq!(r.locator.len(), 5, "redeemer locator must be 5 bytes");
        assert!(
            tx.windows(r.component_bytes.len())
                .any(|w| w == r.component_bytes),
            "redeemer data is not a sub-slice of tx_bytes",
        );
    }

    // Without cost models: no redeemers emitted (only txid-authenticated parts).
    let no_cm = locate_tx_components(&tx, &txid, None).unwrap();
    assert!(no_cm.iter().all(|c| c.component_type != C_REDEEMER));

    // Wrong cost model: the folded binding fails.
    let mut bad = v1_costs();
    bad[0] += 1;
    assert!(locate_tx_components(&tx, &txid, Some(&cost_models_to_wire(&[(0u8, bad)]))).is_err());
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

    let components =
        locate_tx_components(&tx, &h32(DATUM_TXID), Some(&wire)).expect("locate datum tx");
    let datums: Vec<_> = components
        .iter()
        .filter(|c| c.component_type == C_WITNESS_DATUM)
        .collect();
    assert_eq!(datums.len(), 1, "expected one witness datum");

    let d = datums[0];
    assert!(
        tx.windows(d.component_bytes.len())
            .any(|w| w == d.component_bytes),
        "datum is not a sub-slice of tx_bytes",
    );
    assert_eq!(
        hex::encode(&d.locator),
        onchain,
        "locator != on-chain datum hash"
    );
    assert_eq!(
        datum_hash(&d.component_bytes).to_vec(),
        d.locator,
        "locator != blake2b256(datum)"
    );
}

#[test]
fn locate_extracts_real_output_datums() {
    let tx = hex::decode(include_str!("test_data/tx_scripts/output_datum_tx.hex").trim()).unwrap();
    // Output datums are body-resident (txid-committed) — no cost models needed.
    let components = locate_tx_components(&tx, &h32(OUTPUT_DATUM_TXID), None).expect("locate");

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
        assert_eq!(c.locator.len(), 4, "output-datum locator is a u32 index");
        assert!(
            tx.windows(c.component_bytes.len())
                .any(|w| w == c.component_bytes),
            "output datum is not a sub-slice of tx_bytes",
        );
    }
    assert_eq!(dhash[0].component_bytes.len(), 32);
}

#[test]
fn locate_rejects_garbage() {
    let any = [0u8; 32];
    assert!(locate_tx_components(&[0xff, 0x00, 0x13], &any, None).is_err());
    assert!(locate_tx_components(&[], &any, None).is_err());
}

/// Panic-safety: mutating / truncating a real tx must return (Ok/Err), never
/// panic the pallas decoder.
#[test]
fn locate_never_panics_on_mutated_tx() {
    let tx = hex::decode(include_str!("test_data/tx_scripts/plutus_tx.hex").trim()).unwrap();
    let txid = h32(PLUTUS_TXID);
    for i in (0..tx.len()).step_by(7) {
        for b in [0x01u8, 0x80, 0xff] {
            let mut m = tx.clone();
            m[i] ^= b;
            let r = std::panic::catch_unwind(|| locate_tx_components(&m, &txid, None));
            assert!(r.is_ok(), "panicked on byte-{i} mutation {b:#x}");
        }
    }
    for cut in (0..tx.len()).step_by(11) {
        let r = std::panic::catch_unwind(|| locate_tx_components(&tx[..cut], &txid, None));
        assert!(r.is_ok(), "panicked on truncation at {cut}");
    }
}
