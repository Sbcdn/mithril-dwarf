//! Adversarial gate for `tx-parsing`. The job here is to *break* the extractor —
//! to forge a component the bindings should have rejected. The invariant under
//! attack: a transaction's bound bytes are load-bearing, so no tampering yields a
//! different *accepted* output. Anything that changes a bound region must reject
//! (decode / txid / script_data), never silently mutate the extracted set.

use mithril_dwarf::tx_parsing::{
    TxParseError, cost_models_to_wire, locate_tx_components, verify_script_data,
};

const C_SCRIPT: u8 = 0x05;
const PLUTUS_TXID: &str = "f8f7f35d9d383db586f86cca89abe9cf1592b8c93e34146a6c6757261218cccb";

fn h32(s: &str) -> [u8; 32] {
    hex::decode(s).unwrap().try_into().unwrap()
}
fn plutus_tx() -> Vec<u8> {
    hex::decode(include_str!("test_data/tx_scripts/plutus_tx.hex").trim()).unwrap()
}
fn v1_costs() -> Vec<i64> {
    serde_json::from_str(include_str!("test_data/tx_scripts/epoch297_v1_costs.json")).unwrap()
}

/// Flip every byte of a real tx (under the real txid + cost models). The **bound**
/// components — body-resident `0x02`/`0x03` (txid-committed) and script_data-bound
/// `0x01`/`0x04` — must be tamper-proof: no single-byte mutation may forge a
/// different *accepted* bound component. Witness scripts (`0x05`) are excluded:
/// they are self-certifying but NOT bound to the proven tx (the witness set isn't
/// in the txid preimage, and spending-script credentials live in the spent UTxO,
/// out of T-local scope) — see the script-binding caveat. So a script swap is
/// *expected* to change the set; a bound-component change would be a soundness
/// hole.
fn bound(c: &mithril_dwarf::tx_parsing::TxComponent) -> bool {
    c.component_type != C_SCRIPT
}

#[test]
fn no_single_byte_mutation_forges_a_bound_component() {
    let tx = plutus_tx();
    let txid = h32(PLUTUS_TXID);
    let wire = cost_models_to_wire(&[(0u8, v1_costs())]);
    let baseline = locate_tx_components(&tx, &txid, Some(&wire)).expect("baseline");
    let want: Vec<_> = baseline.iter().filter(|c| bound(c)).cloned().collect();

    for i in 0..tx.len() {
        for b in [0x01u8, 0x55, 0xff] {
            let mut m = tx.clone();
            m[i] ^= b;
            let r = std::panic::catch_unwind(|| locate_tx_components(&m, &txid, Some(&wire)));
            match r {
                Ok(Ok(comps)) => {
                    let got: Vec<_> = comps.into_iter().filter(bound).collect();
                    assert_eq!(
                        got, want,
                        "byte {i} ^ {b:#x}: a BOUND component (0x01-0x04) was forged",
                    );
                }
                Ok(Err(_)) => {}
                Err(_) => panic!("panicked on byte {i} ^ {b:#x}"),
            }
        }
    }
}

/// A real tx's script_data verifies under its real cost model — and under no
/// other. Every single-byte tamper of the cost-model wire must reject (a wrong
/// cost model can never authenticate the redeemers/datums).
#[test]
fn no_cost_model_tamper_authenticates() {
    let tx = plutus_tx();
    let wire = cost_models_to_wire(&[(0u8, v1_costs())]);
    assert_eq!(
        verify_script_data(&tx, &wire),
        Ok(()),
        "real cost model must verify"
    );

    for i in 0..wire.len() {
        for b in [0x01u8, 0x80, 0xff] {
            let mut m = wire.clone();
            m[i] ^= b;
            assert_ne!(
                verify_script_data(&tx, &m),
                Ok(()),
                "tampered cost-model wire (byte {i} ^ {b:#x}) was accepted",
            );
        }
    }
    // Truncations (shorter than the real wire) reject too, never panic.
    for cut in 0..wire.len() {
        assert_ne!(verify_script_data(&tx, &wire[..cut]), Ok(()));
    }
    let mut overlong = wire.clone();
    overlong.push(0);
    assert_eq!(
        verify_script_data(&tx, &overlong),
        Err(TxParseError::CostModelWire)
    );
}

/// Wrong language id, extra language, dropped language — none may authenticate.
#[test]
fn no_language_set_confusion_authenticates() {
    let tx = plutus_tx();
    let v1 = v1_costs();
    // real: PlutusV1 only.
    assert_eq!(
        verify_script_data(&tx, &cost_models_to_wire(&[(0u8, v1.clone())])),
        Ok(())
    );
    // wrong language id with the same costs.
    assert_ne!(
        verify_script_data(&tx, &cost_models_to_wire(&[(1u8, v1.clone())])),
        Ok(())
    );
    assert_ne!(
        verify_script_data(&tx, &cost_models_to_wire(&[(2u8, v1.clone())])),
        Ok(())
    );
    // extra (spurious) language alongside the right one.
    assert_ne!(
        verify_script_data(
            &tx,
            &cost_models_to_wire(&[(0u8, v1.clone()), (1u8, v1.clone())])
        ),
        Ok(()),
    );
    // no languages at all.
    assert_ne!(verify_script_data(&tx, &cost_models_to_wire(&[])), Ok(()));
    // right costs but one entry short / one entry long.
    let mut short = v1.clone();
    short.pop();
    assert_ne!(
        verify_script_data(&tx, &cost_models_to_wire(&[(0u8, short)])),
        Ok(())
    );
    let mut long = v1;
    long.push(0);
    assert_ne!(
        verify_script_data(&tx, &cost_models_to_wire(&[(0u8, long)])),
        Ok(())
    );
}
