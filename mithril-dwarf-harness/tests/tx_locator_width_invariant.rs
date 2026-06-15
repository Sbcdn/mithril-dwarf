//! Ratified invariant: every `TxComponent.locator` is fixed-width per
//! `component_type`. oakshield's typed commitment tree builds a leaf as
//! `blake2b256(0x00 ‖ type ‖ locator ‖ blake2b256(component_bytes))` with the
//! locator UNPREFIXED, immediately followed by a 32-byte hash. That is
//! second-preimage-safe only because each type's locator has a fixed width — a
//! variable-width locator would let two distinct `(type, locator)` pairs alias
//! across the concatenation and forge a colliding leaf.
//!
//! This pins the widths over live data so any future type with a
//! variable/content-dependent locator trips here, before it can reach a
//! downstream consumer that froze the unprefixed-locator leaf shape.

use std::collections::BTreeSet;

use mithril_dwarf::tx_parsing::{cost_models_to_wire, locate_tx_components};

/// The ratified width table. An unknown type panics so a newly added component
/// type cannot ship without explicitly extending (or self-delimiting) here.
fn expected_locator_width(component_type: u8) -> usize {
    match component_type {
        0x01 => 5,  // redeemer:      tag:u8 ‖ index:u32-le
        0x02 => 4,  // inline datum:  output index:u32-le
        0x03 => 4,  // datum hash:    output index:u32-le
        0x04 => 32, // witness datum: blake2b256(datum)
        0x05 => 28, // script:        blake2b224 script hash
        other => panic!(
            "unknown component_type 0x{other:02x}: the locator-width invariant \
             must be extended (or the new locator made self-delimiting) before \
             the unprefixed-locator leaf shape can stay second-preimage-safe"
        ),
    }
}

fn h32(s: &str) -> [u8; 32] {
    hex::decode(s.trim()).unwrap().try_into().unwrap()
}

fn assert_widths(comps: &[mithril_dwarf::tx_parsing::TxComponent], seen: &mut BTreeSet<u8>, ctx: &str) {
    for c in comps {
        assert_eq!(
            c.locator.len(),
            expected_locator_width(c.component_type),
            "{ctx}: type 0x{:02x} locator is {} bytes, invariant says {}",
            c.component_type,
            c.locator.len(),
            expected_locator_width(c.component_type),
        );
        seen.insert(c.component_type);
    }
}

#[test]
fn every_emitted_locator_is_fixed_width_per_type() {
    let mut seen: BTreeSet<u8> = BTreeSet::new();

    // Body-resident types (0x02 / 0x03 / 0x05) over the full real-tx corpus.
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/test_data/tx_corpus");
    let mut n = 0;
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_stem().unwrap().to_str().unwrap().to_string();
        let txid = h32(&name);
        let tx = hex::decode(std::fs::read_to_string(&path).unwrap().trim()).unwrap();
        let comps = locate_tx_components(&tx, &txid, None)
            .unwrap_or_else(|e| panic!("locate {name}: {e:?}"));
        assert_widths(&comps, &mut seen, &name);
        n += 1;
    }
    assert!(n >= 30, "corpus too small ({n})");

    // 0x01 redeemers: the plutus_tx fixture behind its script_data binding.
    let tx = hex::decode(include_str!("test_data/tx_scripts/plutus_tx.hex").trim()).unwrap();
    let txid = h32("f8f7f35d9d383db586f86cca89abe9cf1592b8c93e34146a6c6757261218cccb");
    let v1: Vec<i64> =
        serde_json::from_str(include_str!("test_data/tx_scripts/epoch297_v1_costs.json")).unwrap();
    let comps = locate_tx_components(&tx, &txid, Some(&cost_models_to_wire(&[(0u8, v1)])))
        .expect("locate plutus_tx with cost models");
    assert_widths(&comps, &mut seen, "plutus_tx");

    // 0x04 witness datum: the datum_tx fixture behind its script_data binding.
    let tx = hex::decode(include_str!("test_data/tx_scripts/datum_tx.hex").trim()).unwrap();
    let txid = h32("fe79a789efb774f97df074d3c9ff9228316e2f26e9e37d2a9831f5a32971d863");
    let v1: Vec<i64> = serde_json::from_str(include_str!(
        "test_data/tx_scripts/datum_tx_epoch327_v1_costs.json"
    ))
    .unwrap();
    let comps = locate_tx_components(&tx, &txid, Some(&cost_models_to_wire(&[(0u8, v1)])))
        .expect("locate datum_tx with cost models");
    assert_widths(&comps, &mut seen, "datum_tx");

    // 0x02 inline output datums: the output_datum_tx fixture (body-resident).
    let tx = hex::decode(include_str!("test_data/tx_scripts/output_datum_tx.hex").trim()).unwrap();
    let txid = h32("8ecb7f970bd3eebada2d98b3e59f34f6ecf10cc708bdcd92a1dac0900205ea8d");
    let comps = locate_tx_components(&tx, &txid, None).expect("locate output_datum_tx");
    assert_widths(&comps, &mut seen, "output_datum_tx");

    // The invariant must be non-vacuous: every type was actually observed and
    // width-checked against live data, not just declared in the table.
    let expected: BTreeSet<u8> = [0x01, 0x02, 0x03, 0x04, 0x05].into_iter().collect();
    assert_eq!(
        seen, expected,
        "not all component types were exercised; observed {seen:?}, want {expected:?}"
    );
}
