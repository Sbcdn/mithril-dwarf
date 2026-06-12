//! `cardano_tx_id` pinned to real mainnet transactions.
//!
//! The transaction id is `blake2b256(body)` where `body` is the raw CBOR of the
//! transaction body (element 0 of the tx array). Each fixture is that exact body
//! slice (extracted from the on-chain CBOR fetched from Koios); the assertion is
//! that dwarf's hasher reproduces the canonical on-chain txid.

use mithril_dwarf::tx_parsing::cardano_tx_id;

fn h32(s: &str) -> [u8; 32] {
    let v = hex::decode(s).unwrap();
    let mut a = [0u8; 32];
    a.copy_from_slice(&v);
    a
}

fn check(txid: &str, body_hex: &str) {
    let body = hex::decode(body_hex.trim()).unwrap();
    assert_eq!(cardano_tx_id(&body), h32(txid), "txid mismatch for {txid}");
}

#[test]
fn cardano_tx_id_matches_real_mainnet_txids() {
    check(
        "1d013efbd0f784f801cc3542605f4dcedbc45c01e10c625124eea505158d546b",
        include_str!(
            "test_data/tx_cbor/1d013efbd0f784f801cc3542605f4dcedbc45c01e10c625124eea505158d546b.body.hex"
        ),
    );
    check(
        "9dad0d7f6bf1e793f2572ff96337d7dc30ef554c1c0687e66cfe3855a458f503",
        include_str!(
            "test_data/tx_cbor/9dad0d7f6bf1e793f2572ff96337d7dc30ef554c1c0687e66cfe3855a458f503.body.hex"
        ),
    );
    check(
        "fdb2d9b874ef322540a402fb83c2541f67b32451c4983af2d27e4217bc4b8559",
        include_str!(
            "test_data/tx_cbor/fdb2d9b874ef322540a402fb83c2541f67b32451c4983af2d27e4217bc4b8559.body.hex"
        ),
    );
}
