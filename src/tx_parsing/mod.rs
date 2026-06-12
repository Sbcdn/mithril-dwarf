//! Cardano transaction parsing for the `oaks_tx` guest.
//!
//! Phase A (this module): the transaction-id hasher. The host slices the
//! transaction body's raw CBOR bytes; the guest hashes them. The resulting id
//! is what the inclusion proof's leaf binds, so a wrong host slice yields a
//! wrong id and `verify_tx_inclusion*` rejects — safe by construction.

mod txid;

pub use txid::cardano_tx_id;
