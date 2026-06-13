//! Cardano transaction parsing for the `oaks_tx` guest.
//!
//! - [`cardano_tx_id`] — txid = `blake2b256` of the host-sliced body CBOR. The
//!   id is what the inclusion proof's leaf binds, so a wrong host slice yields a
//!   wrong id and `verify_tx_inclusion*` rejects — safe by construction.
//! - [`script_hash`] / [`datum_hash`] — the `0x05` script / datum leaf hashes.
//!
//! All blake2b only (no CBOR parse, no pallas). The CBOR component locator that
//! feeds these the exact byte slices lands under a separate feature.

mod hashes;
mod txid;

pub use hashes::{ScriptLanguage, datum_hash, script_hash};
pub use txid::cardano_tx_id;
