//! Cardano transaction parsing for the `oaks_tx` guest.
//!
//! - [`cardano_tx_id`] — txid = `blake2b256` of the host-sliced body CBOR. The
//!   id is what the inclusion proof's leaf binds, so a wrong host slice yields a
//!   wrong id and `verify_tx_inclusion*` rejects — safe by construction.
//! - [`script_hash`] / [`datum_hash`] — the `0x05` script / datum leaf hashes.
//!
//! [`cardano_tx_id`] / [`script_hash`] / [`datum_hash`] are blake2b only (no CBOR
//! parse, no pallas). [`locate_tx_components`] (feature `tx-components`) decodes
//! the tx CBOR with pallas + `KeepRaw` and feeds these the exact byte slices.

mod hashes;
#[cfg(feature = "tx-components")]
mod locate;
mod txid;

pub use hashes::{ScriptLanguage, datum_hash, script_hash};
#[cfg(feature = "tx-components")]
pub use locate::{TxComponent, TxParseError, locate_tx_components};
pub use txid::cardano_tx_id;
