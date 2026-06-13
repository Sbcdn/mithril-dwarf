//! Byte-exact CBOR component location (§5), via pallas Conway `Tx` +
//! `KeepRaw` so each `component_bytes` is the ORIGINAL sub-slice of `tx_bytes`
//! (Plutus CBOR is non-canonical — the consumer re-hashes these exact bytes,
//! never a re-encoding). Scope is `T`-local (body + witness set); no ledger
//! recursion, no UTxO lookup, no redeemer->script resolution.
//!
//! Component types (§5 table): `0x01` redeemer, `0x02` inline datum,
//! `0x03` output datum-hash, `0x04` witness datum, `0x05` script.
//!
//! WIP: this lands incrementally. Currently emits `0x05` scripts; datums
//! (`0x02`/`0x03`/`0x04`), redeemers (`0x01`) and the `script_data_hash` binding
//! follow in the same module.

use pallas_codec::minicbor;
use pallas_primitives::conway::Tx;

use super::hashes::{ScriptLanguage, script_hash};

/// `tx_parsing` failure — wrong/garbage input, never a panic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxParseError {
    /// The transaction CBOR did not decode as a Conway transaction.
    Decode,
    /// The cost-model wire was malformed.
    CostModelWire,
    /// Recomputed `script_data_hash` did not match the transaction body's.
    ScriptDataMismatch,
}

// §5 type tags: 0x01 redeemer, 0x02 inline datum, 0x03 output datum-hash,
// 0x04 witness datum, 0x05 script. Added as each lands.
const C_SCRIPT: u8 = 0x05;

/// A located transaction component: a byte-exact sub-slice of `tx_bytes` plus a
/// type tag and a type-specific address (see §5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxComponent {
    pub component_type: u8,
    pub address: Vec<u8>,
    pub component_bytes: Vec<u8>,
}

/// Locate the in-scope components of a Cardano transaction. Returns `Err` on a
/// malformed transaction, never panics.
pub fn locate_tx_components(tx_bytes: &[u8]) -> Result<Vec<TxComponent>, TxParseError> {
    let tx: Tx = minicbor::decode(tx_bytes).map_err(|_| TxParseError::Decode)?;
    let mut out = Vec::new();
    extract_scripts(&tx, &mut out);
    Ok(out)
}

/// `0x05` script: `component_bytes = language_tag ‖ script_bytes`, so the address
/// is `blake2b224(component_bytes)` by construction (self-certifying). Native
/// scripts are hashed over their CBOR; Plutus over their raw bytes — pallas hands
/// the right form for each (`KeepRaw` vs raw).
fn push_script(out: &mut Vec<TxComponent>, lang: ScriptLanguage, script_bytes: &[u8]) {
    let mut component_bytes = Vec::with_capacity(1 + script_bytes.len());
    component_bytes.push(lang as u8);
    component_bytes.extend_from_slice(script_bytes);
    out.push(TxComponent {
        component_type: C_SCRIPT,
        address: script_hash(lang, script_bytes).to_vec(),
        component_bytes,
    });
}

fn extract_scripts(tx: &Tx, out: &mut Vec<TxComponent>) {
    let ws = &tx.transaction_witness_set;
    if let Some(v) = &ws.native_script {
        for s in v.iter() {
            push_script(out, ScriptLanguage::Native, s.raw_cbor());
        }
    }
    if let Some(v) = &ws.plutus_v1_script {
        for s in v.iter() {
            push_script(out, ScriptLanguage::PlutusV1, s.as_ref());
        }
    }
    if let Some(v) = &ws.plutus_v2_script {
        for s in v.iter() {
            push_script(out, ScriptLanguage::PlutusV2, s.as_ref());
        }
    }
    if let Some(v) = &ws.plutus_v3_script {
        for s in v.iter() {
            push_script(out, ScriptLanguage::PlutusV3, s.as_ref());
        }
    }
}
