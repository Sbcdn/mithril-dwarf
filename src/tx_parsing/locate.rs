//! Byte-exact CBOR component location (§5), via pallas Conway `Tx` +
//! `KeepRaw` so each `component_bytes` is the ORIGINAL sub-slice of `tx_bytes`
//! (Plutus CBOR is non-canonical — the consumer re-hashes these exact bytes,
//! never a re-encoding). Scope is `T`-local (body + witness set); no ledger
//! recursion, no UTxO lookup, no redeemer->script resolution.
//!
//! Component types (§5 table): `0x01` redeemer, `0x02` inline datum,
//! `0x03` output datum-hash, `0x04` witness datum, `0x05` script.
//!
//! WIP: lands incrementally. Currently emits `0x05` scripts and (with cost
//! models) `0x01` redeemers behind the `script_data_hash` binding; datums
//! (`0x02`/`0x03`/`0x04`) follow.

use pallas_codec::minicbor;
use pallas_primitives::conway::{PlutusData, RedeemerTag, Redeemers, Tx};

use super::hashes::{ScriptLanguage, script_hash};
use super::script_data::verify_decoded;

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

// §5 type tags: 0x02 inline datum, 0x03 output datum-hash, 0x04 witness datum
// added as each lands.
const C_REDEEMER: u8 = 0x01;
const C_SCRIPT: u8 = 0x05;

/// A located transaction component: a byte-exact sub-slice of `tx_bytes` plus a
/// type tag and a type-specific locator (see §5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxComponent {
    pub component_type: u8,
    pub locator: Vec<u8>,
    pub component_bytes: Vec<u8>,
}

/// Locate the in-scope components of a Cardano transaction. `0x05` scripts are
/// always emitted (txid/hash-authenticated). Witness-set components that are
/// only bound via `script_data_hash` — `0x01` redeemers — are emitted only when
/// `cost_models` is given: the binding is then verified first (folded in), so a
/// redeemer can't be emitted unless it is authentic. Returns `Err` on a
/// malformed transaction or a failed binding, never panics.
pub fn locate_tx_components(
    tx_bytes: &[u8],
    cost_models: Option<&[u8]>,
) -> Result<Vec<TxComponent>, TxParseError> {
    let tx: Tx = minicbor::decode(tx_bytes).map_err(|_| TxParseError::Decode)?;
    let mut out = Vec::new();
    extract_scripts(&tx, &mut out);
    if let Some(cost_models) = cost_models {
        verify_decoded(&tx, cost_models)?;
        extract_redeemers(&tx, &mut out)?;
    }
    Ok(out)
}

fn redeemer_tag(tag: &RedeemerTag) -> u8 {
    match tag {
        RedeemerTag::Spend => 0,
        RedeemerTag::Mint => 1,
        RedeemerTag::Cert => 2,
        RedeemerTag::Reward => 3,
        RedeemerTag::Vote => 4,
        RedeemerTag::Propose => 5,
    }
}

/// `0x01` redeemer: locator = `tag:u8 ‖ index:u32-le`; component_bytes = the
/// redeemer's data CBOR. pallas re-encodes the data, which is byte-exact here
/// because the folded `verify_decoded` proved the redeemers' encoding matches
/// the on-chain `script_data_hash`.
fn push_redeemer(
    out: &mut Vec<TxComponent>,
    tag: &RedeemerTag,
    index: u32,
    data: &PlutusData,
) -> Result<(), TxParseError> {
    let component_bytes = minicbor::to_vec(data).map_err(|_| TxParseError::Decode)?;
    let mut locator = Vec::with_capacity(5);
    locator.push(redeemer_tag(tag));
    locator.extend_from_slice(&index.to_le_bytes());
    out.push(TxComponent {
        component_type: C_REDEEMER,
        locator,
        component_bytes,
    });
    Ok(())
}

fn extract_redeemers(tx: &Tx, out: &mut Vec<TxComponent>) -> Result<(), TxParseError> {
    let Some(redeemers) = &tx.transaction_witness_set.redeemer else {
        return Ok(());
    };
    match &**redeemers {
        Redeemers::List(v) => {
            for r in v.iter() {
                push_redeemer(out, &r.tag, r.index, &r.data)?;
            }
        }
        Redeemers::Map(m) => {
            for (k, val) in m.iter() {
                push_redeemer(out, &k.tag, k.index, &val.data)?;
            }
        }
    }
    Ok(())
}

/// `0x05` script: `component_bytes = language_tag ‖ script_bytes`, so the locator
/// is `blake2b224(component_bytes)` by construction (self-certifying). Native
/// scripts are hashed over their CBOR; Plutus over their raw bytes — pallas hands
/// the right form for each (`KeepRaw` vs raw).
fn push_script(out: &mut Vec<TxComponent>, lang: ScriptLanguage, script_bytes: &[u8]) {
    let mut component_bytes = Vec::with_capacity(1 + script_bytes.len());
    component_bytes.push(lang as u8);
    component_bytes.extend_from_slice(script_bytes);
    out.push(TxComponent {
        component_type: C_SCRIPT,
        locator: script_hash(lang, script_bytes).to_vec(),
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
