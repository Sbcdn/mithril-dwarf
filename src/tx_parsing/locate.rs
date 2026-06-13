//! Byte-exact CBOR component location (§5), via pallas Conway `Tx` +
//! `KeepRaw` so each `component_bytes` is the ORIGINAL sub-slice of `tx_bytes`
//! (Plutus CBOR is non-canonical — the consumer re-hashes these exact bytes,
//! never a re-encoding). Scope is `T`-local (body + witness set); no ledger
//! recursion, no UTxO lookup, no redeemer->script resolution.
//!
//! Component types (§5 table): `0x01` redeemer, `0x02` inline datum,
//! `0x03` output datum-hash, `0x04` witness datum, `0x05` script.
//!
//! `0x02`/`0x03`/`0x05` are body/witness-resident (txid- or hash-authenticated)
//! and always emitted. `0x01`/`0x04` are bound only via `script_data_hash`, so
//! they are emitted only when `cost_models` is supplied and that binding verifies.

use std::collections::BTreeSet;

use pallas_codec::minicbor;
use pallas_primitives::babbage::{DatumOption, GenTransactionOutput};
use pallas_primitives::conway::{PlutusData, RedeemerTag, Redeemers, ScriptRef, Tx};

use super::hashes::{ScriptLanguage, datum_hash, script_hash};
use super::script_data::verify_decoded;
use super::txid::cardano_tx_id;

/// `tx_parsing` failure — wrong/garbage input, never a panic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxParseError {
    /// The transaction CBOR did not decode as a Conway transaction.
    Decode,
    /// `blake2b256(body)` did not equal the expected (proven) txid.
    TxidMismatch,
    /// The cost-model wire was malformed.
    CostModelWire,
    /// Recomputed `script_data_hash` did not match the transaction body's.
    ScriptDataMismatch,
}

const C_REDEEMER: u8 = 0x01;
const C_DATUM_INLINE: u8 = 0x02;
const C_DATUM_HASH: u8 = 0x03;
const C_WITNESS_DATUM: u8 = 0x04;
const C_SCRIPT: u8 = 0x05;

/// A located transaction component: a byte-exact sub-slice of `tx_bytes` plus a
/// type tag and a type-specific locator (see §5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxComponent {
    pub component_type: u8,
    pub locator: Vec<u8>,
    pub component_bytes: Vec<u8>,
}

/// Locate the in-scope components of a Cardano transaction.
///
/// The transaction is first bound to the proven `expected_txid`
/// (`blake2b256(body) == expected_txid`) — folded in so nothing is extracted
/// from a transaction that isn't the certified one. Scripts (`0x05`) and output
/// datums (`0x02`/`0x03`) are then always emitted (txid/hash-authenticated).
/// Witness-set components bound only via `script_data_hash` (`0x01` redeemers,
/// `0x04` witness datums) are emitted only when `cost_models` is given, after
/// that binding verifies. Returns `Err` on a malformed tx, a txid mismatch, or a
/// failed binding, never panics.
pub fn locate_tx_components(
    tx_bytes: &[u8],
    expected_txid: &[u8; 32],
    cost_models: Option<&[u8]>,
) -> Result<Vec<TxComponent>, TxParseError> {
    let tx: Tx = minicbor::decode(tx_bytes).map_err(|_| TxParseError::Decode)?;
    if cardano_tx_id(tx.transaction_body.raw_cbor()) != *expected_txid {
        return Err(TxParseError::TxidMismatch);
    }
    let mut out = Vec::new();
    extract_scripts(&tx, &mut out);
    extract_output_datums(&tx, &mut out);
    if let Some(cost_models) = cost_models {
        verify_decoded(&tx, cost_models)?;
        extract_redeemers(&tx, &mut out)?;
        extract_witness_datums(&tx, &mut out);
    }
    Ok(out)
}

/// `0x02` inline datum / `0x03` output datum-hash, keyed by output index. Both
/// live in the tx body's outputs, so the txid commits them directly — no cost
/// models / binding needed. The inline datum is the datum's own CBOR (the inner
/// `KeepRaw`, byte-exact), not the `#6.24(...)` wrapper.
fn extract_output_datums(tx: &Tx, out: &mut Vec<TxComponent>) {
    for (index, output) in tx.transaction_body.outputs.iter().enumerate() {
        let locator = (index as u32).to_le_bytes().to_vec();
        let datum = match output {
            GenTransactionOutput::PostAlonzo(o) => match o.datum_option.as_deref() {
                Some(DatumOption::Hash(h)) => Some((C_DATUM_HASH, h.to_vec())),
                Some(DatumOption::Data(d)) => Some((C_DATUM_INLINE, d.0.raw_cbor().to_vec())),
                None => None,
            },
            GenTransactionOutput::Legacy(o) => o.datum_hash.map(|h| (C_DATUM_HASH, h.to_vec())),
        };
        if let Some((component_type, component_bytes)) = datum {
            out.push(TxComponent {
                component_type,
                locator,
                component_bytes,
            });
        }
    }
}

/// `0x04` witness datum: component_bytes = the datum's original CBOR (`KeepRaw`,
/// byte-exact); locator = `blake2b256(component_bytes)` = the datum hash, so it's
/// self-certifying. Bound to the tx by `script_data_hash` (verified above).
fn extract_witness_datums(tx: &Tx, out: &mut Vec<TxComponent>) {
    if let Some(v) = &tx.transaction_witness_set.plutus_data {
        for d in v.iter() {
            let bytes = d.raw_cbor();
            out.push(TxComponent {
                component_type: C_WITNESS_DATUM,
                locator: datum_hash(bytes).to_vec(),
                component_bytes: bytes.to_vec(),
            });
        }
    }
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

/// `script_hash(lang, bytes)` of a reference script in an output.
fn script_ref_hash(sref: &ScriptRef) -> [u8; 28] {
    match sref {
        ScriptRef::NativeScript(s) => script_hash(ScriptLanguage::Native, s.raw_cbor()),
        ScriptRef::PlutusV1Script(s) => script_hash(ScriptLanguage::PlutusV1, s.as_ref()),
        ScriptRef::PlutusV2Script(s) => script_hash(ScriptLanguage::PlutusV2, s.as_ref()),
        ScriptRef::PlutusV3Script(s) => script_hash(ScriptLanguage::PlutusV3, s.as_ref()),
    }
}

/// The script hashes a witness script may legitimately match T-locally: mint
/// policy ids and output reference scripts, both committed by the txid. A witness
/// script whose hash is here can't have been substituted without a preimage
/// attack on the body.
fn bound_script_hashes(tx: &Tx) -> BTreeSet<[u8; 28]> {
    let mut set = BTreeSet::new();
    if let Some(mint) = &tx.transaction_body.mint {
        for (policy, _) in mint.iter() {
            set.insert(**policy);
        }
    }
    for output in tx.transaction_body.outputs.iter() {
        if let GenTransactionOutput::PostAlonzo(o) = output {
            if let Some(sref) = &o.script_ref {
                set.insert(script_ref_hash(&sref.0));
            }
        }
    }
    set
}

/// `0x05` script: `component_bytes = language_tag ‖ script_bytes`, so the locator
/// is `blake2b224(component_bytes)` by construction (self-certifying). Native
/// scripts are hashed over their CBOR; Plutus over their raw bytes — pallas hands
/// the right form for each (`KeepRaw` vs raw).
///
/// Only witness scripts whose hash is T-locally bound (a mint policy id or an
/// output reference script) are emitted — the witness set isn't in the txid
/// preimage, so an unbound script could be substituted. SPENDING scripts (whose
/// hash lives in the spent UTxO's credential) are NOT bound T-locally and are
/// therefore skipped here; proving them needs the input UTxOs (a separate proof,
/// out of `oaks_tx` scope).
fn push_bound_script(
    out: &mut Vec<TxComponent>,
    bound: &BTreeSet<[u8; 28]>,
    lang: ScriptLanguage,
    script_bytes: &[u8],
) {
    let hash = script_hash(lang, script_bytes);
    if !bound.contains(&hash) {
        return;
    }
    let mut component_bytes = Vec::with_capacity(1 + script_bytes.len());
    component_bytes.push(lang as u8);
    component_bytes.extend_from_slice(script_bytes);
    out.push(TxComponent {
        component_type: C_SCRIPT,
        locator: hash.to_vec(),
        component_bytes,
    });
}

fn extract_scripts(tx: &Tx, out: &mut Vec<TxComponent>) {
    let bound = bound_script_hashes(tx);
    let ws = &tx.transaction_witness_set;
    if let Some(v) = &ws.native_script {
        for s in v.iter() {
            push_bound_script(out, &bound, ScriptLanguage::Native, s.raw_cbor());
        }
    }
    if let Some(v) = &ws.plutus_v1_script {
        for s in v.iter() {
            push_bound_script(out, &bound, ScriptLanguage::PlutusV1, s.as_ref());
        }
    }
    if let Some(v) = &ws.plutus_v2_script {
        for s in v.iter() {
            push_bound_script(out, &bound, ScriptLanguage::PlutusV2, s.as_ref());
        }
    }
    if let Some(v) = &ws.plutus_v3_script {
        for s in v.iter() {
            push_bound_script(out, &bound, ScriptLanguage::PlutusV3, s.as_ref());
        }
    }
}
