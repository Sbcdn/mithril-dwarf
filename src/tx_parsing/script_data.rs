//! `script_data_hash` (scriptIntegrityHash) recompute + verify.
//!
//! `script_data_hash = blake2b256(redeemers ‖ datums ‖ language_views)` is a tx
//! body field; since the txid commits the body, it's the only thing binding the
//! witness-set redeemers/datums to the proven transaction. We recompute it with
//! pallas's own [`ScriptData::build_for`]/`hash` — the authoritative encoding,
//! including the intricate `language_views` layout (PlutusV1 key `0x4100`, costs
//! as an indefinite array wrapped in a bytestring, V1 ordered last) — so it's
//! upstream-exact by construction, not a re-port.
//!
//! Cost models are an untrusted public input (the host can source them from any
//! epoch params): a wrong model fails this preimage check, so it authenticates
//! itself — passing ⟹ genuine redeemers + datums + cost models.

use pallas_codec::minicbor;
use pallas_primitives::conway::{LanguageViews, ScriptData, Tx};

use super::locate::TxParseError;

/// Cost-model wire (dwarf-defined; the host builds it via [`cost_models_to_wire`]
/// so it can't get the layout wrong — pallas does the language-views CBOR):
/// `u8 lang_count`, then per language `u8 lang_id, u32 cost_count, cost_count × i64-le`.
const MAX_LANGS: usize = 8;
const MAX_COSTS: usize = 4096;

fn take<'a>(wire: &'a [u8], pos: &mut usize, n: usize) -> Result<&'a [u8], TxParseError> {
    let end = pos.checked_add(n).ok_or(TxParseError::CostModelWire)?;
    let s = wire.get(*pos..end).ok_or(TxParseError::CostModelWire)?;
    *pos = end;
    Ok(s)
}

fn decode_cost_models(wire: &[u8]) -> Result<LanguageViews, TxParseError> {
    let mut pos = 0usize;
    let lang_count = take(wire, &mut pos, 1)?[0] as usize;
    if lang_count > MAX_LANGS {
        return Err(TxParseError::CostModelWire);
    }
    let mut models: Vec<(u8, Vec<i64>)> = Vec::with_capacity(lang_count);
    for _ in 0..lang_count {
        let lang = take(wire, &mut pos, 1)?[0];
        let cost_count = u32::from_le_bytes(
            take(wire, &mut pos, 4)?
                .try_into()
                .map_err(|_| TxParseError::CostModelWire)?,
        ) as usize;
        if cost_count > MAX_COSTS {
            return Err(TxParseError::CostModelWire);
        }
        // Reserve no more than the remaining bytes can hold (8 per cost), so a
        // forged count can't amplify a few bytes into a large allocation.
        let mut costs = Vec::with_capacity(cost_count.min((wire.len() - pos) / 8));
        for _ in 0..cost_count {
            costs.push(i64::from_le_bytes(
                take(wire, &mut pos, 8)?
                    .try_into()
                    .map_err(|_| TxParseError::CostModelWire)?,
            ));
        }
        models.push((lang, costs));
    }
    if pos != wire.len() {
        return Err(TxParseError::CostModelWire);
    }
    Ok(LanguageViews::from_iter(models))
}

/// Verify a transaction's `script_data_hash` against the given cost models: the
/// recomputed hash must equal the body field. If the body has no
/// `script_data_hash`, the witness set must carry no redeemers or datums. Any
/// mismatch / malformed input is an `Err`, never a panic.
pub fn verify_script_data(tx_bytes: &[u8], cost_models: &[u8]) -> Result<(), TxParseError> {
    let tx: Tx = minicbor::decode(tx_bytes).map_err(|_| TxParseError::Decode)?;
    verify_decoded(&tx, cost_models)
}

/// Same check on an already-decoded `Tx`, so the locator doesn't decode twice.
pub(super) fn verify_decoded(tx: &Tx, cost_models: &[u8]) -> Result<(), TxParseError> {
    match tx.transaction_body.script_data_hash {
        Some(provided) => {
            let language_views = decode_cost_models(cost_models)?;
            let script_data =
                ScriptData::build_for(&tx.transaction_witness_set, &Some(language_views))
                    .ok_or(TxParseError::ScriptDataMismatch)?;
            if script_data.hash() == provided {
                Ok(())
            } else {
                Err(TxParseError::ScriptDataMismatch)
            }
        }
        None => {
            let ws = &tx.transaction_witness_set;
            if ws.redeemer.is_some() || ws.plutus_data.is_some() {
                Err(TxParseError::ScriptDataMismatch)
            } else {
                Ok(())
            }
        }
    }
}

/// Host-side encoder for the cost-model wire `verify_script_data` consumes. The
/// host supplies each language's ordered cost-model integer array (e.g. from the
/// epoch protocol params); dwarf owns the wire so the guest decodes it for sure.
#[cfg(feature = "host")]
pub fn cost_models_to_wire(models: &[(u8, Vec<i64>)]) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(models.len() as u8);
    for (lang, costs) in models {
        out.push(*lang);
        out.extend_from_slice(&(costs.len() as u32).to_le_bytes());
        for c in costs {
            out.extend_from_slice(&c.to_le_bytes());
        }
    }
    out
}
