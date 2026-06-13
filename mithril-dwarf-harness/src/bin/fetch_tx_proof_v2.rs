//! Fetches a real **v2** (`CardanoBlocksTransactions`) inclusion proof + the
//! certified `cardano_blocks_transactions_merkle_root` from the testing-preview
//! aggregator (the only network that serves the v2 endpoint), for the
//! tx-inclusion equivalence vector.
//!
//! The v2 proof is bincode (`hex(MKMapProof::to_bytes())`) and the message
//! carries the composite-leaf block fields. We GET the proof + its certificate
//! directly (the SDK's v2 verify path needs the preview genesis chain), and
//! write the same three fixtures the oracle reads.
//!
//! Re-running regenerates a fresh, self-consistent vector (the live preview tree
//! advances), so re-commit `preview_v2_proof.bin` + `preview_v2_root.hex` +
//! `preview_v2_tx.txt` together and update the test's expected root.
//!
//! Writes `tests/test_data/tx_proofs/preview_v2_{proof.bin,root.hex,tx.txt}`.

use anyhow::{Result, anyhow};
use serde_json::Value;
use std::fs;
use std::path::PathBuf;

const PREVIEW_AGGREGATOR: &str =
    "https://aggregator.testing-preview.api.mithril.network/aggregator";

/// A preview tx known to be in the `CardanoBlocksTransactions` tree. If the
/// preview chain has pruned it, swap for any recent preview txid.
const TX: &str = "5634d3558843a76a23d554b218b6316c624968d54abe8942bb8f55a29f252f58";

async fn get_json(url: &str) -> Result<Value> {
    let resp = reqwest::get(url)
        .await
        .map_err(|e| anyhow!("GET {url}: {e}"))?;
    if !resp.status().is_success() {
        return Err(anyhow!("GET {url}: status {}", resp.status()));
    }
    resp.json().await.map_err(|e| anyhow!("decode {url}: {e}"))
}

#[tokio::main]
async fn main() -> Result<()> {
    let proof_url =
        format!("{PREVIEW_AGGREGATOR}/proof/v2/cardano-transaction?transaction_hashes={TX}");
    println!("GET {proof_url}");
    let proof = get_json(&proof_url).await?;

    let cert_hash = proof["certificate_hash"]
        .as_str()
        .ok_or_else(|| anyhow!("no certificate_hash"))?;
    let ct = &proof["certified_transactions"];
    let item = ct["items"]
        .get(0)
        .ok_or_else(|| anyhow!("no certified tx items (tx not in v2 tree?)"))?;
    let proof_hex = ct["proof"]
        .as_str()
        .ok_or_else(|| anyhow!("no proof hex"))?;

    let tx_hash = item["transaction_hash"].as_str().unwrap_or_default();
    let block_hash = item["block_hash"].as_str().unwrap_or_default();
    let block_number = item["block_number"].as_u64().unwrap_or_default();
    let slot_number = item["slot_number"].as_u64().unwrap_or_default();

    println!("certificate_hash: {cert_hash}");
    println!("tx: {tx_hash} block {block_number} slot {slot_number} block_hash {block_hash}");

    let proof_bytes = hex::decode(proof_hex).map_err(|e| anyhow!("proof hex: {e}"))?;
    println!("MKMapProof bincode: {} bytes", proof_bytes.len());

    let cert_url = format!("{PREVIEW_AGGREGATOR}/certificate/{cert_hash}");
    println!("GET {cert_url}");
    let cert = get_json(&cert_url).await?;
    let root = cert["protocol_message"]["message_parts"]["cardano_blocks_transactions_merkle_root"]
        .as_str()
        .ok_or_else(|| anyhow!("no cardano_blocks_transactions_merkle_root in cert message"))?;
    println!("certified root: {root}");

    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/test_data/tx_proofs");
    fs::create_dir_all(&dir)?;
    fs::write(dir.join("preview_v2_proof.bin"), &proof_bytes)?;
    fs::write(dir.join("preview_v2_root.hex"), root)?;
    fs::write(
        dir.join("preview_v2_tx.txt"),
        format!("{tx_hash} {block_hash} {block_number} {slot_number}\n"),
    )?;
    println!(
        "wrote {} (preview_v2_proof.bin, root.hex, tx.txt)",
        dir.display()
    );
    Ok(())
}
