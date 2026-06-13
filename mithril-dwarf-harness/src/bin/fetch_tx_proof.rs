//! Fetches a real Cardano-transaction inclusion proof (MKMapProof) + the
//! certified merkle root from the mainnet aggregator, for the tx-inclusion
//! equivalence vector. Uses the v1 `/proof/cardano-transaction` endpoint (what
//! the public mainnet aggregator serves; the v2 path is `unstable` and not
//! served there). The proof CONTENT is the same `MKMapProof` either way — only
//! the encoding differs (v1 = json-hex), which is fine for an equivalence vector.
//!
//! Writes `tests/test_data/tx_proofs/mainnet_proof.json` + `mainnet_root.hex`.

use anyhow::{Result, anyhow};
use mithril_client::{Client, ClientBuilder};
use std::fs;
use std::path::PathBuf;

const MAINNET_AGGREGATOR: &str =
    "https://aggregator.release-mainnet.api.mithril.network/aggregator";
const MAINNET_GENESIS_KEY: &str = "5b3139312c36362c3134302c3138352c3133382c31312c3233372c3230372c3235302c3134342c32372c322c3138382c33302c31322c38312c3135352c3230342c31302c3137392c37352c32332c3133382c3139362c3231372c352c31342c32302c35372c37392c33392c3137365d";

const TXS: &[&str] = &[
    "1d013efbd0f784f801cc3542605f4dcedbc45c01e10c625124eea505158d546b",
    "9dad0d7f6bf1e793f2572ff96337d7dc30ef554c1c0687e66cfe3855a458f503",
    "fdb2d9b874ef322540a402fb83c2541f67b32451c4983af2d27e4217bc4b8559",
];

#[tokio::main]
async fn main() -> Result<()> {
    let client: Client = ClientBuilder::aggregator(MAINNET_AGGREGATOR, MAINNET_GENESIS_KEY)
        .build()
        .map_err(|e| anyhow!("client build: {e}"))?;

    println!(
        "Fetching /proof/cardano-transaction for {} txs ...",
        TXS.len()
    );
    let proofs = client
        .cardano_transaction()
        .get_proofs(TXS)
        .await
        .map_err(|e| anyhow!("get_proofs: {e}"))?;

    println!("certificate_hash: {}", proofs.certificate_hash);
    println!("non_certified:    {:?}", proofs.non_certified_transactions);
    println!("certified parts:  {}", proofs.certified_transactions.len());

    let part = proofs
        .certified_transactions
        .first()
        .ok_or_else(|| anyhow!("no certified_transactions in proof message"))?;
    println!("certified hashes: {:?}", part.transactions_hashes);

    // v1 proof = hex(JSON(MKMapProof)); decode the hex to the JSON bytes.
    let proof_json = hex::decode(&part.proof).map_err(|e| anyhow!("proof hex: {e}"))?;
    println!("MKMapProof json:  {} bytes", proof_json.len());

    // Certified root: verify() reconstructs it; read it out of the protocol message.
    use mithril_common::entities::{ProtocolMessage, ProtocolMessagePartKey};
    let verified = proofs
        .verify()
        .map_err(|e| anyhow!("upstream verify: {e}"))?;
    let mut pmsg = ProtocolMessage::new();
    verified.fill_protocol_message(&mut pmsg);
    let merkle_root = pmsg
        .get_message_part(&ProtocolMessagePartKey::CardanoTransactionsMerkleRoot)
        .ok_or_else(|| anyhow!("no merkle root in protocol message"))?
        .clone();
    println!("certified merkle_root: {merkle_root}");

    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/test_data/tx_proofs");
    fs::create_dir_all(&dir)?;
    fs::write(dir.join("mainnet_proof.json"), &proof_json)?;
    fs::write(dir.join("mainnet_root.hex"), merkle_root.as_bytes())?;
    fs::write(
        dir.join("mainnet_txs.txt"),
        part.transactions_hashes.join("\n"),
    )?;
    println!("wrote {} (proof.json, root.hex, txs.txt)", dir.display());
    Ok(())
}
