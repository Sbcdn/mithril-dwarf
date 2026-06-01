//! Certificate Chain Fetcher
//!
//! Fetches a certificate chain from Mithril aggregator and stores them as bincode files.
//! Starts from a given certificate hash and walks backward to genesis.
//!
//! Usage:
//!   cargo run --bin fetch_certificates -- \
//!       --network mainnet \
//!       --certificate-hash <hash>

use anyhow::{Result, anyhow};
use clap::Parser;
use mithril_client::{Client, ClientBuilder, MithrilCertificate};
use mithril_common::messages::CertificateMessage;
use std::fs;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Network to fetch from (mainnet, preprod, preview)
    #[arg(long, default_value = "mainnet")]
    network: String,

    /// Starting certificate hash (walks backward from here to genesis)
    #[arg(long)]
    certificate_hash: String,

    /// Output directory for certificate files
    #[arg(
        long,
        default_value = "mithril-dwarf-harness/tests/test_data/certificates"
    )]
    output_dir: PathBuf,

    /// Maximum certificates to fetch (safety limit)
    #[arg(long, default_value = "1000")]
    max_certificates: usize,
}

#[derive(Debug, Clone)]
pub enum Network {
    Preview,
    Preprod,
    Mainnet,
}

impl Network {
    pub fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "preview" => Ok(Self::Preview),
            "preprod" => Ok(Self::Preprod),
            "mainnet" => Ok(Self::Mainnet),
            _ => Err(anyhow!(
                "Unknown network: {}. Use: mainnet, preprod, or preview",
                s
            )),
        }
    }

    pub fn get_genesis_key(&self) -> &str {
        match self {
            Self::Preview | Self::Preprod => {
                "5b3132372c37332c3132342c3136312c362c3133372c3133312c3231332c3230372c3131372c3139382c38352c3137362c3139392c3136322c3234312c36382c3132332c3131392c3134352c31332c3233322c3234332c34392c3232392c322c3234392c3230352c3230352c33392c3233352c34345d"
            }
            Self::Mainnet => {
                "5b3139312c36362c3134302c3138352c3133382c31312c3233372c3230372c3235302c3134342c32372c322c3138382c33302c31322c38312c3135352c3230342c31302c3137392c37352c32332c3133382c3139362c3231372c352c31342c32302c35372c37392c33392c3137365d"
            }
        }
    }

    pub fn get_aggregator_url(&self) -> &str {
        match self {
            Self::Preview => {
                "https://aggregator.pre-release-preview.api.mithril.network/aggregator"
            }
            Self::Preprod => "https://aggregator.release-preprod.api.mithril.network/aggregator",
            Self::Mainnet => "https://aggregator.release-mainnet.api.mithril.network/aggregator",
        }
    }
}

fn make_mithril_client(network: &Network) -> Result<Client> {
    ClientBuilder::aggregator(network.get_aggregator_url(), network.get_genesis_key())
        .build()
        .map_err(|e| anyhow!("Failed to create Mithril client: {}", e))
}

async fn get_certificate(
    client: &Client,
    certificate_hash: &str,
) -> Result<Option<MithrilCertificate>> {
    client
        .certificate()
        .get(certificate_hash)
        .await
        .map_err(|e| anyhow!("Failed to fetch certificate {}: {}", certificate_hash, e))
}

fn is_genesis_certificate(cert: &CertificateMessage) -> bool {
    // Genesis certificate has empty or zero previous_hash
    cert.previous_hash.is_empty()
        || cert.previous_hash == "0000000000000000000000000000000000000000000000000000000000000000"
}

fn save_certificate(
    cert: &CertificateMessage,
    hash: &str,
    output_dir: &PathBuf,
) -> Result<PathBuf> {
    let filename = format!("{}.cert", hash);
    let filepath = output_dir.join(&filename);

    // Serialize to bincode
    let bytes = bincode::serialize(cert)
        .map_err(|e| anyhow!("Failed to serialize certificate {}: {}", hash, e))?;

    // Write to file
    fs::write(&filepath, bytes).map_err(|e| {
        anyhow!(
            "Failed to write certificate file {}: {}",
            filepath.display(),
            e
        )
    })?;

    Ok(filepath)
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    println!("Mithril certificate-chain fetcher");
    println!("------------------------------------------------");

    // Parse network
    let network = Network::from_str(&args.network)?;
    println!("Network:     {}", args.network);
    println!("Aggregator:  {}", network.get_aggregator_url());
    println!("Starting at: {}", args.certificate_hash);
    println!("Output dir:  {}", args.output_dir.display());
    println!();

    // Create output directory
    fs::create_dir_all(&args.output_dir)
        .map_err(|e| anyhow!("Failed to create output directory: {}", e))?;

    // Create Mithril client
    let client = make_mithril_client(&network)?;

    // Walk the chain backward from starting hash to genesis
    let mut current_hash = args.certificate_hash.clone();
    let mut certificates_fetched = 0;
    let mut genesis_reached = false;

    println!("Fetching certificate chain (walking backward to genesis)...\n");

    loop {
        if certificates_fetched >= args.max_certificates {
            eprintln!("Reached max-certificates limit ({})", args.max_certificates);
            eprintln!("Use --max-certificates to raise it");
            break;
        }

        println!("[{}] Fetching: {}", certificates_fetched + 1, current_hash);

        let cert = get_certificate(&client, &current_hash)
            .await?
            .ok_or_else(|| anyhow!("Certificate not found: {}", current_hash))?;

        let cert_msg: CertificateMessage = cert;

        if is_genesis_certificate(&cert_msg) {
            println!("   Genesis certificate reached");
            let filepath = save_certificate(&cert_msg, &current_hash, &args.output_dir)?;
            println!("   Saved: {}", filepath.display());
            genesis_reached = true;
            certificates_fetched += 1;
            break;
        }

        let previous_hash = cert_msg.previous_hash.clone();
        println!("   Epoch:         {}", cert_msg.epoch);
        println!("   Previous hash: {}", previous_hash);
        let filepath = save_certificate(&cert_msg, &current_hash, &args.output_dir)?;
        println!("   Saved: {}", filepath.display());
        println!();
        certificates_fetched += 1;
        current_hash = previous_hash;
    }

    println!("------------------------------------------------");
    println!("Summary:");
    println!("  Certificates fetched: {}", certificates_fetched);
    println!(
        "  Genesis reached:      {}",
        if genesis_reached { "yes" } else { "no" }
    );
    println!("  Output directory:     {}", args.output_dir.display());

    if !genesis_reached {
        println!("\nWarning: chain may be incomplete; genesis not reached.");
    }

    create_metadata_file(
        &args.output_dir,
        &network,
        &args.certificate_hash,
        certificates_fetched,
        genesis_reached,
    )?;

    println!("\nDone.");

    Ok(())
}

fn create_metadata_file(
    output_dir: &PathBuf,
    network: &Network,
    starting_hash: &str,
    certificate_count: usize,
    genesis_reached: bool,
) -> Result<()> {
    let metadata = serde_json::json!({
        "network": format!("{:?}", network),
        "aggregator_url": network.get_aggregator_url(),
        "genesis_key": network.get_genesis_key(),
        "starting_certificate_hash": starting_hash,
        "certificate_count": certificate_count,
        "genesis_reached": genesis_reached,
        "fetch_timestamp": chrono::Utc::now().to_rfc3339(),
    });

    let metadata_path = output_dir.join("chain_metadata.json");
    fs::write(&metadata_path, serde_json::to_string_pretty(&metadata)?)?;

    println!("   Metadata: {}", metadata_path.display());

    Ok(())
}
