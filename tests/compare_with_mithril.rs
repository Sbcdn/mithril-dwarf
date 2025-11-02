// tests/compare_with_mithril.rs

/*
use mithril_common::certificate_chain::{CertificateVerifier, MithrilCertificateVerifier};
use mithril_common::entities::Certificate;
use mithril_minimal_parser::risc0_opt::{
    byte_parser::certificate_from_bytes_fast,
    certificate_verification::verify_standard_certificate, serializer::certificate_to_bytes_opt,
};
use reqwest::blocking::Client;

#[test]
#[ignore] // Run with --ignored flag when you want to test against real Mithril
fn test_against_real_mithril_certificates() {
    // Fetch real certificates
    let (cert_current, cert_previous) = fetch_consecutive_certificates();

    println!("Testing certificates:");
    println!(
        "  Current: epoch={}, hash={}",
        cert_current.epoch.0,
        &cert_current.hash[..16]
    );
    println!(
        "  Previous: epoch={}, hash={}",
        cert_previous.epoch.0,
        &cert_previous.hash[..16]
    );

    // Test 1: Verify with Mithril's verifier
    println!("\n1. Verifying with Mithril's verifier...");
    let mithril_verifier = setup_mithril_verifier();
    let mithril_result = mithril_verifier
        .verify_standard_certificate(&cert_current, &cert_previous)
        .await;

    match &mithril_result {
        Ok(_) => println!("   ✅ Mithril verification passed"),
        Err(e) => println!("   ❌ Mithril verification failed: {}", e),
    }

    // Test 2: Verify with our implementation
    println!("\n2. Verifying with our implementation...");
    let our_cert_bytes = certificate_to_bytes_opt(&cert_current);
    let our_prev_bytes = certificate_to_bytes_opt(&cert_previous);

    let our_cert = certificate_from_bytes_fast(&our_cert_bytes).unwrap();
    let our_prev = certificate_from_bytes_fast(&our_prev_bytes).unwrap();

    let our_result = verify_standard_certificate(&our_cert, &our_prev);

    match &our_result {
        Ok(_) => println!("   ✅ Our verification passed"),
        Err(e) => println!("   ❌ Our verification failed: {:?}", e),
    }

    // Test 3: Compare results
    println!("\n3. Comparing results...");
    match (mithril_result, our_result) {
        (Ok(_), Ok(_)) => {
            println!("   ✅ Both verifications passed - MATCH!");
        }
        (Err(e1), Err(e2)) => {
            println!("   ⚠️  Both verifications failed");
            println!("      Mithril error: {}", e1);
            println!("      Our error: {:?}", e2);
        }
        (Ok(_), Err(e)) => {
            panic!("❌ MISMATCH: Mithril passed but ours failed: {:?}", e);
        }
        (Err(e), Ok(_)) => {
            panic!(
                "❌ MISMATCH: Mithril failed but ours passed. Mithril error: {}",
                e
            );
        }
    }
}

fn fetch_consecutive_certificates() -> (Certificate, Certificate) {
    let client = Client::new();

    let response = client
        .get("https://aggregator.release-mainnet.api.mithril.network/artifact/certificates")
        .send()
        .expect("Failed to fetch certificates");

    let certificates: Vec<serde_json::Value> = response.json().expect("Failed to parse JSON");

    let current_hash = certificates[0]["hash"].as_str().unwrap();
    let previous_hash = certificates[1]["hash"].as_str().unwrap();

    let cert_current = fetch_certificate_by_hash(&client, current_hash);
    let cert_previous = fetch_certificate_by_hash(&client, previous_hash);

    (cert_current, cert_previous)
}

fn fetch_certificate_by_hash(client: &Client, hash: &str) -> Certificate {
    let url = format!(
        "https://aggregator.release-mainnet.api.mithril.network/artifact/certificate/{}",
        hash
    );

    client.get(&url).send().unwrap().json().unwrap()
}

fn setup_mithril_verifier() -> impl CertificateVerifier {
    // Setup Mithril's verifier with proper dependencies
    // You'll need to implement this based on Mithril's setup
    todo!("Setup Mithril verifier")
}
 */
