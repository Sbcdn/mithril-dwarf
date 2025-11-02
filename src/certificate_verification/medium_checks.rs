//! Medium-cost verification checks (~50-100K cycles each)
//! These involve SHA-256 hashing to match Mithril's exact hash computation

use super::VerifyError;
use crate::parser::byte_parser::{
    AggregateVerificationKeyParsed, CertificateZeroCopy, MetadataBasicZeroCopy, MultiSigParsed,
    ProtocolMessageBasicZeroCopy, SignatureBasicZeroCopy, SignatureParsed,
};
use sha2::{Digest, Sha256};

/// Verify that the signed_message equals the hash of the protocol_message
/// Cost: ~50K cycles (SHA-256 hash + comparison)
#[inline]
pub fn verify_signed_message_matches_protocol(
    cert: &CertificateZeroCopy,
) -> Result<(), VerifyError> {
    let protocol_hash_hex = compute_protocol_message_hash(&cert.protocol_message);

    // cert.signed_message is stored as UTF-8 bytes of hex string
    let signed_message_str =
        core::str::from_utf8(cert.signed_message).map_err(|_| VerifyError::InvalidUtf8)?;

    if protocol_hash_hex != signed_message_str {
        return Err(VerifyError::SignedMessageMismatch);
    }
    Ok(())
}

/// Verify that the certificate's hash matches its computed hash
/// Cost: ~750K cycles (SHA-256 hash with nested hashes + JSON building)
#[inline]
pub fn verify_hash_matches_content(cert: &CertificateZeroCopy) -> Result<(), VerifyError> {
    let computed_hash_hex = compute_certificate_hash(cert)?;

    // cert.hash is stored as UTF-8 bytes of hex string
    let cert_hash_str = core::str::from_utf8(cert.hash).map_err(|_| VerifyError::InvalidUtf8)?;

    if computed_hash_hex != cert_hash_str {
        return Err(VerifyError::HashMismatch);
    }
    Ok(())
}

/// Compute SHA-256 hash of protocol message (returns hex string)
/// Matches Mithril's ProtocolMessage::compute_hash()
#[inline]
pub fn compute_protocol_message_hash(msg: &ProtocolMessageBasicZeroCopy) -> String {
    let mut hasher = Sha256::new();

    // Hash: key.to_string() || value
    // Key discriminants map to enum names
    for (key_discriminant, value) in &msg.parts {
        let key_str = protocol_message_key_to_string(*key_discriminant);
        hasher.update(key_str.as_bytes());
        hasher.update(value);
    }

    hex::encode(hasher.finalize())
}

/// Compute SHA-256 hash of certificate (returns hex string)
/// Matches Mithril's Certificate::compute_hash()
#[inline]
pub fn compute_certificate_hash(cert: &CertificateZeroCopy) -> Result<String, VerifyError> {
    let mut hasher = Sha256::new();

    // Hash: previous_hash || epoch || metadata_hash || protocol_message_hash ||
    //       signed_message || avk_json_hex || signature

    hasher.update(cert.previous_hash);
    hasher.update(&cert.epoch.to_be_bytes());

    // Hash of metadata (nested hash)
    let metadata_hash = compute_metadata_hash(&cert.metadata)?;
    hasher.update(metadata_hash.as_bytes());

    // Hash of protocol message (nested hash)
    let protocol_hash = compute_protocol_message_hash(&cert.protocol_message);
    hasher.update(protocol_hash.as_bytes());

    hasher.update(cert.signed_message);

    // AVK as hex-encoded JSON
    let avk_json_hex = avk_to_json_hex(&cert.aggregate_verification_key)?;
    hasher.update(avk_json_hex.as_bytes());

    // Hash signature
    hash_signature(&mut hasher, &cert.signature)?;

    Ok(hex::encode(hasher.finalize()))
}

/// Compute SHA-256 hash of metadata (returns hex string)
/// Matches Mithril's CertificateMetadata::compute_hash()
#[inline]
pub fn compute_metadata_hash(metadata: &MetadataBasicZeroCopy) -> Result<String, VerifyError> {
    let mut hasher = Sha256::new();

    hasher.update(metadata.network);
    hasher.update(metadata.protocol_version);

    // Protocol parameters hash (nested)
    let params_hash = compute_protocol_parameters_hash(metadata.k, metadata.m, metadata.phi_f);
    hasher.update(params_hash.as_bytes());

    // Timestamps as nanos
    let initiated_nanos =
        metadata.initiated_at_timestamp * 1_000_000_000 + metadata.initiated_at_nanos as u64;
    let sealed_nanos =
        metadata.sealed_at_timestamp * 1_000_000_000 + metadata.sealed_at_nanos as u64;
    hasher.update(&initiated_nanos.to_be_bytes());
    hasher.update(&sealed_nanos.to_be_bytes());

    // Signers (each is hashed individually)
    for signer in &metadata.signers {
        let signer_hash = compute_signer_hash(signer.party_id, signer.stake);
        hasher.update(signer_hash.as_bytes());
    }

    Ok(hex::encode(hasher.finalize()))
}

/// Compute SHA-256 hash of protocol parameters (returns hex string)
/// Uses fixed-point representation for phi_f (U8F24)
#[inline]
pub fn compute_protocol_parameters_hash(k: u64, m: u64, phi_f: f64) -> String {
    use fixed::types::U8F24;

    let mut hasher = Sha256::new();
    hasher.update(&k.to_be_bytes());
    hasher.update(&m.to_be_bytes());

    // Convert phi_f to fixed-point U8F24 (this is what Mithril does!)
    let phi_f_fixed = U8F24::from_num(phi_f);
    hasher.update(&phi_f_fixed.to_bits().to_be_bytes());

    hex::encode(hasher.finalize())
}

/// Compute SHA-256 hash of a signer (returns hex string)
#[inline]
pub fn compute_signer_hash(party_id: &[u8], stake: u64) -> String {
    let mut hasher = Sha256::new();
    hasher.update(party_id);
    hasher.update(&stake.to_be_bytes());
    hex::encode(hasher.finalize())
}

/// Convert AVK to hex-encoded JSON string (NO SERDE!)
/// Manually constructs: {"mt_commitment":{"root":[...],"nr_leaves":N},"total_stake":M}
/// Cost: ~50K cycles
#[inline]
pub fn avk_to_json_hex(avk: &AggregateVerificationKeyParsed) -> Result<String, VerifyError> {
    use core::fmt::Write;

    let mut json = String::with_capacity(300);

    json.push_str(r#"{"mt_commitment":{"root":["#);

    // Root as byte array
    for (i, byte) in avk.root.iter().enumerate() {
        if i > 0 {
            json.push(',');
        }
        write!(&mut json, "{}", byte).map_err(|_| VerifyError::FormatError)?;
    }

    // Add "hasher":null
    write!(
        &mut json,
        r#"],"nr_leaves":{},"hasher":null}},"total_stake":{}}}"#,
        avk.nr_leaves, avk.total_stake
    )
    .map_err(|_| VerifyError::FormatError)?;

    Ok(hex::encode(json.as_bytes()))
}

/// Hash signature data
/// Matches Mithril's Certificate::compute_hash() signature handling
#[inline]
pub fn hash_signature(
    hasher: &mut Sha256,
    sig: &SignatureBasicZeroCopy,
) -> Result<(), VerifyError> {
    match sig {
        SignatureBasicZeroCopy::Genesis { signature_bytes } => {
            // Genesis signature as hex string
            let sig_hex = hex::encode(signature_bytes);
            hasher.update(sig_hex.as_bytes());
        }
        SignatureBasicZeroCopy::Multi {
            entity_type_discriminant,
            entity_type_data,
            signature,
        } => {
            // First: feed entity type to hasher (feed_hash equivalent)
            feed_entity_type_hash(hasher, *entity_type_discriminant, entity_type_data);

            // Second: multi signature as hex-encoded JSON
            let multi_sig_json_hex = multi_signature_to_json_hex(signature)?;
            hasher.update(multi_sig_json_hex.as_bytes());
        }
    }
    Ok(())
}

/// Feed signed entity type to hasher (Mithril's feed_hash)
/// This just hashes the raw byte data
#[inline]
pub fn feed_entity_type_hash(hasher: &mut Sha256, discriminant: u8, data: &[u64]) {
    match discriminant {
        0 | 1 => {
            // MithrilStakeDistribution(epoch) or CardanoStakeDistribution(epoch)
            hasher.update(&data[0].to_be_bytes());
        }
        2 | 3 => {
            // CardanoImmutableFilesFull(beacon) or CardanoDatabase(beacon)
            // beacon has: epoch, immutable_file_number
            hasher.update(&data[0].to_be_bytes());
            hasher.update(&data[1].to_be_bytes());
        }
        4 => {
            // CardanoTransactions(epoch, block_number)
            hasher.update(&data[0].to_be_bytes());
            hasher.update(&data[1].to_be_bytes());
        }
        _ => {
            // Unknown type - hash what we have
            for value in data {
                hasher.update(&value.to_be_bytes());
            }
        }
    }
}

/// Convert MultiSigParsed to hex-encoded JSON (NO SERDE!)
/// Constructs: {"signatures":[...],"batch_proof":{...}}
/// Cost: ~500K cycles (complex structure with 176 signatures)
#[inline]
pub fn multi_signature_to_json_hex(multi_sig: &MultiSigParsed) -> Result<String, VerifyError> {
    // Pre-allocate: ~2KB for 176 signatures
    let mut json = String::with_capacity(2048);

    json.push_str(r#"{"signatures":["#);

    // Serialize each signature
    for (i, sig) in multi_sig.signatures.iter().enumerate() {
        if i > 0 {
            json.push(',');
        }
        serialize_single_signature(&mut json, sig)?;
    }

    json.push_str(r#"],"batch_proof":"#);

    // Serialize batch proof
    serialize_batch_proof(&mut json, multi_sig.batch_proof_bytes)?;

    json.push('}');

    // Hex encode the JSON
    Ok(hex::encode(json.as_bytes()))
}

/// Serialize a single signature to JSON
/// Format: [{"sigma":[...],"indexes":[...],"signer_index":N},[[vk_bytes],stake]]
#[inline]
pub fn serialize_single_signature(
    json: &mut String,
    sig: &SignatureParsed,
) -> Result<(), VerifyError> {
    use core::fmt::Write;

    // Start tuple
    json.push('[');

    // First element: sig object
    json.push_str(r#"{"sigma":["#);

    // Sigma as byte array
    for (i, byte) in sig.sigma_bytes.iter().enumerate() {
        if i > 0 {
            json.push(',');
        }
        write!(json, "{}", byte).map_err(|_| VerifyError::FormatError)?;
    }

    json.push_str(r#"],"indexes":["#);
    for (i, idx) in sig.indexes.iter().enumerate() {
        if i > 0 {
            json.push(',');
        }
        write!(json, "{}", idx).map_err(|_| VerifyError::FormatError)?;
    }

    write!(json, r#"],"signer_index":{}}}"#, sig.signer_index)
        .map_err(|_| VerifyError::FormatError)?;

    // Second element: [[vk_array], stake]  <- TWO brackets!
    json.push_str(",[["); // CHANGED: was ",[" now ",[["

    // VK as byte array
    for (i, byte) in sig.vk_bytes.iter().enumerate() {
        if i > 0 {
            json.push(',');
        }
        write!(json, "{}", byte).map_err(|_| VerifyError::FormatError)?;
    }

    // Close: ], stake, ], ]
    write!(json, "],{}]]", sig.stake).map_err(|_| VerifyError::FormatError)?;

    Ok(())
}

/// Parse MerkleBatchPath from bytes
/// Direct translation from mithril-stm's from_bytes()
/// Format: len_v (u64 BE) | len_i (u64 BE) | values (32 bytes each) | indices (u64 BE each)
#[inline]
pub fn parse_batch_proof(bytes: &[u8]) -> Result<ParsedBatchProof, VerifyError> {
    const HASH_SIZE: usize = 32; // Blake2b<U32>

    if bytes.len() < 16 {
        return Err(VerifyError::InvalidBatchProof);
    }

    // Read len_v (number of values)
    let len_v = u64::from_be_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ]) as usize;

    // Read len_i (number of indices)
    let len_i = u64::from_be_bytes([
        bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15],
    ]) as usize;

    // Sanity checks
    if len_v > 10000 || len_i > 10000 {
        return Err(VerifyError::InvalidBatchProof);
    }

    // Read values (each is HASH_SIZE bytes, no length prefix)
    let values_start = 16;
    let values_end = values_start + (len_v * HASH_SIZE);

    if values_end > bytes.len() {
        return Err(VerifyError::InvalidBatchProof);
    }

    let mut values = Vec::with_capacity(len_v);
    for i in 0..len_v {
        let start = values_start + (i * HASH_SIZE);
        let end = start + HASH_SIZE;
        values.push(&bytes[start..end]);
    }

    // Read indices (each is u64 BE)
    let indices_start = values_end;

    if indices_start + (len_i * 8) > bytes.len() {
        return Err(VerifyError::InvalidBatchProof);
    }

    let mut indices = Vec::with_capacity(len_i);
    for i in 0..len_i {
        let pos = indices_start + (i * 8);
        let idx = u64::from_be_bytes([
            bytes[pos],
            bytes[pos + 1],
            bytes[pos + 2],
            bytes[pos + 3],
            bytes[pos + 4],
            bytes[pos + 5],
            bytes[pos + 6],
            bytes[pos + 7],
        ]);
        indices.push(idx);
    }

    Ok(ParsedBatchProof { indices, values })
}

/// Parsed batch proof structure
pub struct ParsedBatchProof<'a> {
    pub indices: Vec<u64>,
    pub values: Vec<&'a [u8]>,
}

/// Serialize batch proof to JSON
/// Format: {"values":[[byte,byte,...],...],"indices":[idx,idx,...],"hasher":null}
#[inline]
pub fn serialize_batch_proof(json: &mut String, proof_bytes: &[u8]) -> Result<(), VerifyError> {
    use core::fmt::Write;

    // Parse the batch proof bytes
    let proof = parse_batch_proof(proof_bytes)?;

    // Start object - VALUES FIRST (not indices!)
    json.push_str(r#"{"values":["#);

    // Serialize values (each is a byte array)
    for (i, value) in proof.values.iter().enumerate() {
        if i > 0 {
            json.push(',');
        }
        json.push('[');
        for (j, byte) in value.iter().enumerate() {
            if j > 0 {
                json.push(',');
            }
            write!(json, "{}", byte).map_err(|_| VerifyError::FormatError)?;
        }
        json.push(']');
    }

    // Now indices
    json.push_str(r#"],"indices":["#);

    for (i, idx) in proof.indices.iter().enumerate() {
        if i > 0 {
            json.push(',');
        }
        write!(json, "{}", idx).map_err(|_| VerifyError::FormatError)?;
    }

    // Close with hasher:null
    json.push_str(r#"],"hasher":null}"#);

    Ok(())
}

/// Map protocol message key discriminant to string (snake_case!)
#[inline]
pub fn protocol_message_key_to_string(discriminant: u8) -> &'static str {
    match discriminant {
        0 => "snapshot_digest",
        1 => "cardano_transactions_merkle_root",
        2 => "next_aggregate_verification_key",
        3 => "next_protocol_parameters",
        4 => "current_epoch",
        5 => "latest_block_number",
        6 => "cardano_stake_distribution_epoch",
        7 => "cardano_stake_distribution_merkle_root",
        8 => "cardano_database_merkle_root",
        _ => "unknown",
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::parser::byte_parser::{ParseError, certificate_from_bytes_fast};

    /// Test helper: Parse a certificate from bytes and verify its hash
    pub fn test_certificate_hash_from_bytes(
        cert_bytes: &[u8],
    ) -> Result<HashTestResult, TestError> {
        // Parse certificate
        let cert = certificate_from_bytes_fast(cert_bytes).map_err(|e| TestError::ParseError(e))?;

        // Get the original hash (from certificate)
        let original_hash = core::str::from_utf8(cert.hash)
            .map_err(|_| TestError::InvalidUtf8)?
            .to_string();

        // Compute hash using our implementation
        let computed_hash =
            compute_certificate_hash(&cert).map_err(|e| TestError::VerifyError(e))?;

        // Compare
        let matches = original_hash == computed_hash;

        Ok(HashTestResult {
            original_hash,
            computed_hash,
            matches,
            details: compute_hash_details(&cert)?,
        })
    }

    /// Compute detailed hash information for debugging
    fn compute_hash_details(cert: &CertificateZeroCopy) -> Result<HashDetails, TestError> {
        let protocol_message_hash = compute_protocol_message_hash(&cert.protocol_message);
        let metadata_hash =
            compute_metadata_hash(&cert.metadata).map_err(|e| TestError::VerifyError(e))?;
        let avk_json = avk_to_json_hex(&cert.aggregate_verification_key)
            .map_err(|e| TestError::VerifyError(e))?;

        // Get signature JSON if it's a multi-signature
        let signature_json = match &cert.signature {
            SignatureBasicZeroCopy::Multi { signature, .. } => Some(
                multi_signature_to_json_hex(signature).map_err(|e| TestError::VerifyError(e))?,
            ),
            _ => None,
        };

        Ok(HashDetails {
            protocol_message_hash,
            metadata_hash,
            avk_json: avk_json.clone(),
            avk_json_decoded: hex::decode(&avk_json)
                .ok()
                .and_then(|bytes| String::from_utf8(bytes).ok()),
            signature_json: signature_json.clone(),
            signature_json_decoded: signature_json
                .as_ref()
                .and_then(|s| hex::decode(s).ok())
                .and_then(|bytes| String::from_utf8(bytes).ok()),
        })
    }

    #[derive(Debug)]
    pub struct HashTestResult {
        pub original_hash: String,
        pub computed_hash: String,
        pub matches: bool,
        pub details: HashDetails,
    }

    #[derive(Debug)]
    pub struct HashDetails {
        pub protocol_message_hash: String,
        pub metadata_hash: String,
        pub avk_json: String,
        pub avk_json_decoded: Option<String>,
        pub signature_json: Option<String>,
        pub signature_json_decoded: Option<String>,
    }

    #[derive(Debug)]
    pub enum TestError {
        ParseError(ParseError),
        VerifyError(VerifyError),
        InvalidUtf8,
    }

    impl HashTestResult {
        /// Print detailed comparison
        pub fn print_detailed(&self) {
            println!("\n========== CERTIFICATE HASH TEST ==========");
            println!("Match: {}", if self.matches { "✅ YES" } else { "❌ NO" });
            println!("\nOriginal hash:  {}", self.original_hash);
            println!("Computed hash:  {}", self.computed_hash);

            if !self.matches {
                println!("\n⚠️  HASHES DO NOT MATCH!");

                // Show character-by-character diff
                println!("\nCharacter diff:");
                for (i, (orig, comp)) in self
                    .original_hash
                    .chars()
                    .zip(self.computed_hash.chars())
                    .enumerate()
                {
                    if orig != comp {
                        println!("  Position {}: '{}' != '{}'", i, orig, comp);
                    }
                }
            }

            println!("\n---------- Hash Components ----------");
            println!(
                "Protocol message hash: {}",
                self.details.protocol_message_hash
            );
            println!("Metadata hash:         {}", self.details.metadata_hash);

            println!("\n---------- AVK JSON (hex-encoded) ----------");
            println!("{}", self.details.avk_json);

            if let Some(decoded) = &self.details.avk_json_decoded {
                println!("\nAVK JSON (decoded):");
                println!("{}", decoded);
            }

            if let Some(sig_json) = &self.details.signature_json {
                println!("\n---------- Signature JSON (hex-encoded) ----------");
                println!("{}", sig_json);

                if let Some(decoded) = &self.details.signature_json_decoded {
                    println!("\nSignature JSON (decoded, first 500 chars):");
                    let preview = if decoded.len() > 500 {
                        &decoded[..500]
                    } else {
                        decoded.as_str()
                    };
                    println!("{}", preview);
                    if decoded.len() > 500 {
                        println!("... ({} more chars)", decoded.len() - 500);
                    }
                }
            }

            println!("\n==========================================\n");
        }
    }

    // Unit tests for individual components

    #[test]
    fn test_protocol_parameters_hash() {
        // Test values from a real certificate
        let k = 2422;
        let m = 20973;
        let phi_f = 0.2;

        let hash = compute_protocol_parameters_hash(k, m, phi_f);
        println!("Protocol params hash: {}", hash);

        // This should be 64 characters (32 bytes in hex)
        assert_eq!(hash.len(), 64);
    }

    #[test]
    fn test_signer_hash() {
        let party_id = b"pool1test123456789";
        let stake = 1000000;

        let hash = compute_signer_hash(party_id, stake);
        println!("Signer hash: {}", hash);

        assert_eq!(hash.len(), 64);
    }

    #[test]
    fn test_avk_json_format() {
        // Create a test AVK
        let root = [1u8; 32];
        let avk = AggregateVerificationKeyParsed {
            root: &root,
            nr_leaves: 100,
            total_stake: 5000000000,
        };

        let json_hex = avk_to_json_hex(&avk).expect("Failed to create AVK JSON");
        println!("AVK JSON (hex): {}", json_hex);

        // Decode and print
        let json_bytes = hex::decode(&json_hex).expect("Failed to decode hex");
        let json_str = String::from_utf8(json_bytes).expect("Failed to decode UTF-8");
        println!("AVK JSON (decoded): {}", json_str);

        // Verify it's valid JSON structure
        assert!(json_str.contains(r#""mt_commitment""#));
        assert!(json_str.contains(r#""root""#));
        assert!(json_str.contains(r#""nr_leaves""#));
        assert!(json_str.contains(r#""total_stake""#));
    }
}
