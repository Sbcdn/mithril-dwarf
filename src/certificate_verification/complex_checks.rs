//! Complex verification checks (expensive, ~1M+ cycles)
//! These involve cryptographic operations and Merkle tree verification

use std::collections::BTreeSet;

use super::VerifyError;
use crate::parser::byte_parser::{CertificateZeroCopy, MultiSigParsed, SignatureBasicZeroCopy};
use blake2::digest::consts::U32;
use blake2::{Blake2b, Blake2b512, Digest as Blake2Digest};

use super::medium_checks::{avk_to_json_hex, compute_protocol_parameters_hash, parse_batch_proof};

use num_bigint::{BigInt, Sign};
use num_rational::Ratio;
use num_traits::{One, Signed};
use std::ops::Neg;

use blst::MultiPoint;
use blst::min_sig::{PublicKey, Signature};

/// Verify AVK chaining between certificates
/// If same epoch: AVKs must match exactly
/// If different epoch: previous cert's next_avk must match current cert's avk
#[inline]
pub fn verify_avk_chain(
    current_cert: &CertificateZeroCopy,
    previous_cert: &CertificateZeroCopy,
) -> Result<(), VerifyError> {
    let same_epoch = current_cert.epoch == previous_cert.epoch;

    if same_epoch {
        // Same epoch: AVKs must be identical
        let current_avk_json = avk_to_json_hex(&current_cert.aggregate_verification_key)?;
        let previous_avk_json = avk_to_json_hex(&previous_cert.aggregate_verification_key)?;

        if current_avk_json != previous_avk_json {
            return Err(VerifyError::AVKMismatch);
        }
    } else {
        // Different epoch: check next_avk from previous cert
        let next_avk = find_protocol_message_part(&previous_cert.protocol_message.parts, 2)
            .ok_or(VerifyError::NextAVKNotFound)?;

        let current_avk_json = avk_to_json_hex(&current_cert.aggregate_verification_key)?;

        // next_avk is stored as UTF-8 hex string
        let next_avk_str = core::str::from_utf8(next_avk).map_err(|_| VerifyError::InvalidUtf8)?;

        if current_avk_json != next_avk_str {
            return Err(VerifyError::AVKMismatch);
        }
    }

    Ok(())
}

/// Verify protocol parameters chaining between certificates
#[inline]
pub fn verify_protocol_params_chain(
    current_cert: &CertificateZeroCopy,
    previous_cert: &CertificateZeroCopy,
) -> Result<(), VerifyError> {
    let same_epoch = current_cert.epoch == previous_cert.epoch;

    if same_epoch {
        // Same epoch: params must be identical
        if current_cert.metadata.k != previous_cert.metadata.k
            || current_cert.metadata.m != previous_cert.metadata.m
            || (current_cert.metadata.phi_f - previous_cert.metadata.phi_f).abs() > f64::EPSILON
        {
            return Err(VerifyError::ProtocolParamsMismatch);
        }
    } else {
        // Different epoch: check next_protocol_parameters hash
        let next_params_hash = find_protocol_message_part(&previous_cert.protocol_message.parts, 3)
            .ok_or(VerifyError::NextProtocolParamsNotFound)?;

        let current_params_hash = compute_protocol_parameters_hash(
            current_cert.metadata.k,
            current_cert.metadata.m,
            current_cert.metadata.phi_f,
        );

        let next_params_hash_str =
            core::str::from_utf8(next_params_hash).map_err(|_| VerifyError::InvalidUtf8)?;

        if current_params_hash != next_params_hash_str {
            return Err(VerifyError::ProtocolParamsMismatch);
        }
    }

    Ok(())
}

/// Verify BLS multi-signature
/// This is the most expensive check (~1M+ cycles)
#[inline]
pub fn verify_bls_multisig(cert: &CertificateZeroCopy) -> Result<(), VerifyError> {
    // Only verify MultiSignature, not Genesis
    let multi_sig = match &cert.signature {
        SignatureBasicZeroCopy::Multi { signature, .. } => signature,
        SignatureBasicZeroCopy::Genesis { .. } => return Ok(()), // Genesis doesn't need BLS verification
    };

    // 1. Prepare message: signed_message || avk.root
    let msgp = prepare_message_with_root(cert.signed_message, &cert.aggregate_verification_key)?;

    // 2. Preliminary verification
    preliminary_verify(
        &multi_sig,
        &msgp,
        cert.metadata.k,
        cert.metadata.m,
        cert.metadata.phi_f,
        cert.aggregate_verification_key.total_stake,
    )?;

    // 3. Verify Merkle batch proof
    verify_merkle_batch_proof(&multi_sig, &cert.aggregate_verification_key)?;

    // 4. BLS aggregate signature verification
    verify_bls_aggregate(&msgp, &multi_sig)?;

    Ok(())
}

/// Prepare message: msg || avk.root
#[inline]
fn prepare_message_with_root(
    signed_message: &[u8],
    avk: &crate::parser::byte_parser::AggregateVerificationKeyParsed,
) -> Result<Vec<u8>, VerifyError> {
    let mut msgp = signed_message.to_vec();
    msgp.extend_from_slice(avk.root);
    Ok(msgp)
}

/// Preliminary verification: check indices, lottery, quorum
#[inline]
fn preliminary_verify(
    multi_sig: &MultiSigParsed,
    msgp: &[u8],
    k: u64,
    m: u64,
    phi_f: f64,
    total_stake: u64,
) -> Result<(), VerifyError> {
    let mut nr_indices = 0;
    let mut unique_indices = BTreeSet::new();

    for sig in &multi_sig.signatures {
        // Check each index
        for &index in &sig.indexes {
            // Check index bound
            if index > m {
                return Err(VerifyError::IndexOutOfBounds);
            }

            // Check lottery
            let ev = evaluate_dense_mapping(msgp, index, sig.sigma_bytes);
            if !is_lottery_won(phi_f, ev, sig.stake, total_stake) {
                return Err(VerifyError::LotteryLost);
            }

            // Track unique indices
            unique_indices.insert(index);
            nr_indices += 1;
        }
    }

    // Check all indices are unique
    if nr_indices != unique_indices.len() {
        return Err(VerifyError::IndexNotUnique);
    }

    // Check quorum
    if (nr_indices as u64) < k {
        return Err(VerifyError::NoQuorum);
    }

    Ok(())
}

/// Evaluate dense mapping: H("map" || msg || index || sigma)
#[inline]
fn evaluate_dense_mapping(msg: &[u8], index: u64, sigma: &[u8; 48]) -> [u8; 64] {
    let hasher = Blake2b512::new()
        .chain_update(b"map")
        .chain_update(msg)
        .chain_update(index.to_le_bytes())
        .chain_update(sigma);

    let mut output = [0u8; 64];
    output.copy_from_slice(hasher.finalize().as_ref());
    output
}

/// Check if lottery is won using Taylor series approximation
/// Matches Mithril's is_lottery_won function exactly
#[inline]
fn is_lottery_won(phi_f: f64, ev: [u8; 64], stake: u64, total_stake: u64) -> bool {
    // If phi_f = 1, automatically win
    if (phi_f - 1.0).abs() < f64::EPSILON {
        return true;
    }

    let ev_max = BigInt::from(2u8).pow(512);
    let ev = BigInt::from_bytes_le(Sign::Plus, &ev);
    let q = Ratio::new_raw(ev_max.clone(), ev_max - ev);

    let c =
        Ratio::from_float((1.0 - phi_f).ln()).expect("Only fails if the float is infinite or NaN.");
    let w = Ratio::new_raw(BigInt::from(stake), BigInt::from(total_stake));
    let x = (w * c).neg();

    // Taylor series comparison with early stopping
    taylor_comparison(1000, q, x)
}

/// Check if cmp < exp(x) using Taylor series with early stopping
/// Uses error approximation for efficiency
#[allow(clippy::redundant_clone)]
fn taylor_comparison(bound: usize, cmp: Ratio<BigInt>, x: Ratio<BigInt>) -> bool {
    let mut new_x = x.clone();
    let mut phi: Ratio<BigInt> = One::one();
    let mut divisor: BigInt = One::one();

    for _ in 0..bound {
        phi += new_x.clone();

        divisor += 1;
        new_x = (new_x.clone() * x.clone()) / divisor.clone();
        let error_term = new_x.clone().abs() * BigInt::from(3); // new_x * M

        if cmp > (phi.clone() + error_term.clone()) {
            return false;
        } else if cmp < phi.clone() - error_term.clone() {
            return true;
        }
    }
    false
}

/// Verify Merkle batch proof
#[inline]
fn verify_merkle_batch_proof(
    multi_sig: &MultiSigParsed,
    avk: &crate::parser::byte_parser::AggregateVerificationKeyParsed,
) -> Result<(), VerifyError> {
    // Parse batch proof
    let proof = parse_batch_proof(multi_sig.batch_proof_bytes)?;

    // Check lengths match
    if multi_sig.signatures.len() != proof.indices.len() {
        return Err(VerifyError::BatchProofInvalid);
    }

    // Check indices are sorted
    let mut sorted_indices = proof.indices.clone();
    sorted_indices.sort_unstable();
    if sorted_indices != proof.indices {
        return Err(VerifyError::BatchProofInvalid);
    }

    // Hash all leaves (vk || stake)
    let mut leaves: Vec<Vec<u8>> = Vec::with_capacity(multi_sig.signatures.len());
    for sig in &multi_sig.signatures {
        let leaf_bytes = serialize_registered_party(sig.vk_bytes, sig.stake);
        let leaf_hash = Blake2b::<U32>::digest(&leaf_bytes).to_vec();
        leaves.push(leaf_hash);
    }

    // Verify batch proof
    verify_batch_path(
        &leaves,
        &proof.indices,
        &proof.values,
        avk.root,
        avk.nr_leaves as usize,
    )?;

    Ok(())
}

/// Serialize RegisteredParty: vk (96 bytes) || stake (8 bytes BE)
#[inline]
fn serialize_registered_party(vk: &[u8; 96], stake: u64) -> [u8; 104] {
    let mut result = [0u8; 104];
    result[..96].copy_from_slice(vk);
    result[96..].copy_from_slice(&stake.to_be_bytes());
    result
}

/// Verify batch Merkle path
#[inline]
fn verify_batch_path(
    leaves: &[Vec<u8>],
    indices: &[u64],
    values: &[&[u8]],
    root: &[u8],
    nr_leaves: usize,
) -> Result<(), VerifyError> {
    let nr_nodes = nr_leaves + nr_leaves.next_power_of_two() - 1;

    // Convert indices to tree positions
    let mut ordered_indices: Vec<usize> = indices
        .iter()
        .map(|&i| i as usize + nr_leaves.next_power_of_two() - 1)
        .collect();

    let mut current_leaves = leaves.to_vec();
    let mut values_iter = values.iter();
    let mut idx = ordered_indices[0];

    while idx > 0 {
        let mut new_hashes = Vec::with_capacity(ordered_indices.len());
        let mut new_indices = Vec::with_capacity(ordered_indices.len());
        let mut i = 0;

        idx = parent(ordered_indices[i]);

        while i < ordered_indices.len() {
            new_indices.push(parent(ordered_indices[i]));

            if ordered_indices[i] & 1 == 0 {
                // Even node - sibling is from values
                let sibling = values_iter.next().ok_or(VerifyError::BatchProofInvalid)?;
                let hash = Blake2b::<U32>::new()
                    .chain_update(sibling)
                    .chain_update(&current_leaves[i])
                    .finalize()
                    .to_vec();
                new_hashes.push(hash);
            } else {
                // Odd node
                let sib = sibling(ordered_indices[i]);
                if i < ordered_indices.len() - 1 && ordered_indices[i + 1] == sib {
                    // Sibling is next leaf
                    let hash = Blake2b::<U32>::new()
                        .chain_update(&current_leaves[i])
                        .chain_update(&current_leaves[i + 1])
                        .finalize()
                        .to_vec();
                    new_hashes.push(hash);
                    i += 1;
                } else if sib < nr_nodes {
                    // Sibling is from values
                    let sibling_val = values_iter.next().ok_or(VerifyError::BatchProofInvalid)?;
                    let hash = Blake2b::<U32>::new()
                        .chain_update(&current_leaves[i])
                        .chain_update(sibling_val)
                        .finalize()
                        .to_vec();
                    new_hashes.push(hash);
                } else {
                    // No sibling - hash with zero
                    let hash = Blake2b::<U32>::new()
                        .chain_update(&current_leaves[i])
                        .chain_update(Blake2b::<U32>::digest([0u8]))
                        .finalize()
                        .to_vec();
                    new_hashes.push(hash);
                }
            }
            i += 1;
        }

        current_leaves = new_hashes;
        ordered_indices = new_indices;
    }

    // Check final hash matches root
    if current_leaves.len() == 1 && current_leaves[0].as_slice() == root {
        Ok(())
    } else {
        Err(VerifyError::BatchProofInvalid)
    }
}

/// Verify BLS aggregate signature using RISC0 precompile
#[inline]
fn verify_bls_aggregate(msgp: &[u8], multi_sig: &MultiSigParsed) -> Result<(), VerifyError> {
    // 1. Aggregate signatures and verification keys
    let (aggr_vk, aggr_sig) = aggregate_signatures_and_keys(&multi_sig)?;

    // 2. Call BLS verification using RISC0's blst precompile
    // This replaces: aggr_sig.verify(false, msgp, &[], &[], &aggr_vk, false)

    // In RISC0, we use the same blst API - it's automatically accelerated
    use blst::min_sig::{PublicKey, Signature};

    // Deserialize aggregated signature and key
    let sig = Signature::from_bytes(&aggr_sig).map_err(|_| VerifyError::BLSVerificationFailed)?;
    let pk = PublicKey::from_bytes(&aggr_vk).map_err(|_| VerifyError::BLSVerificationFailed)?;

    // Verify: e(sig, G2) == e(H(msg), pk)
    let result = sig.verify(false, msgp, &[], &[], &pk, false);

    if result == blst::BLST_ERROR::BLST_SUCCESS {
        Ok(())
    } else {
        Err(VerifyError::BLSVerificationFailed)
    }
}

/// Aggregate signatures and keys using Mithril's Figure 6 algorithm
/// This implements the scalar multiplication aggregation using blst's MultiPoint
#[inline]
fn aggregate_signatures_and_keys(
    multi_sig: &MultiSigParsed,
) -> Result<([u8; 96], [u8; 48]), VerifyError> {
    if multi_sig.signatures.is_empty() {
        return Err(VerifyError::BLSVerificationFailed);
    }

    // If only one signature, return as-is
    if multi_sig.signatures.len() == 1 {
        return Ok((
            *multi_sig.signatures[0].vk_bytes,
            *multi_sig.signatures[0].sigma_bytes,
        ));
    }

    // 1. Hash all signatures together to generate randomness
    let mut hashed_sigs = Blake2b::<blake2::digest::consts::U16>::new();
    for sig in &multi_sig.signatures {
        hashed_sigs.update(sig.sigma_bytes);
    }

    // 2. Generate scalars (16 bytes each, 128 bits)
    let mut scalars = Vec::with_capacity(multi_sig.signatures.len() * 16);
    for (index, _) in multi_sig.signatures.iter().enumerate() {
        let mut hasher = hashed_sigs.clone();
        hasher.update((index as usize).to_be_bytes());
        scalars.extend_from_slice(hasher.finalize().as_ref());
    }

    // 3. Convert our parsed data to blst types
    let mut pks = Vec::with_capacity(multi_sig.signatures.len());
    let mut sigs = Vec::with_capacity(multi_sig.signatures.len());

    for sig_parsed in &multi_sig.signatures {
        let pk = PublicKey::from_bytes(sig_parsed.vk_bytes)
            .map_err(|_| VerifyError::BLSVerificationFailed)?;
        let sig = Signature::from_bytes(sig_parsed.sigma_bytes)
            .map_err(|_| VerifyError::BLSVerificationFailed)?;

        pks.push(pk);
        sigs.push(sig);
    }

    // 4. Use MultiPoint::mult for scalar multiplication aggregation
    // This is exactly what Mithril does with p1_affines::mult and p2_affines::mult
    let agg_pk = pks.mult(&scalars, 128); // 128 bits per scalar
    let agg_sig = sigs.mult(&scalars, 128);

    // 5. Convert to bytes
    let aggr_pk_bytes = agg_pk.to_public_key().to_bytes();
    let aggr_sig_bytes = agg_sig.to_signature().to_bytes();

    Ok((aggr_pk_bytes, aggr_sig_bytes))
}

// Helper functions

#[inline]
fn parent(i: usize) -> usize {
    (i - 1) / 2
}

#[inline]
fn sibling(i: usize) -> usize {
    if i % 2 == 1 { i + 1 } else { i - 1 }
}

#[inline]
fn find_protocol_message_part<'a>(
    parts: &'a [(u8, &'a [u8])],
    discriminant: u8,
) -> Option<&'a [u8]> {
    parts
        .iter()
        .find(|(disc, _)| *disc == discriminant)
        .map(|(_, value)| *value)
}
