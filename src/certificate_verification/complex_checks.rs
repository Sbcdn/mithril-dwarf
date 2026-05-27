//! Complex verification checks (expensive, ~1M+ cycles)
//!
//! These involve cryptographic operations and Merkle tree verification.
//!
//! # Optimizations Applied
//!
//! - **Cached c computation**: ln(1-phi_f) is cached by phi_f value
//! - **Skip q reduction**: ev_max/(ev_max-ev) is already in lowest terms
//! - **Fast from_float**: Uses u64 GCD for small values (~192x faster)
//!
//! # Performance
//!
//! Lottery verification: ~120K cycles per check
//! Total improvement: 2x faster than num-bigint baseline (477M vs 954M cycles)

use super::VerifyError;
use crate::parser::byte_deserializer::{
    CertificateZeroCopy, MultiSigParsed, SignatureBasicZeroCopy,
};
use blake2::digest::consts::U32;
use blake2::{Blake2b, Blake2b512, Digest as Blake2Digest};
use crypto_ratio::RatioU512 as Ratio512;
//use risc0_zkvm::guest::env;
use std::collections::{BTreeSet, HashMap};
use std::sync::{Mutex, OnceLock};

use super::medium_checks::{avk_to_json_hex, compute_protocol_parameters_hash, parse_batch_proof};

use crypto_bigint::U512;

use blst::MultiPoint;
use blst::min_sig::{PublicKey, Signature};

// ============================================================================
// CACHING - Avoid recomputing ln(1-phi_f)
// ============================================================================

/// Cache for c values (ln(1-phi_f)) keyed by phi_f
static C_CACHE: OnceLock<Mutex<HashMap<u64, Ratio512>>> = OnceLock::new();

/// Get cached c value for phi_f, computing if not cached
///
/// Since phi_f is constant for a certificate, this avoids recomputing
/// ln(1-phi_f) for every lottery check (~384K cycles saved per reuse)
fn get_c_cached(phi_f: f64) -> Ratio512 {
    let key = phi_f.to_bits();

    let cache = C_CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    let mut map = cache.lock().unwrap();

    if let Some(cached) = map.get(&key) {
        return cached.clone();
    }

    // Cache miss - compute and store
    let c = Ratio512::from_float((1.0 - phi_f).ln())
        .expect("phi_f must be in (0,1) range, ln is finite");
    map.insert(key, c.clone());
    c
}

// ============================================================================
// CERTIFICATE CHAINING VERIFICATION
// ============================================================================

/// Verify AVK chaining between certificates
///
/// If same epoch: AVKs must match exactly
/// If different epoch: previous cert's next_avk must match current cert's avk
#[inline]
pub fn verify_avk_chain(
    current_cert: &CertificateZeroCopy,
    previous_cert: &CertificateZeroCopy,
) -> Result<(), VerifyError> {
    let same_epoch = current_cert.epoch == previous_cert.epoch;

    if same_epoch {
        let current_avk_json = avk_to_json_hex(&current_cert.aggregate_verification_key)?;
        let previous_avk_json = avk_to_json_hex(&previous_cert.aggregate_verification_key)?;

        if current_avk_json != previous_avk_json {
            return Err(VerifyError::AVKMismatch);
        }
    } else {
        let next_avk = find_protocol_message_part(&previous_cert.protocol_message.parts, 2)
            .ok_or(VerifyError::NextAVKNotFound)?;

        let current_avk_json = avk_to_json_hex(&current_cert.aggregate_verification_key)?;
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
        if current_cert.metadata.k != previous_cert.metadata.k
            || current_cert.metadata.m != previous_cert.metadata.m
            || (current_cert.metadata.phi_f - previous_cert.metadata.phi_f).abs() > f64::EPSILON
        {
            return Err(VerifyError::ProtocolParamsMismatch);
        }
    } else {
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

// ============================================================================
// BLS MULTI-SIGNATURE VERIFICATION
// ============================================================================

/// Verify BLS multi-signature (most expensive check: ~55M cycles)
#[inline]
pub fn verify_bls_multisig(cert: &CertificateZeroCopy) -> Result<(), VerifyError> {
    let multi_sig = match &cert.signature {
        SignatureBasicZeroCopy::Multi { signature, .. } => signature,
        SignatureBasicZeroCopy::Genesis { .. } => return Ok(()),
    };

    // 1. Prepare message: signed_message || avk.root
    let msgp = prepare_message_with_root(cert.signed_message, &cert.aggregate_verification_key)?;

    // 2. Preliminary verification (indices, lottery, quorum)
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

/// Prepare message for signature verification: msg || avk.root
#[inline]
fn prepare_message_with_root(
    signed_message: &[u8],
    avk: &crate::parser::byte_deserializer::AggregateVerificationKeyParsed,
) -> Result<Vec<u8>, VerifyError> {
    let mut msgp = signed_message.to_vec();
    msgp.extend_from_slice(avk.root);
    Ok(msgp)
}

// ============================================================================
// PRELIMINARY VERIFICATION (Indices, Lottery, Quorum)
// ============================================================================

/// Preliminary verification: check indices, lottery wins, and quorum
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

// ============================================================================
// LOTTERY VERIFICATION
// ============================================================================

/// Check if lottery is won using Taylor series approximation
///
/// Mathematical background:
/// - Lottery won if: q < exp(w * ln(1-phi_f))
/// - Where: q = 2^512 / (2^512 - ev)
/// - And: w = stake / total_stake
///
/// Uses Taylor series: exp(x) ≈ 1 + x + x²/2! + x³/3! + ...
/// Convergence is checked with error bounds: phi ± 3*last_term
///
/// # Performance
///
/// - ~120K cycles per lottery check
/// - Optimizations:
///   - Cached c = ln(1-phi_f) (saves ~384K cycles on cache hit)
///   - Skip q reduction (saves ~430K cycles, q is already coprime)
///   - Fast u64 GCD in from_float (saves ~380K cycles)
///   - Converges in 1 iteration for typical values
#[inline]
fn is_lottery_won(phi_f: f64, ev: [u8; 64], stake: u64, total_stake: u64) -> bool {
    // Special case: phi_f = 1 means always win
    if (phi_f - 1.0).abs() < f64::EPSILON {
        return true;
    }

    // Compute q = 2^512 / (2^512 - ev)
    let ev_u512 = U512::from_le_slice(&ev);
    let ev_max = U512::MAX;
    let denominator = ev_max.wrapping_sub(&ev_u512);

    // OPTIMIZATION: Don't reduce q - it's already in lowest terms
    // GCD(2^512, 2^512 - ev) = 1 for random ev
    let q = Ratio512::new_raw(ev_max, denominator, false);

    // OPTIMIZATION: Use cached c value (saves ~384K cycles on hit)
    let c = get_c_cached(phi_f);

    // Compute w = stake / total_stake (already reduced via from_u64)
    let w = Ratio512::from_u64(stake, total_stake);

    // Compute x = -w * ln(1-phi_f)
    let x = w.mul(&c).neg();

    // Check: q < exp(x) using Taylor series
    taylor_comparison(1000, q, x)
}

/// Taylor series comparison: check if cmp < exp(x)
///
/// Uses error approximation for convergence:
/// - If cmp > phi + 3*term: FALSE (lottery lost)
/// - If cmp < phi - 3*term: TRUE (lottery won)
/// - Otherwise: continue iterating
///
/// Typically converges in 1 iteration for lottery values.
#[inline]
fn taylor_comparison(bound: usize, cmp: Ratio512, x: Ratio512) -> bool {
    let mut new_x = x.clone();
    let mut phi = Ratio512::one();
    let mut divisor = U512::ONE;
    let three = Ratio512::from_u64(3, 1);

    for _ in 0..bound {
        // Accumulate: phi += new_x
        phi = phi.add(&new_x);

        // Next term: new_x = new_x * x / (divisor + 1)
        divisor = divisor.wrapping_add(&U512::ONE);
        new_x = new_x.mul(&x).div_by_uint(&divisor);

        // Prevent overflow by reducing when values get large
        if new_x.numer.bits() > 450 || new_x.denom.bits() > 450 {
            new_x.normalize();
        }
        if phi.numer.bits() > 450 || phi.denom.bits() > 450 {
            phi.normalize();
        }

        // Compute error term: 3 * |new_x|
        let error_term = new_x.abs().mul(&three);

        // Check convergence with error bounds
        let mut phi_plus = phi.add(&error_term);
        let mut phi_minus = phi.add(&error_term.neg());

        // Reduce before comparison if needed
        if phi_plus.numer.bits() > 400 || phi_plus.denom.bits() > 400 {
            phi_plus.normalize();
        }
        if phi_minus.numer.bits() > 400 || phi_minus.denom.bits() > 400 {
            phi_minus.normalize();
        }

        // Check if we can determine result within error bounds
        if cmp.gt(&phi_plus) {
            return false; // cmp > exp(x) + error
        }
        if cmp.lt(&phi_minus) {
            return true; // cmp < exp(x) - error
        }

        // Continue iterating (inconclusive)
    }

    // Reached iteration limit without convergence
    // Conservative: assume lottery lost
    false
}

// ============================================================================
// MERKLE BATCH PROOF VERIFICATION
// ============================================================================

/// Verify Merkle batch proof
#[inline]
fn verify_merkle_batch_proof(
    multi_sig: &MultiSigParsed,
    avk: &crate::parser::byte_deserializer::AggregateVerificationKeyParsed,
) -> Result<(), VerifyError> {
    let proof = parse_batch_proof(multi_sig.batch_proof_bytes)?;

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
                    let hash = Blake2b::<U32>::new()
                        .chain_update(&current_leaves[i])
                        .chain_update(&current_leaves[i + 1])
                        .finalize()
                        .to_vec();
                    new_hashes.push(hash);
                    i += 1;
                } else if sib < nr_nodes {
                    let sibling_val = values_iter.next().ok_or(VerifyError::BatchProofInvalid)?;
                    let hash = Blake2b::<U32>::new()
                        .chain_update(&current_leaves[i])
                        .chain_update(sibling_val)
                        .finalize()
                        .to_vec();
                    new_hashes.push(hash);
                } else {
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

    if current_leaves.len() == 1 && current_leaves[0].as_slice() == root {
        Ok(())
    } else {
        Err(VerifyError::BatchProofInvalid)
    }
}

// ============================================================================
// BLS AGGREGATE SIGNATURE VERIFICATION
// ============================================================================

/// Verify BLS aggregate signature using RISC0 blst precompile
#[inline]
fn verify_bls_aggregate(msgp: &[u8], multi_sig: &MultiSigParsed) -> Result<(), VerifyError> {
    let (aggr_vk, aggr_sig) = aggregate_signatures_and_keys(&multi_sig)?;

    let sig = Signature::from_bytes(&aggr_sig).map_err(|_| VerifyError::BLSVerificationFailed)?;
    let pk = PublicKey::from_bytes(&aggr_vk).map_err(|_| VerifyError::BLSVerificationFailed)?;

    let result = sig.verify(false, msgp, &[], &[], &pk, false);

    if result == blst::BLST_ERROR::BLST_SUCCESS {
        Ok(())
    } else {
        Err(VerifyError::BLSVerificationFailed)
    }
}

/// Aggregate signatures and keys using Mithril's Figure 6 algorithm
#[inline]
fn aggregate_signatures_and_keys(
    multi_sig: &MultiSigParsed,
) -> Result<([u8; 96], [u8; 48]), VerifyError> {
    if multi_sig.signatures.is_empty() {
        return Err(VerifyError::BLSVerificationFailed);
    }

    if multi_sig.signatures.len() == 1 {
        return Ok((
            *multi_sig.signatures[0].vk_bytes,
            *multi_sig.signatures[0].sigma_bytes,
        ));
    }

    // Generate randomness from hash of all signatures
    let mut hashed_sigs = Blake2b::<blake2::digest::consts::U16>::new();
    for sig in &multi_sig.signatures {
        hashed_sigs.update(sig.sigma_bytes);
    }

    // Generate scalars (16 bytes each, 128 bits)
    let mut scalars = Vec::with_capacity(multi_sig.signatures.len() * 16);
    for (index, _) in multi_sig.signatures.iter().enumerate() {
        let mut hasher = hashed_sigs.clone();
        hasher.update((index as usize).to_be_bytes());
        scalars.extend_from_slice(hasher.finalize().as_ref());
    }

    // Convert to blst types
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

    // Scalar multiplication aggregation
    let agg_pk = pks.mult(&scalars, 128);
    let agg_sig = sigs.mult(&scalars, 128);

    let aggr_pk_bytes = agg_pk.to_public_key().to_bytes();
    let aggr_sig_bytes = agg_sig.to_signature().to_bytes();

    Ok((aggr_pk_bytes, aggr_sig_bytes))
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

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
