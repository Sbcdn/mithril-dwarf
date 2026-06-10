//! Phase 3 (cross-epoch chain checks) and phase 4 (BLS multi-signature,
//! Merkle batch proof, lottery).

use super::VerifyError;
use crate::parser::byte_deserializer::{
    CertificateZeroCopy, MultiSigParsed, SignatureBasicZeroCopy,
};
use blake2::digest::consts::U32;
use blake2::{Blake2b, Blake2b512, Digest as Blake2Digest};
use crypto_ratio::RatioU512 as Ratio512;

use super::medium_checks::{
    EqSink, avk_to_json_hex_into, compute_protocol_parameters_digest, hex_digest_to_buf,
    parse_batch_proof,
};

use crypto_bigint::U512;

use blst::MultiPoint;
use blst::min_sig::{PublicKey, Signature};

/// `Blake2b::<U32>::digest([0u8])` — Merkle "phantom sibling" hash for
/// odd-cardinality levels. Precomputed; the `phantom_sibling_test`
/// unit test re-derives it and asserts equality.
const PHANTOM_SIBLING_BLAKE2B_256: [u8; 32] = [
    0x03, 0x17, 0x0a, 0x2e, 0x75, 0x97, 0xb7, 0xb7, 0xe3, 0xd8, 0x4c, 0x05, 0x39, 0x1d, 0x13,
    0x9a, 0x62, 0xb1, 0x57, 0xe7, 0x87, 0x86, 0xd8, 0xc0, 0x82, 0xf2, 0x9d, 0xcf, 0x4c, 0x11,
    0x13, 0x14,
];

#[cfg(test)]
mod phantom_sibling_test {
    use super::PHANTOM_SIBLING_BLAKE2B_256;
    use blake2::digest::consts::U32;
    use blake2::{Blake2b, Digest as _};

    #[test]
    fn phantom_sibling_const_matches_runtime() {
        let runtime: [u8; 32] = Blake2b::<U32>::digest([0u8]).into();
        assert_eq!(runtime, PHANTOM_SIBLING_BLAKE2B_256);
    }
}

/// Cross-epoch only: `current.aggregate_verification_key` must hex-equal
/// the `NextAggregateVerificationKey` (discriminant 2) carried in the
/// previous cert's protocol message. Streams the AVK JSON hex into an
/// `EqSink` over the expected bytes.
#[inline]
pub fn verify_avk_chain(
    current_cert: &CertificateZeroCopy,
    previous_cert: &CertificateZeroCopy,
) -> Result<(), VerifyError> {
    // `NextAggregateVerificationKey` is discriminant 3 at upstream Mithril 2617.0.
    let next_avk = find_protocol_message_part(&previous_cert.protocol_message.parts, 3)
        .ok_or(VerifyError::NextAVKNotFound)?;

    let mut sink = EqSink::new(next_avk);
    avk_to_json_hex_into(&mut sink, &current_cert.aggregate_verification_key)?;
    if !sink.matches() {
        return Err(VerifyError::AVKMismatch);
    }
    Ok(())
}

/// Same-epoch: direct field compare. Cross-epoch: recomputes
/// `pp_digest` and delegates to
/// [`verify_protocol_params_chain_cross_epoch_with_pp_digest`].
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
        Ok(())
    } else {
        let digest = compute_protocol_parameters_digest(
            current_cert.metadata.k,
            current_cert.metadata.m,
            current_cert.metadata.phi_f,
        );
        verify_protocol_params_chain_cross_epoch_with_pp_digest(
            current_cert,
            previous_cert,
            &digest,
        )
    }
}

/// `hex(pp_digest)` must equal the `NextProtocolParameters`
/// (discriminant 3) hash carried by the previous cert. Cross-epoch only.
#[inline]
pub fn verify_protocol_params_chain_cross_epoch_with_pp_digest(
    current_cert: &CertificateZeroCopy,
    previous_cert: &CertificateZeroCopy,
    pp_digest: &[u8; 32],
) -> Result<(), VerifyError> {
    // `NextProtocolParameters` is discriminant 4 at upstream Mithril 2617.0.
    let next_params_hash = find_protocol_message_part(&previous_cert.protocol_message.parts, 4)
        .ok_or(VerifyError::NextProtocolParamsNotFound)?;
    let _ = current_cert; // pp_digest already encodes current_cert.metadata.
    let mut computed_hex = [0u8; 64];
    hex_digest_to_buf(pp_digest, &mut computed_hex);

    if computed_hex != *next_params_hash {
        return Err(VerifyError::ProtocolParamsMismatch);
    }
    Ok(())
}

/// BLS multi-signature verification (phase 4).
///
/// `c = ln(1 - phi_f)` and the Taylor coefficient `3` are hoisted to
/// per-cert scope so [`preliminary_verify`] doesn't rebuild them per
/// index. `c_opt = None` shortcuts `phi_f == 1` (lottery always won).
#[inline]
pub fn verify_bls_multisig(cert: &CertificateZeroCopy) -> Result<(), VerifyError> {
    let multi_sig = match &cert.signature {
        SignatureBasicZeroCopy::Multi { signature, .. } => signature,
        SignatureBasicZeroCopy::Genesis { .. } => return Ok(()),
    };

    // `aggregate_signatures_and_keys` hashes each signer's iteration
    // index as `usize.to_be_bytes()`. On RISC0 (RV32) `usize = u32`,
    // so indices >= 2^32 would alias. The realistic memory ceiling
    // bars this in practice; the assert pins the assumption (see
    // divergence #5). Comparison is `as u64` so RV32's narrower usize
    // does not turn `1u64 << 32` into 0.
    assert!(
        (multi_sig.signatures.len() as u64) < (1u64 << 32),
        "BLS multi-signature carries {} signers; must be < 2^32",
        multi_sig.signatures.len(),
    );

    let msgp = prepare_message_with_root(cert.signed_message, &cert.aggregate_verification_key)?;

    let phi_f = cert.metadata.phi_f;
    let c_opt = if (phi_f - 1.0).abs() < f64::EPSILON {
        None
    } else {
        Some(
            Ratio512::from_float((1.0 - phi_f).ln())
                .expect("phi_f in (0,1); ln finite"),
        )
    };
    let three = Ratio512::from_u64(3, 1);

    preliminary_verify(
        &multi_sig,
        &msgp,
        cert.metadata.k,
        cert.metadata.m,
        c_opt.as_ref(),
        &three,
        cert.aggregate_verification_key.total_stake,
    )?;

    verify_merkle_batch_proof(&multi_sig, &cert.aggregate_verification_key)?;
    verify_bls_aggregate(&msgp, &multi_sig)?;

    Ok(())
}

/// `signed_message (64) || avk.root (32)` on the stack. The length
/// checks turn a parser-surfaced malformed cert into `FormatError`
/// rather than a `copy_from_slice` panic.
#[inline]
fn prepare_message_with_root(
    signed_message: &[u8],
    avk: &crate::parser::byte_deserializer::AggregateVerificationKeyParsed,
) -> Result<[u8; 96], VerifyError> {
    if signed_message.len() != 64 || avk.root.len() != 32 {
        return Err(VerifyError::FormatError);
    }
    let mut msgp = [0u8; 96];
    msgp[..64].copy_from_slice(signed_message);
    msgp[64..].copy_from_slice(avk.root);
    Ok(msgp)
}

/// Indices, lottery, and quorum. `c = ln(1 - phi_f)` and the Taylor
/// coefficient `three` come from the caller; `None` short-circuits the
/// lottery when `phi_f == 1`.
///
/// Per-signer `x = -w * c` (where `w = stake/total_stake`) is constant
/// across each signer's indices and hoisted out of the inner loop.
///
/// Uniqueness uses a `(m+1)`-bit bitset of `u32` cells; on RV32 every
/// op is single-instruction width, and the walk is O(N) without a
/// sort.
#[inline]
fn preliminary_verify(
    multi_sig: &MultiSigParsed,
    msgp: &[u8],
    k: u64,
    m: u64,
    c: Option<&Ratio512>,
    three: &Ratio512,
    total_stake: u64,
) -> Result<(), VerifyError> {
    let total_indices: usize = multi_sig
        .signatures
        .iter()
        .map(|s| s.indexes_len())
        .sum();
    let mut indices: Vec<u32> = Vec::with_capacity(total_indices);

    // Pre-absorb the per-cert `"map" || msgp` prefix once; clone the
    // hasher per index instead of re-absorbing 99 bytes per call.
    let base_hasher = Blake2b512::new()
        .chain_update(b"map")
        .chain_update(msgp);

    for sig in &multi_sig.signatures {
        let x_opt = c.map(|c_ref| {
            let w = Ratio512::from_u64(sig.stake, total_stake);
            w.mul(c_ref).neg()
        });

        for index in sig.indexes() {
            if index > m {
                return Err(VerifyError::IndexOutOfBounds);
            }

            let ev = evaluate_dense_mapping_with_base(&base_hasher, index, sig.sigma_bytes);
            let won = match &x_opt {
                None => true,
                Some(x) => is_lottery_won_with_x(ev, x, three),
            };
            if !won {
                return Err(VerifyError::LotteryLost);
            }

            // Safe truncation: `index <= m` and the bitset below
            // covers `[0, m]`. If `m > u32::MAX`, the bitset alloc
            // already rejects via panic on the same path.
            indices.push(index as u32);
        }
    }

    if (indices.len() as u64) < k {
        return Err(VerifyError::NoQuorum);
    }

    let bitset_words = ((m as usize) / 32) + 1;
    let mut seen: Vec<u32> = vec![0u32; bitset_words];
    for &idx in &indices {
        let idx_us = idx as usize;
        let word = idx_us >> 5;
        let mask = 1u32 << (idx_us & 31);
        if seen[word] & mask != 0 {
            return Err(VerifyError::IndexNotUnique);
        }
        seen[word] |= mask;
    }

    Ok(())
}

/// `H("map" || msg || index || sigma)` with `"map" || msg` already
/// absorbed into `base`. Returns `U512` directly to skip the
/// `[u8; 64]` → `U512` reparse per index.
#[inline]
fn evaluate_dense_mapping_with_base(
    base: &Blake2b512,
    index: u64,
    sigma: &[u8; 48],
) -> U512 {
    let digest = base
        .clone()
        .chain_update(index.to_le_bytes())
        .chain_update(sigma)
        .finalize();
    U512::from_le_slice(digest.as_ref())
}

// LOTTERY VERIFICATION

/// Check if the lottery is won, given the per-signer constant
/// `x = -w * ln(1 - phi_f)` precomputed by the caller and `ev` (the
/// dense-mapping output) as a `U512`.
///
/// Mathematical background:
/// - Lottery won if: q < exp(x)
/// - Where: q = 2^512 / (2^512 - ev)
///
/// Only the `ev`-dependent `q` and the Taylor comparison run per
/// index. The `phi_f == 1` short-circuit and the `w`/`x` derivation
/// have been hoisted to `verify_bls_multisig` and `preliminary_verify`.
/// `three` is also a per-cert constant — passed in so Ratio512 init
/// doesn't happen per index.
///
/// # Optimizations
///
/// Lottery test: `q < exp(x)` where `q = 2^512 / (2^512 - ev)`.
/// `q` is already coprime so reduction is skipped.
#[inline]
fn is_lottery_won_with_x(ev: U512, x: &Ratio512, three: &Ratio512) -> bool {
    let ev_max = U512::MAX;
    let denominator = ev_max.wrapping_sub(&ev);
    let q = Ratio512::new_raw(ev_max, denominator, false);
    taylor_comparison(1000, q, x, three)
}

/// `cmp < exp(x)` via Taylor series with a `3 * term` error bound.
/// Returns false if `cmp > phi + err`, true if `cmp < phi - err`,
/// otherwise iterates. Falls through to `false` (lottery lost) if the
/// bound is reached without convergence.
#[inline]
fn taylor_comparison(bound: usize, cmp: Ratio512, x: &Ratio512, three: &Ratio512) -> bool {
    let mut new_x = x.clone();
    let mut phi = Ratio512::one();
    // Factorial counter (bounded by `bound`); u64 lets `div_by_u64` scale the
    // denominator with a single-limb multiply.
    let mut divisor: u64 = 1;

    for _ in 0..bound {
        phi = phi.add(&new_x);

        divisor += 1;
        new_x = new_x.mul(x).div_by_u64(divisor);

        if new_x.numer.bits() > 450 || new_x.denom.bits() > 450 {
            new_x.normalize();
        }
        if phi.numer.bits() > 450 || phi.denom.bits() > 450 {
            phi.normalize();
        }

        let error_term = new_x.abs().mul(three);
        // (phi + err, phi - err) sharing the cross-multiplications: 3 wide-muls
        // instead of 6 per Taylor iteration. Bit-identical to the two adds.
        let (mut phi_plus, mut phi_minus) = phi.add_sub(&error_term);

        if phi_plus.numer.bits() > 400 || phi_plus.denom.bits() > 400 {
            phi_plus.normalize();
        }
        if phi_minus.numer.bits() > 400 || phi_minus.denom.bits() > 400 {
            phi_minus.normalize();
        }

        if cmp.gt(&phi_plus) {
            return false;
        }
        if cmp.lt(&phi_minus) {
            return true;
        }
    }

    false
}

/// Merkle batch-proof verification. Index sortedness uses `<=` (not
/// strict `<`) to match upstream's sort-and-equality check, which
/// admits equal-consecutive entries.
#[inline]
fn verify_merkle_batch_proof(
    multi_sig: &MultiSigParsed,
    avk: &crate::parser::byte_deserializer::AggregateVerificationKeyParsed,
) -> Result<(), VerifyError> {
    let proof = parse_batch_proof(multi_sig.batch_proof_bytes)?;

    if multi_sig.signatures.len() != proof.indices.len() {
        return Err(VerifyError::BatchProofInvalid);
    }
    if !proof.indices.windows(2).all(|w| w[0] <= w[1]) {
        return Err(VerifyError::BatchProofInvalid);
    }

    let mut leaves: Vec<[u8; 32]> = Vec::with_capacity(multi_sig.signatures.len());
    for sig in &multi_sig.signatures {
        let leaf_bytes = serialize_registered_party(sig.vk_bytes, sig.stake);
        leaves.push(Blake2b::<U32>::digest(&leaf_bytes).into());
    }

    verify_batch_path(
        leaves,
        &proof.indices,
        proof.values,
        avk.root,
        avk.nr_leaves as usize,
    )?;

    Ok(())
}

/// `vk (96 BE) || stake (8 BE)` — the canonical `RegisteredParty` form.
#[inline]
fn serialize_registered_party(vk: &[u8; 96], stake: u64) -> [u8; 104] {
    let mut result = [0u8; 104];
    result[..96].copy_from_slice(vk);
    result[96..].copy_from_slice(&stake.to_be_bytes());
    result
}

/// Verify the batch Merkle path. `leaves` is moved in and reused as
/// the walking buffer; the per-level scratch vectors are hoisted out
/// of the level loop and rotated via `mem::swap` to keep allocations
/// at one per buffer per cert.
#[inline]
fn verify_batch_path(
    leaves: Vec<[u8; 32]>,
    indices: &[u64],
    values: &[u8],
    root: &[u8],
    nr_leaves: usize,
) -> Result<(), VerifyError> {
    let pot = nr_leaves.next_power_of_two();
    let nr_nodes = nr_leaves + pot - 1;
    let leaf_offset = pot - 1;

    let mut ordered_indices: Vec<usize> = indices
        .iter()
        .map(|&i| i as usize + leaf_offset)
        .collect();

    let mut current_leaves: Vec<[u8; 32]> = leaves;
    let mut scratch_hashes: Vec<[u8; 32]> = Vec::with_capacity(current_leaves.len());
    let mut scratch_indices: Vec<usize> = Vec::with_capacity(ordered_indices.len());
    let mut values_iter = values.chunks_exact(32);
    let mut idx = ordered_indices[0];

    // Hoisted Blake2b state; `finalize_reset` re-zeroes the buffer
    // without re-running the parameter-block init.
    let mut node_h = Blake2b::<U32>::new();

    while idx > 0 {
        scratch_hashes.clear();
        scratch_indices.clear();
        let mut i = 0;

        idx = parent(ordered_indices[i]);

        while i < ordered_indices.len() {
            scratch_indices.push(parent(ordered_indices[i]));

            if ordered_indices[i] & 1 == 0 {
                // Even node - sibling is from values
                let sibling = values_iter.next().ok_or(VerifyError::BatchProofInvalid)?;
                node_h.update(sibling);
                node_h.update(&current_leaves[i]);
                scratch_hashes.push(node_h.finalize_reset().into());
            } else {
                // Odd node
                let sib = sibling(ordered_indices[i]);
                if i < ordered_indices.len() - 1 && ordered_indices[i + 1] == sib {
                    node_h.update(&current_leaves[i]);
                    node_h.update(&current_leaves[i + 1]);
                    scratch_hashes.push(node_h.finalize_reset().into());
                    i += 1;
                } else if sib < nr_nodes {
                    let sibling_val = values_iter.next().ok_or(VerifyError::BatchProofInvalid)?;
                    node_h.update(&current_leaves[i]);
                    node_h.update(sibling_val);
                    scratch_hashes.push(node_h.finalize_reset().into());
                } else {
                    node_h.update(&current_leaves[i]);
                    node_h.update(PHANTOM_SIBLING_BLAKE2B_256);
                    scratch_hashes.push(node_h.finalize_reset().into());
                }
            }
            i += 1;
        }

        // Rotate scratch in for the next level.
        core::mem::swap(&mut current_leaves, &mut scratch_hashes);
        core::mem::swap(&mut ordered_indices, &mut scratch_indices);
    }

    if current_leaves.len() == 1 && &current_leaves[0][..] == root {
        Ok(())
    } else {
        Err(VerifyError::BatchProofInvalid)
    }
}

/// Aggregate BLS signature verification via the RISC0 `blst` precompile.
/// [`aggregate_signatures_and_keys`] returns live `PublicKey` /
/// `Signature` so no bytes round-trip / subgroup re-check is needed —
/// the aggregates are scalar multiples of subgroup elements by
/// construction.
#[inline]
fn verify_bls_aggregate(msgp: &[u8], multi_sig: &MultiSigParsed) -> Result<(), VerifyError> {
    let (pk, sig) = aggregate_signatures_and_keys(multi_sig)?;

    let result = sig.verify(false, msgp, &[], &[], &pk, false);

    if result == blst::BLST_ERROR::BLST_SUCCESS {
        Ok(())
    } else {
        Err(VerifyError::BLSVerificationFailed)
    }
}

/// Mithril Figure 6 — aggregate signers' keys and sigs into single
/// `PublicKey` / `Signature` values. Single-signer fast path parses
/// from bytes; multi-signer path goes straight from `MultiPoint::mult`
/// to `to_public_key()` / `to_signature()` without a bytes round-trip.
///
/// `#[inline(always)]` is load-bearing: the fused scalar-gen + parse
/// loops would otherwise miss LLVM's inline cost threshold and add
/// ~75k cycles per cert on mainnet inputs.
#[inline(always)]
fn aggregate_signatures_and_keys(
    multi_sig: &MultiSigParsed,
) -> Result<(PublicKey, Signature), VerifyError> {
    if multi_sig.signatures.is_empty() {
        return Err(VerifyError::BLSVerificationFailed);
    }

    if multi_sig.signatures.len() == 1 {
        let pk = PublicKey::from_bytes(multi_sig.signatures[0].vk_bytes)
            .map_err(|_| VerifyError::BLSVerificationFailed)?;
        let sig = Signature::from_bytes(multi_sig.signatures[0].sigma_bytes)
            .map_err(|_| VerifyError::BLSVerificationFailed)?;
        return Ok((pk, sig));
    }

    let mut hashed_sigs = Blake2b::<blake2::digest::consts::U16>::new();
    for sig in &multi_sig.signatures {
        hashed_sigs.update(sig.sigma_bytes);
    }

    // 128-bit scalars per signer.
    let mut scalars = Vec::with_capacity(multi_sig.signatures.len() * 16);
    for (index, _) in multi_sig.signatures.iter().enumerate() {
        let mut hasher = hashed_sigs.clone();
        hasher.update((index as usize).to_be_bytes());
        scalars.extend_from_slice(hasher.finalize().as_ref());
    }

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

    let agg_pk = pks.mult(&scalars, 128);
    let agg_sig = sigs.mult(&scalars, 128);

    Ok((agg_pk.to_public_key(), agg_sig.to_signature()))
}

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
