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

    #[cfg(feature = "guest-bench")]
    let t = risc0_zkvm::guest::env::cycle_count();
    preliminary_verify(
        &multi_sig,
        &msgp,
        cert.metadata.k,
        cert.metadata.m,
        c_opt.as_ref(),
        &three,
        cert.aggregate_verification_key.total_stake,
    )?;
    #[cfg(feature = "guest-bench")]
    let t = {
        let now = risc0_zkvm::guest::env::cycle_count();
        eprintln!("[DWARF-BENCH] preliminary_verify={}", now - t);
        now
    };

    verify_merkle_batch_proof(&multi_sig, &cert.aggregate_verification_key)?;
    #[cfg(feature = "guest-bench")]
    let t = {
        let now = risc0_zkvm::guest::env::cycle_count();
        eprintln!("[DWARF-BENCH] merkle_batch_proof={}", now - t);
        now
    };

    verify_bls_aggregate(&msgp, &multi_sig)?;
    #[cfg(feature = "guest-bench")]
    {
        let now = risc0_zkvm::guest::env::cycle_count();
        eprintln!("[DWARF-BENCH] bls_aggregate={}", now - t);
    }

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

    #[cfg(feature = "guest-bench")]
    let (mut dense_cyc, mut lott_cyc): (u64, u64) = (0, 0);

    for sig in &multi_sig.signatures {
        // The Taylor-bound sequence depends only on the per-signer
        // `x = -w*ln(1-phi_f)` and the per-cert `three`, so it is identical
        // across all of this signer's indices. Build it once and let each
        // index reuse the cached `(phi_plus, phi_minus)` bounds; only the
        // `q < exp(x)` compare is per-index. `None` keeps the `phi_f == 1`
        // short-circuit (lottery always won).
        let mut bounds = c.map(|c_ref| {
            let w = Ratio512::from_u64(sig.stake, total_stake);
            TaylorBounds::new(w.mul(c_ref).neg(), three)
        });

        for index in sig.indexes() {
            if index > m {
                return Err(VerifyError::IndexOutOfBounds);
            }

            #[cfg(feature = "guest-bench")]
            let d0 = risc0_zkvm::guest::env::cycle_count();
            let ev = evaluate_dense_mapping_with_base(&base_hasher, index, sig.sigma_bytes);
            #[cfg(feature = "guest-bench")]
            let l0 = {
                let now = risc0_zkvm::guest::env::cycle_count();
                dense_cyc += now - d0;
                now
            };
            let won = match &mut bounds {
                None => true,
                Some(b) => b.lottery_won(lottery_q(ev)),
            };
            #[cfg(feature = "guest-bench")]
            {
                lott_cyc += risc0_zkvm::guest::env::cycle_count() - l0;
            }
            if !won {
                return Err(VerifyError::LotteryLost);
            }

            // Safe truncation: `index <= m` and the bitset below
            // covers `[0, m]`. If `m > u32::MAX`, the bitset alloc
            // already rejects via panic on the same path.
            indices.push(index as u32);
        }
    }

    #[cfg(feature = "guest-bench")]
    eprintln!(
        "[DWARF-BENCH]   dense_mapping={dense_cyc} lottery_compare={lott_cyc} indices={}",
        indices.len()
    );

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

/// `q = 2^512 / (2^512 - ev)` as an unreduced ratio. `ev` is the
/// dense-mapping output; the lottery is won iff `q < exp(x)`. `q` is
/// already coprime, so reduction is skipped (`new_raw`).
#[inline]
fn lottery_q(ev: U512) -> Ratio512 {
    let ev_max = U512::MAX;
    Ratio512::new_raw(ev_max, ev_max.wrapping_sub(&ev), false)
}

/// Taylor iteration ceiling; matches the historical `taylor_comparison`
/// bound. An index that doesn't resolve within this many terms loses.
const TAYLOR_BOUND: usize = 1000;

/// One cached Taylor term: the error-bound interval plus the `q`-independent
/// half of each comparison cross-multiply, precomputed once per signer.
struct Bound {
    phi_plus: Ratio512,
    phi_minus: Ratio512,
    // `U512::MAX * phi.denom` as `(lo, hi)` — the `q.numer * bound.denom`
    // side of the compare (`q.numer` is always `U512::MAX`). Shared across
    // all of a signer's indices; the per-index compare then needs only the
    // `bound.numer * q.denom` mul_wide, halving the per-level wide-muls.
    ad_plus: (U512, U512),
    ad_minus: (U512, U512),
}

/// Per-signer Taylor expansion of `exp(x)` with a `3 * term` error bound.
///
/// The `(phi_plus, phi_minus)` bound sequence is a pure function of `x`
/// (per-signer) and `three` (per-cert): the per-index value `q` enters
/// only at the final compare. [`lottery_won`](Self::lottery_won) lazily
/// extends and caches the sequence so a signer's N indices build it once
/// instead of N times; the per-index residual is the two `q.gt`/`q.lt`
/// cross-multiplies, each with the `q.numer`-side product precached
/// ([`Bound`]). Emitted bounds and verdicts are bit-identical to
/// recomputing the series per index — only the wide-mul/normalize work is
/// shared.
struct TaylorBounds<'a> {
    x: Ratio512,
    three: &'a Ratio512,
    // Carried series state, advanced one term per `extend`.
    new_x: Ratio512,
    phi: Ratio512,
    // Factorial counter; u64 lets `div_by_u64` scale the denominator with
    // a single-limb multiply.
    divisor: u64,
    bounds: Vec<Bound>,
}

impl<'a> TaylorBounds<'a> {
    #[inline]
    fn new(x: Ratio512, three: &'a Ratio512) -> Self {
        Self {
            new_x: x.clone(),
            x,
            three,
            phi: Ratio512::one(),
            divisor: 1,
            bounds: Vec::new(),
        }
    }

    /// Append the next `(phi_plus, phi_minus)` term, mirroring one
    /// iteration of the original series. Returns `false` once
    /// `TAYLOR_BOUND` terms exist.
    #[inline]
    fn extend(&mut self) -> bool {
        if self.bounds.len() >= TAYLOR_BOUND {
            return false;
        }
        self.phi = self.phi.add(&self.new_x);

        self.divisor += 1;
        self.new_x = self.new_x.mul(&self.x).div_by_u64(self.divisor);

        if self.new_x.numer.bits() > 450 || self.new_x.denom.bits() > 450 {
            self.new_x.normalize();
        }
        if self.phi.numer.bits() > 450 || self.phi.denom.bits() > 450 {
            self.phi.normalize();
        }

        let error_term = self.new_x.abs().mul(self.three);
        // (phi + err, phi - err) sharing the cross-multiplications: 3 wide-muls
        // instead of 6 per Taylor iteration. Bit-identical to the two adds.
        let (mut phi_plus, mut phi_minus) = self.phi.add_sub(&error_term);

        if phi_plus.numer.bits() > 400 || phi_plus.denom.bits() > 400 {
            phi_plus.normalize();
        }
        if phi_minus.numer.bits() > 400 || phi_minus.denom.bits() > 400 {
            phi_minus.normalize();
        }

        // Precompute the `q.numer`-side product (`q.numer == U512::MAX`).
        let ad_plus = U512::MAX.mul_wide(&phi_plus.denom);
        let ad_minus = U512::MAX.mul_wide(&phi_minus.denom);
        self.bounds.push(Bound { phi_plus, phi_minus, ad_plus, ad_minus });
        true
    }

    /// `q < exp(x)`: walk the cached bounds, extending as needed.
    /// `q > phi_plus` ⇒ lost, `q < phi_minus` ⇒ won; exhausting the
    /// bound without a decision ⇒ lost. Identical verdict to running the
    /// full series against `q` from scratch.
    #[inline]
    fn lottery_won(&mut self, q: Ratio512) -> bool {
        debug_assert!(q.numer == U512::MAX && !q.negative, "q must be lottery_q output");
        let mut level = 0;
        loop {
            if level >= self.bounds.len() && !self.extend() {
                return false;
            }
            let b = &self.bounds[level];
            if q_gt_bound(&q, &b.phi_plus, &b.ad_plus) {
                return false;
            }
            if q_lt_bound(&q, &b.phi_minus, &b.ad_minus) {
                return true;
            }
            level += 1;
        }
    }
}

/// `q > bound`, with `q.numer * bound.denom` supplied precomputed as
/// `ad = (lo, hi)`. `q` is the positive lottery ratio (`numer = U512::MAX`).
///
/// Bit-identical to `q.gt(bound)`: for a non-negative `bound` the factored
/// cross-multiply (`q.numer*bound.denom` vs `bound.numer*q.denom`) equals
/// the full one, and crypto-ratio's `mag_diff` / small-value fast paths
/// only ever short-circuit to that same boolean. The rare negative `bound`
/// defers to `Ratio512::gt` for its sign handling.
#[inline]
fn q_gt_bound(q: &Ratio512, bound: &Ratio512, ad: &(U512, U512)) -> bool {
    if bound.negative {
        return q.gt(bound);
    }
    let (bc_lo, bc_hi) = bound.numer.mul_wide(&q.denom);
    match ad.1.cmp(&bc_hi) {
        core::cmp::Ordering::Greater => true,
        core::cmp::Ordering::Less => false,
        core::cmp::Ordering::Equal => ad.0.cmp(&bc_lo) == core::cmp::Ordering::Greater,
    }
}

/// `q < bound`; mirror of [`q_gt_bound`]. Defers to `Ratio512::lt` for a
/// negative `bound`.
#[inline]
fn q_lt_bound(q: &Ratio512, bound: &Ratio512, ad: &(U512, U512)) -> bool {
    if bound.negative {
        return q.lt(bound);
    }
    let (bc_lo, bc_hi) = bound.numer.mul_wide(&q.denom);
    match ad.1.cmp(&bc_hi) {
        core::cmp::Ordering::Less => true,
        core::cmp::Ordering::Greater => false,
        core::cmp::Ordering::Equal => ad.0.cmp(&bc_lo) == core::cmp::Ordering::Less,
    }
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

/// Verbatim copy of the pre-cache per-index series (the production code
/// before `TaylorBounds`). Module-scoped so both test modules share it as
/// the regression oracle.
#[cfg(test)]
pub(super) fn taylor_comparison_ref(
    bound: usize,
    cmp: &Ratio512,
    x: &Ratio512,
    three: &Ratio512,
) -> bool {
    let mut new_x = x.clone();
    let mut phi = Ratio512::one();
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

#[cfg(test)]
mod taylor_cache_tests {
    use super::*;
    use super::taylor_comparison_ref;

    /// One cache instance, reused across many `q` (mirrors a signer with
    /// many indices), must match a fresh reference run for each `q` — and
    /// the result must be order-independent.
    #[test]
    fn cached_bounds_match_reference() {
        let three = Ratio512::from_u64(3, 1);
        let phis = [0.05_f64, 0.2, 0.5, 0.9];
        let stakes: [(u64, u64); 4] = [(1, 1000), (7, 1000), (250, 1000), (999, 1000)];

        // Well-distributed 512-bit `ev` values, as the real dense mapping
        // would produce. Includes the q≈1 (ev=0) and q-huge (ev≈MAX) ends.
        let mut evs: Vec<U512> = vec![U512::ZERO, U512::MAX, U512::MAX.wrapping_sub(&U512::ONE)];
        for seed in 0u64..40 {
            let d = Blake2b512::digest(seed.to_le_bytes());
            evs.push(U512::from_le_slice(d.as_ref()));
        }

        let mut n_won = 0usize;
        let mut n_lost = 0usize;
        for &phi_f in &phis {
            let c = Ratio512::from_float((1.0 - phi_f).ln()).expect("ln finite");
            for &(stake, total) in &stakes {
                let x = Ratio512::from_u64(stake, total).mul(&c).neg();
                let mut cache = TaylorBounds::new(x.clone(), &three);
                for ev in &evs {
                    let q = lottery_q(*ev);
                    let got = cache.lottery_won(q.clone());
                    let want = taylor_comparison_ref(TAYLOR_BOUND, &q, &x, &three);
                    assert_eq!(
                        got, want,
                        "phi_f={phi_f} stake={stake}/{total} ev={ev:?}"
                    );
                    if got { n_won += 1 } else { n_lost += 1 }
                }
            }
        }
        // Non-vacuity: the sweep must contain BOTH outcomes, else a bug
        // that always returns one value would pass silently.
        assert!(n_won > 0 && n_lost > 0, "sweep vacuous: won={n_won} lost={n_lost}");
        eprintln!("cached_bounds_match_reference: won={n_won} lost={n_lost}");
    }

    /// Definitive bit-equality pin on PRODUCTION data: parse a real SD
    /// cert and, for every signer's every lottery index, assert the
    /// cached path's won/lost decision equals a from-scratch run of the
    /// verbatim old series on the same `(q, x)`. Also forces a
    /// deep-iteration LOST case per real `x` (q from ev≈MAX), which the
    /// zero-stake mutation (x=0, resolves at level 0) can't reach.
    /// Catches any divergence the positive corpus (all-won) would mask.
    #[test]
    fn real_cert_per_index_decisions_match_reference() {
        use crate::parser::byte_deserializer::{certificate_from_bytes, SignatureBasicZeroCopy};

        let bytes = include_bytes!("../../benches/data/cert_current.bin");
        let cert = certificate_from_bytes(bytes).expect("parse real SD cert");
        let multi_sig = match &cert.signature {
            SignatureBasicZeroCopy::Multi { signature, .. } => signature,
            _ => panic!("expected a standard multi-sig cert"),
        };

        let phi_f = cert.metadata.phi_f;
        let total_stake = cert.aggregate_verification_key.total_stake;
        assert!((phi_f - 1.0).abs() >= f64::EPSILON, "phi_f==1 would skip the lottery");
        let c = Ratio512::from_float((1.0 - phi_f).ln()).expect("ln finite");
        let three = Ratio512::from_u64(3, 1);

        let msgp = prepare_message_with_root(cert.signed_message, &cert.aggregate_verification_key)
            .expect("msgp");
        let base = Blake2b512::new().chain_update(b"map").chain_update(&msgp);

        // ev≈MAX → q huge → forced LOST on every real x (deep path).
        let q_lost = lottery_q(U512::MAX.wrapping_sub(&U512::ONE));

        let mut signers = 0usize;
        let mut indices = 0usize;
        let mut real_won = 0usize;
        for sig in &multi_sig.signatures {
            signers += 1;
            let x = Ratio512::from_u64(sig.stake, total_stake).mul(&c).neg();
            let mut cache = TaylorBounds::new(x.clone(), &three);

            for index in sig.indexes() {
                indices += 1;
                let ev = evaluate_dense_mapping_with_base(&base, index, sig.sigma_bytes);
                let q = lottery_q(ev);
                let got = cache.lottery_won(q.clone());
                let want = taylor_comparison_ref(TAYLOR_BOUND, &q, &x, &three);
                assert_eq!(got, want, "signer stake={} index={index}", sig.stake);
                if got { real_won += 1 }
            }

            // Forced-lost probe on this signer's real x, on the SAME
            // reused cache (mirrors production reuse).
            let got_lost = cache.lottery_won(q_lost.clone());
            let want_lost = taylor_comparison_ref(TAYLOR_BOUND, &q_lost, &x, &three);
            assert_eq!(got_lost, want_lost, "forced-lost mismatch, stake={}", sig.stake);
            assert!(!want_lost, "q≈MAX must lose against exp(x>=0)");
        }

        assert!(signers > 0 && indices > 0, "no signers/indices exercised");
        assert_eq!(real_won, indices, "a real cert's indices must all win");
        eprintln!(
            "real_cert_per_index: signers={signers} indices={indices} \
             indices_per_signer={:.1}",
            indices as f64 / signers as f64
        );
    }

    /// The factored `q_gt_bound` / `q_lt_bound` must equal crypto-ratio's
    /// real `Ratio512::gt` / `lt` for every `(q, bound)` — this is the
    /// bit-exactness proof for the precomputed-`ad` optimisation,
    /// independent of the Taylor series. Sweeps bounds across magnitudes
    /// (near 1, ≫1, ≪1, tiny, huge), signs, and real Taylor terms, against
    /// `q` from the full `ev` range.
    #[test]
    fn factored_compare_matches_cryptoratio() {
        // q values: ev=0 (q≈1), ev≈MAX (q huge), and a hash sweep.
        let mut qs: Vec<Ratio512> = vec![
            lottery_q(U512::ZERO),
            lottery_q(U512::ONE),
            lottery_q(U512::MAX),
            lottery_q(U512::MAX.wrapping_sub(&U512::ONE)),
        ];
        for s in 0u64..64 {
            let d: [u8; 64] = Blake2b512::digest((s ^ 0x5151).to_le_bytes()).into();
            qs.push(lottery_q(U512::from_le_slice(&d)));
        }

        // Synthetic bounds across magnitudes and signs.
        let mut bounds: Vec<Ratio512> = Vec::new();
        let pairs: &[(u64, u64)] = &[
            (1, 1), (2, 1), (1, 2), (1000001, 1000000), (999999, 1000000),
            (1, 1_000_000_000), (1_000_000_000, 1), (3, 7), (7, 3), (1, u64::MAX),
            (u64::MAX, 1), (u64::MAX, u64::MAX),
        ];
        for &(a, b) in pairs {
            let r = Ratio512::from_u64(a, b);
            bounds.push(r.clone());
            bounds.push(r.neg()); // exercise the negative-bound fallback
        }
        // Real Taylor terms (the actual phi_plus/phi_minus shapes). Tiny
        // per-signer `w` and a shallow depth keep the series inside U512
        // (deep levels on a larger x hit the pre-existing overflow #9,
        // which is irrelevant to the compare being tested here).
        let three = Ratio512::from_u64(3, 1);
        for &phi_f in &[0.05_f64, 0.2, 0.5] {
            let c = Ratio512::from_float((1.0 - phi_f).ln()).unwrap();
            let x = Ratio512::from_u64(1, 1000).mul(&c).neg();
            let mut tb = TaylorBounds::new(x, &three);
            while tb.bounds.len() < 6 && tb.extend() {}
            for b in &tb.bounds {
                bounds.push(b.phi_plus.clone());
                bounds.push(b.phi_minus.clone());
            }
        }

        let (mut gt_t, mut gt_f, mut lt_t, mut lt_f) = (0u64, 0u64, 0u64, 0u64);
        for bound in &bounds {
            let ad = U512::MAX.mul_wide(&bound.denom);
            for q in &qs {
                let g = q_gt_bound(q, bound, &ad);
                let l = q_lt_bound(q, bound, &ad);
                assert_eq!(g, q.gt(bound), "gt mismatch q.denom={:?} bound={:?}", q.denom, bound);
                assert_eq!(l, q.lt(bound), "lt mismatch q.denom={:?} bound={:?}", q.denom, bound);
                if g { gt_t += 1 } else { gt_f += 1 }
                if l { lt_t += 1 } else { lt_f += 1 }
            }
        }
        // Non-vacuity: both outcomes must appear for both operators.
        assert!(gt_t > 0 && gt_f > 0 && lt_t > 0 && lt_f > 0,
            "vacuous: gt({gt_t},{gt_f}) lt({lt_t},{lt_f})");
        eprintln!("factored_compare: {} (q,bound) pairs; gt(T={gt_t},F={gt_f}) lt(T={lt_t},F={lt_f})",
            bounds.len() * qs.len());
    }

    /// Adversarial primitive fuzz targeting the exact region a comparison
    /// bug hides in: bounds constructed within a few ULPs of `q`, so the
    /// 1024-bit cross-products `M*d` and `n*D` tie in their high limb and
    /// the decision falls to the low limb. (The end-to-end differential
    /// tests never reach this region — random `ev` puts `q` nowhere near a
    /// bound, and the boundary sweep targets `q ≈ exp(x)`, below
    /// `phi_plus`.) For every constructed pair, `q_gt_bound`/`q_lt_bound`
    /// must equal crypto-ratio's `gt`/`lt`. Asserts the tied-high-limb
    /// path is actually exercised, so the test can never pass vacuously.
    #[test]
    #[ignore = "heavy adversarial primitive fuzz; run with --release -- --ignored"]
    fn factored_compare_adversarial_near_equal() {
        use crypto_bigint::Encoding;
        use num_bigint::{BigInt, Sign};

        let to_big = |u: &U512| BigInt::from_bytes_le(Sign::Plus, &u.to_le_bytes());
        let from_big = |b: &BigInt| -> Option<U512> {
            if b.sign() == Sign::Minus {
                return None;
            }
            let (_, mut le) = b.to_bytes_le();
            if le.len() > 64 {
                return None;
            }
            le.resize(64, 0);
            Some(U512::from_le_slice(&le))
        };

        let m_big = to_big(&U512::MAX);
        let (mut checked, mut tied) = (0u64, 0u64);
        for s in 0u64..6000 {
            let ev: [u8; 64] = Blake2b512::digest(s.to_le_bytes()).into();
            let q = lottery_q(U512::from_le_slice(&ev));
            if q.denom == U512::ZERO {
                continue;
            }
            let d_q_big = to_big(&q.denom);

            let dd: [u8; 64] = Blake2b512::digest((s ^ 0xBEEF_BEEF).to_le_bytes()).into();
            let d = U512::from_le_slice(&dd);
            if d == U512::ZERO {
                continue;
            }
            // n0 = floor(M*d / D): makes bound n0/d ≈ q = M/D.
            let n0 = (&m_big * to_big(&d)) / &d_q_big;
            for delta in -4i64..=4 {
                let Some(n_u) = from_big(&(&n0 + BigInt::from(delta))) else {
                    continue;
                };
                let bound = Ratio512::new_raw(n_u, d, false);
                let ad = U512::MAX.mul_wide(&bound.denom);
                let (_, bc_hi) = bound.numer.mul_wide(&q.denom);
                if ad.1 == bc_hi {
                    tied += 1;
                }
                assert_eq!(q_gt_bound(&q, &bound, &ad), q.gt(&bound), "gt s={s} d={delta}");
                assert_eq!(q_lt_bound(&q, &bound, &ad), q.lt(&bound), "lt s={s} d={delta}");
                checked += 1;
            }
        }
        assert!(tied > 500, "tied-high-limb path under-exercised: {tied}/{checked}");
        eprintln!("adversarial near-equal: checked={checked} tied_high_limb={tied}");
    }
}

/// Differential testing against a faithful re-port of upstream
/// `mithril-stm`'s lottery (rev `7e787de`,
/// `mithril-stm/src/proof_system/concatenation/eligibility.rs`). Two
/// goals, kept separate on purpose:
///
/// 1. **Regression (airtight):** the cached path must equal the
///    pre-cache series for EVERY input — proving the optimisation is a
///    behavioural no-op. Asserted hard.
/// 2. **No new upstream divergence:** the cache must agree with upstream
///    on exactly the same inputs the old code did. Since (1) holds this
///    is automatic, but we assert it explicitly.
///
/// dwarf carries two PRE-EXISTING numeric approximations vs upstream,
/// neither introduced by the cache: `q` uses `2^512-1` (upstream:
/// `2^512`), and `x` uses crypto-ratio `from_float` (~2^-52 truncation;
/// upstream: exact f64 rational). These only matter in a measure-~2^-52
/// sliver at the decision boundary; this module quantifies that sliver
/// and its direction so it is documented, not hidden.
#[cfg(test)]
mod upstream_differential {
    use super::*;
    use num_bigint::{BigInt, Sign};
    use num_rational::Ratio;
    use num_traits::{One, Signed};
    use std::ops::Neg;

    // ---- Faithful re-port of upstream (BigInt, arbitrary precision) ----
    // eligibility.rs L63-81. Char-for-char; diff against the pinned rev.
    fn upstream_taylor(bound: usize, cmp: Ratio<BigInt>, x: Ratio<BigInt>) -> bool {
        let mut new_x = x.clone();
        let mut phi: Ratio<BigInt> = One::one();
        let mut divisor: BigInt = One::one();
        for _ in 0..bound {
            phi += new_x.clone();
            divisor += 1;
            new_x = (new_x.clone() * x.clone()) / divisor.clone();
            let error_term = new_x.clone().abs() * BigInt::from(3);
            if cmp > phi.clone() + error_term.clone() {
                return false;
            } else if cmp < phi.clone() - error_term.clone() {
                return true;
            }
        }
        false
    }

    // eligibility.rs L32-49, with `ev` taken as BigInt for boundary probing.
    fn upstream_won(phi_f: f64, ev: &BigInt, stake: u64, total_stake: u64) -> bool {
        if (phi_f - 1.0).abs() < f64::EPSILON {
            return true;
        }
        let ev_max = BigInt::from(2u8).pow(512);
        let q = Ratio::new_raw(ev_max.clone(), &ev_max - ev);
        let c = Ratio::from_float((1.0 - phi_f).ln()).expect("ln finite");
        let w = Ratio::new_raw(BigInt::from(stake), BigInt::from(total_stake));
        let x = (w * c).neg();
        upstream_taylor(1000, q, x)
    }

    fn ev_to_le64(ev: &BigInt) -> [u8; 64] {
        let (_, le) = ev.to_bytes_le();
        let mut out = [0u8; 64];
        let n = le.len().min(64);
        out[..n].copy_from_slice(&le[..n]);
        out
    }

    // dwarf NEW path (per-signer cache) and OLD path (pre-cache series),
    // sharing the exact production `x`/`q` construction.
    fn dwarf_x(phi_f: f64, stake: u64, total_stake: u64) -> (Ratio512, Ratio512) {
        let three = Ratio512::from_u64(3, 1);
        let c = Ratio512::from_float((1.0 - phi_f).ln()).expect("ln finite");
        let x = Ratio512::from_u64(stake, total_stake).mul(&c).neg();
        (x, three)
    }
    fn dwarf_cache(phi_f: f64, ev: &[u8; 64], stake: u64, total_stake: u64) -> bool {
        if (phi_f - 1.0).abs() < f64::EPSILON {
            return true;
        }
        let (x, three) = dwarf_x(phi_f, stake, total_stake);
        let mut cache = TaylorBounds::new(x, &three);
        cache.lottery_won(lottery_q(U512::from_le_slice(ev)))
    }
    fn dwarf_old(phi_f: f64, ev: &[u8; 64], stake: u64, total_stake: u64) -> bool {
        if (phi_f - 1.0).abs() < f64::EPSILON {
            return true;
        }
        let (x, three) = dwarf_x(phi_f, stake, total_stake);
        taylor_comparison_ref(TAYLOR_BOUND, &lottery_q(U512::from_le_slice(ev)), &x, &three)
    }

    // Realistic Mithril domain: phi_f in [0.01, 0.5], no signer holds a
    // majority (w = stake/total <= 0.5), total in [1e8, 1e9]. Matches
    // upstream's own proptest ranges; dwarf's bounded U512 arithmetic
    // does not overflow here.
    fn gen_params(seed: u64) -> (f64, u64, u64, [u8; 64]) {
        let d0: [u8; 64] = Blake2b512::digest(seed.to_le_bytes()).into();
        let d1: [u8; 64] = Blake2b512::digest((seed ^ 0x9E37_79B9_7F4A_7C15).to_le_bytes()).into();
        let mut ev = [0u8; 64];
        ev[..32].copy_from_slice(&d0[..32]);
        ev[32..].copy_from_slice(&d1[..32]);
        let phi_f = 0.01 + (d0[40] as f64 / 255.0) * 0.49;
        let total = 100_000_000u64
            + u64::from_le_bytes(d1[0..8].try_into().unwrap()) % 900_000_000;
        let stake = 1 + u64::from_le_bytes(d1[8..16].try_into().unwrap()) % (total / 2);
        (phi_f, stake, total, ev)
    }

    // Extreme/out-of-domain: phi_f up to 0.95 and w up to ~1.0, where
    // dwarf's U512 Taylor can overflow. Used only to prove the cache
    // preserves OLD behaviour (incl. overflow) bit-for-bit.
    fn gen_params_extreme(seed: u64) -> (f64, u64, u64, [u8; 64]) {
        let d0: [u8; 64] = Blake2b512::digest(seed.to_le_bytes()).into();
        let d1: [u8; 64] = Blake2b512::digest((seed ^ 0x1234_5678_9ABC_DEF0).to_le_bytes()).into();
        let mut ev = [0u8; 64];
        ev[..32].copy_from_slice(&d0[..32]);
        ev[32..].copy_from_slice(&d1[..32]);
        let phi_f = 0.01 + (d0[40] as f64 / 255.0) * 0.94;
        let total = 1u64 + u64::from_le_bytes(d1[0..8].try_into().unwrap()) % 1_000_000_000;
        let stake = 1 + u64::from_le_bytes(d1[8..16].try_into().unwrap()) % total;
        (phi_f, stake, total, ev)
    }

    /// Massive cache==old regression fuzz on the realistic domain. The
    /// airtight proof the optimisation changed no decision where dwarf
    /// actually operates.
    #[test]
    #[ignore = "heavy differential fuzz vs upstream re-port; run: cargo test --release -- --ignored"]
    fn cache_equals_old_series_massive() {
        const N: u64 = 2_000_000;
        for i in 0..N {
            let (phi_f, stake, total, ev) = gen_params(i);
            let cache = dwarf_cache(phi_f, &ev, stake, total);
            let old = dwarf_old(phi_f, &ev, stake, total);
            assert_eq!(
                cache, old,
                "REGRESSION: cache != old at seed {i}: phi_f={phi_f} stake={stake} total={total}"
            );
        }
        eprintln!("cache_equals_old_series_massive: {N} realistic inputs, all identical");
    }

    /// Cache==old EVEN in the overflow regime: where the old series
    /// panics (U512 overflow), the cache must panic identically; where it
    /// returns, the cache must return the same. Proves the optimisation
    /// is a perfect no-op even out of domain. Suppresses the panic hook
    /// so the expected overflow panics don't spam stderr.
    #[test]
    #[ignore = "heavy differential fuzz vs upstream re-port; run: cargo test --release -- --ignored"]
    fn cache_equals_old_under_overflow() {
        use std::panic::{catch_unwind, AssertUnwindSafe};
        let prev = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        const N: u64 = 200_000;
        let mut overflows = 0u64;
        for i in 0..N {
            let (phi_f, stake, total, ev) = gen_params_extreme(i);
            let cache = catch_unwind(AssertUnwindSafe(|| dwarf_cache(phi_f, &ev, stake, total)));
            let old = catch_unwind(AssertUnwindSafe(|| dwarf_old(phi_f, &ev, stake, total)));
            match (cache, old) {
                (Ok(a), Ok(b)) => assert_eq!(a, b, "REGRESSION at seed {i} (no overflow)"),
                (Err(_), Err(_)) => overflows += 1,
                (a, b) => {
                    std::panic::set_hook(prev);
                    panic!("OVERFLOW PARITY BROKEN at seed {i}: cache_ok={} old_ok={} \
                            phi_f={phi_f} stake={stake} total={total}",
                           a.is_ok(), b.is_ok());
                }
            }
        }
        std::panic::set_hook(prev);
        eprintln!(
            "cache_equals_old_under_overflow: N={N}, identical incl. {overflows} \
             shared-overflow inputs (pre-existing, out of realistic domain)"
        );
    }

    /// Random fuzz vs upstream BigInt. Random 512-bit `ev` is essentially
    /// never in the ~2^-52 boundary sliver, so dwarf and upstream must
    /// agree everywhere here — a non-zero count would mean a gross `x`/`q`
    /// construction bug, not a boundary effect. Also asserts cache==old.
    #[test]
    #[ignore = "heavy differential fuzz vs upstream re-port; run: cargo test --release -- --ignored"]
    fn dwarf_matches_upstream_random() {
        const N: u64 = 40_000;
        let mut mism = 0u64;
        for i in 0..N {
            let (phi_f, stake, total, ev) = gen_params(i.wrapping_mul(2_654_435_761));
            let cache = dwarf_cache(phi_f, &ev, stake, total);
            let old = dwarf_old(phi_f, &ev, stake, total);
            assert_eq!(cache, old, "REGRESSION at seed {i}");
            let up = upstream_won(phi_f, &BigInt::from_bytes_le(Sign::Plus, &ev), stake, total);
            if cache != up {
                mism += 1;
            }
        }
        eprintln!("dwarf_matches_upstream_random: N={N}, dwarf-vs-upstream mismatches={mism}");
        assert_eq!(mism, 0, "dwarf diverged from upstream away from the boundary");
    }

    /// Quantify the pre-existing boundary sliver: for a param grid,
    /// binary-search each impl's winning/losing `ev` threshold and report
    /// the gap (|Δ| in bits) and its DIRECTION — whether dwarf wins on a
    /// wider or narrower `ev` range than upstream. cache==old asserted at
    /// each threshold. This documents the dwarf/upstream relationship; it
    /// does NOT hard-assert a direction, because the gap is pre-existing.
    #[test]
    #[ignore = "heavy differential fuzz vs upstream re-port; run: cargo test --release -- --ignored"]
    fn quantify_boundary_gap_vs_upstream() {
        let phis = [0.05_f64, 0.2, 0.5];
        let params: &[(u64, u64)] = &[(1_000_000, 100_000_000), (50_000_000, 1_000_000_000)];
        let two512 = BigInt::from(2u8).pow(512);
        let max_ev = &two512 - 1;

        use std::panic::{catch_unwind, AssertUnwindSafe};

        // Upstream's first-lost `ev` via binary search (BigInt, never
        // overflows). `is_lottery_won` is monotone decreasing in `ev`.
        let upstream_threshold = |phi_f: f64, stake: u64, total: u64| -> Option<BigInt> {
            let zero = BigInt::from(0u8);
            if !upstream_won(phi_f, &zero, stake, total) {
                return Some(zero);
            }
            if upstream_won(phi_f, &max_ev, stake, total) {
                return None;
            }
            let (mut lo, mut hi) = (zero, max_ev.clone());
            while &hi - &lo > BigInt::one() {
                let mid = (&lo + &hi) / 2u8;
                if upstream_won(phi_f, &mid, stake, total) {
                    lo = mid;
                } else {
                    hi = mid;
                }
            }
            Some(hi)
        };

        let prev = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));

        // Tallies across the whole boundary sweep.
        let mut agree = 0u64;
        let mut safe_disagree = 0u64; // dwarf LOST, upstream WON — conservative
        let mut unsafe_disagree = 0u64; // dwarf WON, upstream LOST — DANGER
        let mut dwarf_overflow = 0u64; // dwarf can't resolve near boundary
        let mut regressions = 0u64; // cache != old

        const W: i64 = 800;
        for &phi_f in &phis {
            for &(stake, total) in params {
                let Some(up_t) = upstream_threshold(phi_f, stake, total) else {
                    continue;
                };
                for d in -W..=W {
                    let ev = &up_t + BigInt::from(d);
                    if ev.sign() == Sign::Minus || ev > max_ev {
                        continue;
                    }
                    let e = ev_to_le64(&ev);
                    let up = upstream_won(phi_f, &ev, stake, total);
                    let cache = catch_unwind(AssertUnwindSafe(|| dwarf_cache(phi_f, &e, stake, total)));
                    let old = catch_unwind(AssertUnwindSafe(|| dwarf_old(phi_f, &e, stake, total)));
                    match (cache, old) {
                        (Ok(c), Ok(o)) => {
                            if c != o {
                                regressions += 1;
                            }
                            if c == up {
                                agree += 1;
                            } else if !c && up {
                                safe_disagree += 1;
                            } else {
                                unsafe_disagree += 1; // c && !up
                            }
                        }
                        (Err(_), Err(_)) => dwarf_overflow += 1, // both panic ⇒ still cache==old
                        _ => regressions += 1, // overflow parity broken
                    }
                }
            }
        }
        std::panic::set_hook(prev);

        eprintln!(
            "boundary sweep (±{W} around upstream ev*, {} param sets):\n  \
             agree={agree}  safe_disagree(dwarf-lost/up-won)={safe_disagree}  \
             UNSAFE(dwarf-won/up-lost)={unsafe_disagree}  \
             dwarf_overflow={dwarf_overflow}  regressions={regressions}",
            phis.len() * params.len()
        );
        // The two non-negotiables:
        //  * the cache never diverges from the old series (regression), and
        //  * dwarf NEVER accepts a ticket upstream rejects (soundness).
        assert_eq!(regressions, 0, "cache diverged from old series at the boundary");
        assert_eq!(
            unsafe_disagree, 0,
            "SOUNDNESS: dwarf accepted a lottery ticket upstream rejected"
        );
    }
}
