//! Mutation engine for negative testing.
//!
//! Each [`Mutation`] is a deterministic edit to a [`CertificateMessage`].
//! An [`AppliedMutation`] pairs a `Mutation` with a [`MutationTarget`]
//! (current cert or previous cert), so the same mutation primitive can
//! exercise both attack surfaces.
//!
//! The audit driver applies the mutation, then runs the full per-check +
//! full-verify pipeline against both Mithril and dwarf. The harness's
//! contract:
//!
//! - **Critical (hard test failure):** dwarf returns `Ok` for a mutation
//!   Mithril rejects — false-positive attack window, fails the test.
//! - **Soundness regression (hard test failure):** dwarf rejects what
//!   Mithril accepts — bug, fails the test.
//! - **Insufficient mutation (hard test failure):** both impls accept —
//!   the mutation isn't actually adversarial.
//! - **Soft divergence (report-only):** both reject, but with different
//!   `ErrorCategory` values — semantically equivalent, surfaced in the
//!   report.

use mithril_common::entities::{Certificate, ProtocolMessagePartKey, SignedEntityType};
use mithril_common::messages::CertificateMessage;

/// Where to apply the mutation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MutationTarget {
    /// Mutate the current certificate (the one under verification).
    Current,
    /// Mutate the previous certificate (the chain predecessor). Used to
    /// exercise dwarf's `verify_avk_chain` /
    /// `verify_protocol_params_chain` against tampered `NextAvk` /
    /// `NextProtocolParameters` fields in the previous protocol message.
    Previous,
}

#[derive(Debug, Clone)]
pub struct AppliedMutation {
    pub target: MutationTarget,
    pub mutation: Mutation,
}

#[derive(Debug, Clone)]
pub enum Mutation {
    // -----------------------------------------------------------------
    // Top-level cert fields
    // -----------------------------------------------------------------
    /// Toggle one hex char in `cert.hash`.
    FlipHashByte { index: usize },
    /// Toggle one hex char in `cert.previous_hash`.
    FlipPreviousHashByte { index: usize },
    /// Toggle one hex char in `cert.signed_message`.
    FlipSignedMessageByte { index: usize },
    /// Shift `cert.epoch.0` by `delta` (clamped at 0).
    BumpEpoch { delta: i64 },
    /// Overwrite `protocol_message[CurrentEpoch]`.
    SetProtocolMessageCurrentEpoch { value: String },
    /// Overwrite `protocol_message[NextAggregateVerificationKey]` (drives
    /// the cross-epoch AVK chain check on the next cert).
    SetProtocolMessageNextAvk { value: String },
    /// Overwrite `protocol_message[NextProtocolParameters]` (drives the
    /// cross-epoch params chain check on the next cert).
    SetProtocolMessageNextProtocolParameters { value: String },

    // -----------------------------------------------------------------
    // Signature / AVK envelopes
    // -----------------------------------------------------------------
    /// Toggle one hex char inside `cert.multi_signature` /
    /// `cert.genesis_signature`. The chosen index is in the middle of
    /// the envelope, so it may land on JSON syntax or on payload bytes —
    /// both outcomes cause rejection but at different layers.
    ScrambleSignatureField,
    /// Toggle one hex char inside `cert.aggregate_verification_key`.
    /// Targets the JSON-hex envelope; may land on the Merkle root or
    /// elsewhere.
    ScrambleAvkEnvelope,

    // -----------------------------------------------------------------
    // Metadata fields — these all enter `metadata.compute_hash()` which
    // feeds `Certificate::compute_hash()`, so a single-byte change here
    // should make hash recomputation reject the cert.
    // -----------------------------------------------------------------
    /// Shift `metadata.protocol_parameters.k` by `delta`.
    BumpProtocolK { delta: i64 },
    /// Shift `metadata.protocol_parameters.m` by `delta`.
    BumpProtocolM { delta: i64 },
    /// Set `metadata.protocol_parameters.phi_f` to an explicit value.
    SetProtocolPhiF { value: f64 },
    /// Shift `metadata.signers[signer_idx].stake` by `delta`.
    BumpSignerStake { signer_idx: usize, delta: i64 },
    /// Append a sentinel char to `metadata.network` so the field changes
    /// regardless of the original content.
    ScrambleNetwork,
    /// Append a sentinel char to `metadata.protocol_version` so the field
    /// changes regardless of the original content. (Case-toggling the
    /// first byte was a no-op on strings starting with a digit, which
    /// `protocol_version` often does.)
    ScrambleProtocolVersion,
    /// Shift `metadata.initiated_at` by 1 second.
    BumpInitiatedAtTimestamp,

    // -----------------------------------------------------------------
    // Entity-type mutations — exercise the
    // `feed_entity_type_hash` discriminant table in dwarf
    // (`medium_checks.rs`). Each variant of `SignedEntityType` has a
    // different inner field shape (1 u64 vs 2 u64s); a layout drift on
    // dwarf's side would silently produce a different cert hash.
    // -----------------------------------------------------------------
    /// Shift the first inner `u64` of `signed_entity_type` (epoch on
    /// every variant) by `delta`. Always applicable.
    BumpEntityTypeFirstField { delta: i64 },
    /// Shift the second inner `u64` of `signed_entity_type`
    /// (immutable_file_number for `CardanoImmutableFilesFull` /
    /// `CardanoDatabase`, block_number for `CardanoTransactions`) by
    /// `delta`. Only applicable to two-field variants; panics on
    /// single-field variants with a clear scaffolding-bug message.
    BumpEntityTypeSecondField { delta: i64 },

    // -----------------------------------------------------------------
    // BLS-algebraic mutations — modify the multi-signature payload AND
    // recompute `cert.hash` so the cheap hash check passes and the BLS
    // path (lottery, index-uniqueness, Merkle batch proof, aggregate
    // verify) actually executes. Without the hash recompute, every
    // multi-sig change is caught by the cheap hash check before BLS
    // runs — so dwarf's BLS algebraic surface is never exercised in
    // a negative test.
    // -----------------------------------------------------------------
    /// Duplicate the first index of the first single-signature
    /// (`indexes[1] = indexes[0]`). Should trip
    /// `IndexNotUnique` in both impls during preliminary verification.
    BlsDuplicateFirstIndex,
    /// Zero out the stake of the first single-signature's signer.
    /// A zero-stake signer can never win the lottery, so the BLS
    /// preliminary check should reject.
    BlsZeroFirstSignerStake,
    /// Replace `signatures[0]`'s `sigma` with `signatures[1]`'s `sigma`.
    /// Both blobs are guaranteed-valid BLS G1 compressed points (each
    /// was produced by a real signer), so the parser accepts them; but
    /// `signatures[0]`'s sigma is no longer a signature of
    /// `signatures[0]`'s message under `signatures[0]`'s VK, so the BLS
    /// aggregate verification has to reject. A bit-flip on `sigma`
    /// fails ~50% of the time (`x³ + b` not a QR → decompression
    /// error) so we use a guaranteed-valid donor.
    BlsCopyFirstSigmaFromSecond,
    /// Copy `signatures[0]`'s first lottery index into `signatures[1]`'s
    /// first index slot. Both impls' `preliminary_verify` collects all
    /// indices across signers and rejects on any duplicate via
    /// `IndexNotUnique` — `BlsDuplicateFirstIndex` exercises the
    /// within-signer path; this one exercises the cross-signer path.
    BlsDuplicateIndexCrossSig,
    /// Append a sentinel byte to `metadata.signers[0].party_id`. Both
    /// impls feed party_id into the per-signer hash inside the metadata
    /// hash, so any change here trips the cert-hash recomputation. Adds
    /// the party_id axis to the signer-mutation coverage (we already
    /// exercise the stake axis via `BumpSignerStake`).
    BumpSignerPartyId { signer_idx: usize },

    /// Drop the last hex character of `cert.hash` (length 64 → 63).
    /// Tests the length-validation axis of both verifiers' hash check
    /// — neither impl can compute a 63-character SHA-256 hex, so both
    /// must reject. Closes the length-axis gap (G-6) flagged in the
    /// harness audit.
    TruncateHashByOneChar,

    /// Append a single ASCII-hex char to `cert.hash` (length 64 → 65).
    /// Same axis as truncation: both verifiers must reject the
    /// over-length hash. Pairs with `TruncateHashByOneChar`.
    AppendCharToHash,

    /// Remove the `CurrentEpoch` part from `cert.protocol_message`.
    /// Dwarf must surface this as `CurrentEpochNotFound`; upstream
    /// must surface as `EpochInProtocolMessageMismatch`. Both
    /// canonicalise via `verify_error_to_category` /
    /// `mithril_error_to_category` to the same `ErrorCategory`. Closes
    /// the missing-required-part axis of G-6.
    RemoveCurrentEpochPart,

    /// Re-encode the previous cert's
    /// `protocol_message[NextAggregateVerificationKey]` value into a
    /// semantically-equivalent but byte-different form (decode hex →
    /// JSON value → re-serialise with `to_vec_pretty` → re-hex). Tested
    /// on the `Previous` target so the round-trip-canonicalisation
    /// happens at the `CertificateMessage → Certificate` boundary on
    /// `previous`, leaving the mutated bytes intact in
    /// `protocol_message`. Both impls reject (at the cheap prev-cert
    /// hash recompute, since `protocol_message` feeds the cert hash —
    /// the same rejection shape as the existing
    /// `SetProtocolMessageNextAvk` previous-target mutation). The new
    /// coverage versus `SetProtocolMessageNextAvk` is the encoding
    /// axis: any future regression that silently canonicalises the
    /// JSON before hashing would let this mutation slip past dwarf
    /// while upstream byte-rejects (a critical false positive).
    ReEncodePreviousNextAvkJson,

    // BLS identity-point mutations (scalar-zero, identity-AVK) cannot
    // run through the `CertificateMessage → Certificate → compute_hash`
    // path this enum uses: upstream's `AggregateSignature::from_bytes`
    // rejects identity at deserialise, so the mutation never reaches
    // dwarf. dwarf's parser accepts the bytes but the BLS pairing
    // rejects later — pinned by `dwarf_rejects_bls_identity_in_cert`
    // in `tests/equivalence.rs`, which calls blst directly.

    // -----------------------------------------------------------------
    // Intentional-divergence mutations — RESERVED.
    //
    // Reserved for KNOWN tradeoffs where dwarf accepts what upstream
    // Mithril rejects, for cycle savings approved at design time. The
    // harness counts such cases in a distinct
    // `mutations_intentional_divergence` bucket rather than flagging
    // them as CRITICAL false positives.
    //
    // No variants are currently defined — an earlier draft included
    // `Ed25519MalleabilityTwin` (replace `s` with `s + L`) on the
    // theory that dwarf's non-strict `vk.verify` would accept where
    // upstream's `verify_strict` would reject. Empirically that does
    // not happen: `ed25519-dalek` 2.1.1's non-strict `vk.verify` also
    // routes through `Scalar::from_canonical_bytes(s)` which rejects
    // any `s >= L`. The real `verify` vs `verify_strict` difference in
    // dalek 2.x is the post-canonicality subgroup check on `R` (and
    // `A`/the vk); constructing a twin that exploits that requires
    // either a maliciously crafted public key (not our threat model —
    // genesis VK is fixed) or breaking ed25519. So dwarf's non-strict
    // verify is operationally equivalent to `verify_strict` for the
    // mainnet genesis signature path. The bucket is preserved so a
    // future genuine divergence can be added cleanly.
    // -----------------------------------------------------------------
}

impl Mutation {
    /// True iff this mutation can meaningfully be applied to `cert`. The
    /// test driver filters the mutation set through this so we don't trip
    /// our own scaffolding panics on certs that don't have the mutated
    /// field (e.g. `BumpEntityTypeSecondField` on a single-field
    /// `MithrilStakeDistribution` cert).
    pub fn is_applicable_to(&self, cert: &CertificateMessage) -> bool {
        match self {
            Mutation::BumpEntityTypeSecondField { .. } => matches!(
                cert.signed_entity_type,
                SignedEntityType::CardanoImmutableFilesFull(_)
                    | SignedEntityType::CardanoDatabase(_)
                    | SignedEntityType::CardanoTransactions(_, _)
            ),
            Mutation::BumpSignerStake { signer_idx, .. } => {
                cert.metadata.signers.len() > *signer_idx
            }
            // BLS-axis mutations need a multi-signature to dig into; on a
            // genesis cert they would parse an empty/invalid blob.
            Mutation::BlsZeroFirstSignerStake => !cert.multi_signature.is_empty(),
            // Real mainnet certs often have single-index lottery wins;
            // only apply the duplicate-index mutation when there's a
            // single-sig with ≥2 indexes to perturb.
            Mutation::BlsDuplicateFirstIndex => {
                !cert.multi_signature.is_empty()
                    && max_indexes_per_single_sig(&cert.multi_signature) >= 2
            }
            // Needs ≥2 signatures to donate one sigma to another.
            Mutation::BlsCopyFirstSigmaFromSecond => {
                !cert.multi_signature.is_empty() && multi_sig_count(&cert.multi_signature) >= 2
            }
            // Needs ≥2 signatures to copy one signer's index into another.
            Mutation::BlsDuplicateIndexCrossSig => {
                !cert.multi_signature.is_empty() && multi_sig_count(&cert.multi_signature) >= 2
            }
            // Needs a signer at signer_idx to exist.
            Mutation::BumpSignerPartyId { signer_idx } => {
                cert.metadata.signers.len() > *signer_idx
            }
            // Applies to the `Previous` cert in audit_mutated; here we
            // gate on the `current` cert by proxy of "any cert with a
            // NextAvk part has a re-encodable target", which is true of
            // every standard cert (NextAvk is mandatory in the protocol
            // message). `audit_mutated` enforces target-specific shape.
            Mutation::ReEncodePreviousNextAvkJson => true,
            // Cert hash is a SHA-256 hex string (64 chars) on every
            // well-formed cert; truncation and append always apply.
            Mutation::TruncateHashByOneChar | Mutation::AppendCharToHash => !cert.hash.is_empty(),
            // CurrentEpoch is a mandatory protocol_message part on every
            // well-formed cert.
            Mutation::RemoveCurrentEpochPart => cert
                .protocol_message
                .message_parts
                .contains_key(&ProtocolMessagePartKey::CurrentEpoch),
            _ => true,
        }
    }

    /// `true` iff this mutation is known to produce a result where
    /// dwarf accepts and upstream Mithril rejects, **by design**. The
    /// test driver routes such mutations into the
    /// `mutations_intentional_divergence` bucket instead of failing
    /// the test as a CRITICAL false positive.
    ///
    /// Currently always `false` — see the "Intentional-divergence
    /// mutations" comment block in the `Mutation` enum for the
    /// analysis (no genuine in-threat-model divergence currently
    /// exists for ed25519 in `ed25519-dalek` 2.x).
    pub fn intentionally_diverges_from_upstream(&self) -> bool {
        false
    }
}

pub fn mutation_label(m: &Mutation) -> String {
    match m {
        Mutation::FlipHashByte { index } => format!("flip cert.hash[{index}]"),
        Mutation::FlipPreviousHashByte { index } => format!("flip cert.previous_hash[{index}]"),
        Mutation::FlipSignedMessageByte { index } => format!("flip cert.signed_message[{index}]"),
        Mutation::BumpEpoch { delta } => format!("bump cert.epoch by {delta:+}"),
        Mutation::SetProtocolMessageCurrentEpoch { value } => {
            format!("set protocol_message[CurrentEpoch] = {value:?}")
        }
        Mutation::SetProtocolMessageNextAvk { value } => {
            format!("set protocol_message[NextAggregateVerificationKey] = {value:?}")
        }
        Mutation::SetProtocolMessageNextProtocolParameters { value } => {
            format!("set protocol_message[NextProtocolParameters] = {value:?}")
        }
        Mutation::ScrambleSignatureField => "scramble signature envelope".to_string(),
        Mutation::ScrambleAvkEnvelope => "scramble AVK envelope".to_string(),
        Mutation::BumpProtocolK { delta } => format!("bump protocol_parameters.k by {delta:+}"),
        Mutation::BumpProtocolM { delta } => format!("bump protocol_parameters.m by {delta:+}"),
        Mutation::SetProtocolPhiF { value } => {
            format!("set protocol_parameters.phi_f = {value}")
        }
        Mutation::BumpSignerStake { signer_idx, delta } => {
            format!("bump signers[{signer_idx}].stake by {delta:+}")
        }
        Mutation::ScrambleNetwork => "scramble metadata.network".to_string(),
        Mutation::ScrambleProtocolVersion => "scramble metadata.protocol_version".to_string(),
        Mutation::BumpInitiatedAtTimestamp => "bump metadata.initiated_at by +1s".to_string(),
        Mutation::BumpEntityTypeFirstField { delta } => {
            format!("bump signed_entity_type.first_field by {delta:+}")
        }
        Mutation::BumpEntityTypeSecondField { delta } => {
            format!("bump signed_entity_type.second_field by {delta:+}")
        }
        Mutation::BlsDuplicateFirstIndex => "BLS: duplicate first index in sig 0".to_string(),
        Mutation::BlsZeroFirstSignerStake => "BLS: zero stake of sig 0's signer".to_string(),
        Mutation::BlsCopyFirstSigmaFromSecond => {
            "BLS: copy sigma from sig 1 into sig 0".to_string()
        }
        Mutation::BlsDuplicateIndexCrossSig => {
            "BLS: duplicate sig 0's first index into sig 1".to_string()
        }
        Mutation::BumpSignerPartyId { signer_idx } => {
            format!("append byte to signers[{signer_idx}].party_id")
        }
        Mutation::ReEncodePreviousNextAvkJson => {
            "AVK: re-encode previous cert's NextAvk JSON (pretty form)".to_string()
        }
        Mutation::TruncateHashByOneChar => "length: drop last char of cert.hash".to_string(),
        Mutation::AppendCharToHash => "length: append '!' to cert.hash".to_string(),
        Mutation::RemoveCurrentEpochPart => {
            "length: remove protocol_message[CurrentEpoch]".to_string()
        }
    }
}

pub fn applied_mutation_label(am: &AppliedMutation) -> String {
    let target = match am.target {
        MutationTarget::Current => "current",
        MutationTarget::Previous => "previous",
    };
    format!("{}: {}", target, mutation_label(&am.mutation))
}

/// Standard mutation set covering the major attack axes on both `current`
/// and `previous` certificates.
pub fn standard_mutations() -> Vec<AppliedMutation> {
    let current = [
        Mutation::FlipHashByte { index: 0 },
        Mutation::FlipPreviousHashByte { index: 0 },
        Mutation::FlipSignedMessageByte { index: 0 },
        Mutation::BumpEpoch { delta: 10 },
        Mutation::SetProtocolMessageCurrentEpoch {
            value: "99999999".to_string(),
        },
        Mutation::ScrambleSignatureField,
        Mutation::ScrambleAvkEnvelope,
        Mutation::BumpProtocolK { delta: 1 },
        Mutation::BumpProtocolM { delta: 1 },
        Mutation::SetProtocolPhiF { value: 0.5 },
        Mutation::BumpSignerStake {
            signer_idx: 0,
            delta: 1,
        },
        Mutation::ScrambleNetwork,
        Mutation::ScrambleProtocolVersion,
        Mutation::BumpInitiatedAtTimestamp,
        // Entity-type axis. The second-field variant is only applicable
        // when the cert is a two-field variant; `apply_mutation` panics
        // with a clear message otherwise.
        Mutation::BumpEntityTypeFirstField { delta: 1 },
        Mutation::BumpEntityTypeSecondField { delta: 1 },
        // BLS-algebraic axis. These bypass the cheap hash check by
        // recomputing `cert.hash` after the mutation, so dwarf's BLS
        // verification code path is the one that has to reject.
        Mutation::BlsDuplicateFirstIndex,
        Mutation::BlsZeroFirstSignerStake,
        Mutation::BlsCopyFirstSigmaFromSecond,
        Mutation::BlsDuplicateIndexCrossSig,
        // Signer party_id axis (the stake axis is covered above).
        Mutation::BumpSignerPartyId { signer_idx: 0 },
        // Length-axis mutations (G-6): truncation, extension, and
        // missing-required-part. Each tests a different aspect of
        // field-length / structural-completeness validation that the
        // hex-flip / value-set mutations don't reach.
        Mutation::TruncateHashByOneChar,
        Mutation::AppendCharToHash,
        Mutation::RemoveCurrentEpochPart,
    ];
    let previous = [
        // Tampering with prev's "next_*" parts: forwards the wrong AVK /
        // params into the next epoch's chain check.
        Mutation::SetProtocolMessageNextAvk {
            value: "deadbeef".to_string(),
        },
        Mutation::SetProtocolMessageNextProtocolParameters {
            value: "deadbeef".to_string(),
        },
        // A hash tweak on prev breaks the next cert's previous_hash link
        // and the prev cert's own hash recomputation.
        Mutation::FlipHashByte { index: 0 },
        // JSON encoding axis on NextAvk — guards against any future
        // drift that silently canonicalises the JSON before hashing.
        Mutation::ReEncodePreviousNextAvkJson,
    ];
    let mut out: Vec<AppliedMutation> = current
        .into_iter()
        .map(|m| AppliedMutation {
            target: MutationTarget::Current,
            mutation: m,
        })
        .collect();
    out.extend(previous.into_iter().map(|m| AppliedMutation {
        target: MutationTarget::Previous,
        mutation: m,
    }));
    out
}

pub fn apply_mutation(cert: &CertificateMessage, mutation: &Mutation) -> CertificateMessage {
    let mut out = cert.clone();
    match mutation {
        Mutation::FlipHashByte { index } => flip_hex_char(&mut out.hash, *index),
        Mutation::FlipPreviousHashByte { index } => flip_hex_char(&mut out.previous_hash, *index),
        Mutation::FlipSignedMessageByte { index } => flip_hex_char(&mut out.signed_message, *index),
        Mutation::BumpEpoch { delta } => {
            let new_epoch = (out.epoch.0 as i128) + (*delta as i128);
            out.epoch.0 = new_epoch.max(0) as u64;
        }
        Mutation::SetProtocolMessageCurrentEpoch { value } => {
            out.protocol_message
                .message_parts
                .insert(ProtocolMessagePartKey::CurrentEpoch, value.clone());
        }
        Mutation::SetProtocolMessageNextAvk { value } => {
            out.protocol_message.message_parts.insert(
                ProtocolMessagePartKey::NextAggregateVerificationKey,
                value.clone(),
            );
        }
        Mutation::SetProtocolMessageNextProtocolParameters { value } => {
            out.protocol_message.message_parts.insert(
                ProtocolMessagePartKey::NextProtocolParameters,
                value.clone(),
            );
        }
        Mutation::ScrambleSignatureField => {
            if !out.multi_signature.is_empty() {
                flip_first_hex_byte(&mut out.multi_signature);
            } else if !out.genesis_signature.is_empty() {
                flip_first_hex_byte(&mut out.genesis_signature);
            }
        }
        Mutation::ScrambleAvkEnvelope => {
            if !out.aggregate_verification_key.is_empty() {
                flip_first_hex_byte(&mut out.aggregate_verification_key);
            }
        }
        Mutation::BumpProtocolK { delta } => {
            let v = (out.metadata.protocol_parameters.k as i128) + (*delta as i128);
            out.metadata.protocol_parameters.k = v.max(0) as u64;
        }
        Mutation::BumpProtocolM { delta } => {
            let v = (out.metadata.protocol_parameters.m as i128) + (*delta as i128);
            out.metadata.protocol_parameters.m = v.max(0) as u64;
        }
        Mutation::SetProtocolPhiF { value } => {
            out.metadata.protocol_parameters.phi_f = *value;
        }
        Mutation::BumpSignerStake { signer_idx, delta } => {
            // If the cert has no signers at this index, the mutation would be
            // a silent no-op and would later trip the "mutation insufficient"
            // hard failure path — which is misleading: the corpus is the
            // problem, not the engine. Panic with a clear scaffolding-bug
            // message instead.
            let Some(signer) = out.metadata.signers.get_mut(*signer_idx) else {
                panic!(
                    "BumpSignerStake: cert has only {} signers; mutation cannot be applied at index {}",
                    out.metadata.signers.len(),
                    signer_idx
                );
            };
            let v = (signer.stake as i128) + (*delta as i128);
            signer.stake = v.max(0) as u64;
        }
        Mutation::ScrambleNetwork => append_suffix(&mut out.metadata.network),
        Mutation::ScrambleProtocolVersion => append_suffix(&mut out.metadata.protocol_version),
        Mutation::BumpInitiatedAtTimestamp => {
            out.metadata.initiated_at = out.metadata.initiated_at + chrono::Duration::seconds(1);
        }
        Mutation::BumpEntityTypeFirstField { delta } => {
            bump_entity_type_field(&mut out.signed_entity_type, *delta, EntityField::First);
        }
        Mutation::BumpEntityTypeSecondField { delta } => {
            bump_entity_type_field(&mut out.signed_entity_type, *delta, EntityField::Second);
        }
        Mutation::BlsDuplicateFirstIndex => {
            mutate_multi_sig_with_hash_recompute(&mut out, |json| {
                let sig = first_single_sig_with_multi_indexes_mut(json)
                    .expect("BlsDuplicateFirstIndex: applicability check should have filtered");
                let indexes = sig
                    .get_mut("indexes")
                    .and_then(|v| v.as_array_mut())
                    .expect("indexes array");
                indexes[1] = indexes[0].clone();
            });
        }
        Mutation::BlsZeroFirstSignerStake => {
            mutate_multi_sig_with_hash_recompute(&mut out, |json| {
                // signatures[0] is a 2-tuple [SingleSig, [RegisteredParty, Stake]].
                // The stake is the second element of the inner tuple.
                let sigs = json
                    .get_mut("signatures")
                    .and_then(|v| v.as_array_mut())
                    .expect("multi_signature.signatures array");
                let sig0 = sigs
                    .get_mut(0)
                    .and_then(|v| v.as_array_mut())
                    .expect("signature[0] outer tuple");
                let party_stake = sig0
                    .get_mut(1)
                    .and_then(|v| v.as_array_mut())
                    .expect("(RegisteredParty, Stake) inner tuple");
                assert_eq!(party_stake.len(), 2, "inner tuple must be (party, stake)");
                party_stake[1] = serde_json::Value::Number(serde_json::Number::from(0u64));
            });
        }
        Mutation::BlsCopyFirstSigmaFromSecond => {
            mutate_multi_sig_with_hash_recompute(&mut out, |json| {
                let sigs = json
                    .get_mut("signatures")
                    .and_then(|v| v.as_array_mut())
                    .expect("multi_signature.signatures array");
                assert!(
                    sigs.len() >= 2,
                    "BlsCopyFirstSigmaFromSecond: applicability check should have filtered"
                );
                let donor_sigma = sigs[1]
                    .as_array()
                    .and_then(|outer| outer.first())
                    .and_then(|single| single.get("sigma"))
                    .and_then(|v| v.as_array())
                    .expect("donor (signatures[1]) sigma array")
                    .clone();
                let single = sigs[0]
                    .as_array_mut()
                    .and_then(|outer| outer.get_mut(0))
                    .expect("signatures[0]'s SingleSig");
                let dst = single
                    .get_mut("sigma")
                    .expect("signatures[0].sigma field");
                *dst = serde_json::Value::Array(donor_sigma);
            });
        }
        Mutation::BlsDuplicateIndexCrossSig => {
            mutate_multi_sig_with_hash_recompute(&mut out, |json| {
                let sigs = json
                    .get_mut("signatures")
                    .and_then(|v| v.as_array_mut())
                    .expect("multi_signature.signatures array");
                assert!(
                    sigs.len() >= 2,
                    "BlsDuplicateIndexCrossSig: applicability check should have filtered"
                );
                let donor_index = sigs[0]
                    .as_array()
                    .and_then(|outer| outer.first())
                    .and_then(|single| single.get("indexes"))
                    .and_then(|v| v.as_array())
                    .and_then(|a| a.first())
                    .expect("donor (signatures[0]) first index")
                    .clone();
                let single = sigs[1]
                    .as_array_mut()
                    .and_then(|outer| outer.get_mut(0))
                    .expect("signatures[1]'s SingleSig");
                let indexes = single
                    .get_mut("indexes")
                    .and_then(|v| v.as_array_mut())
                    .expect("signatures[1].indexes array");
                assert!(
                    !indexes.is_empty(),
                    "BlsDuplicateIndexCrossSig: signatures[1] has no indexes"
                );
                indexes[0] = donor_index;
            });
        }
        Mutation::BumpSignerPartyId { signer_idx } => {
            let Some(signer) = out.metadata.signers.get_mut(*signer_idx) else {
                panic!(
                    "BumpSignerPartyId: cert has only {} signers; cannot mutate index {}",
                    out.metadata.signers.len(),
                    signer_idx
                );
            };
            append_suffix(&mut signer.party_id);
        }
        Mutation::TruncateHashByOneChar => {
            // SHA-256 hex is 64 chars; pop one to make it 63.
            out.hash.pop();
        }
        Mutation::AppendCharToHash => {
            // Append a non-hex sentinel — keeps the field a String
            // (no UTF-8 invariant break) while making it 65 chars.
            // Both impls' hash slice compare reject on length mismatch.
            out.hash.push('!');
        }
        Mutation::RemoveCurrentEpochPart => {
            out.protocol_message
                .message_parts
                .remove(&ProtocolMessagePartKey::CurrentEpoch);
        }
        Mutation::ReEncodePreviousNextAvkJson => {
            // Pull the NextAvk part, decode hex → JSON → pretty-print →
            // re-hex, write back. Whitespace differs from compact form
            // so the resulting bytes are byte-different even when the
            // source was already canonical. Don't recompute prev.hash:
            // the rejection path is the prev-cert hash recompute
            // (`protocol_message` feeds prev's cert hash), and both
            // impls reject there — matching the existing
            // `SetProtocolMessageNextAvk` previous-target shape.
            let Some(current_value) = out
                .protocol_message
                .message_parts
                .get(&ProtocolMessagePartKey::NextAggregateVerificationKey)
            else {
                panic!(
                    "ReEncodePreviousNextAvkJson: previous cert has no \
                     NextAggregateVerificationKey part to re-encode"
                );
            };
            let raw = hex::decode(current_value).expect("NextAvk hex decode");
            let value: serde_json::Value =
                serde_json::from_slice(&raw).expect("NextAvk JSON parse");
            let pretty = serde_json::to_vec_pretty(&value).expect("NextAvk re-encode");
            assert_ne!(
                pretty, raw,
                "ReEncodePreviousNextAvkJson: pretty form was byte-identical to original \
                 — corpus NextAvk already had whitespace; pick a different re-encoding"
            );
            out.protocol_message.message_parts.insert(
                ProtocolMessagePartKey::NextAggregateVerificationKey,
                hex::encode(&pretty),
            );
        }
    }
    out
}

/// Discriminator for `bump_entity_type_field`.
#[derive(Debug, Clone, Copy)]
enum EntityField {
    First,
    Second,
}

/// Shift one inner `u64` of a `SignedEntityType`. The first field is
/// always an epoch; the second exists only on the two-field variants
/// (`CardanoImmutableFilesFull`, `CardanoTransactions`, `CardanoDatabase`)
/// and is the immutable-file number or block number.
fn bump_entity_type_field(t: &mut SignedEntityType, delta: i64, which: EntityField) {
    use mithril_common::entities::{BlockNumber, CardanoDbBeacon, Epoch, ImmutableFileNumber};
    let shift_u64 = |v: u64| -> u64 {
        let new = (v as i128) + (delta as i128);
        new.max(0) as u64
    };
    match (t, which) {
        (SignedEntityType::MithrilStakeDistribution(Epoch(e)), EntityField::First)
        | (SignedEntityType::CardanoStakeDistribution(Epoch(e)), EntityField::First) => {
            *e = shift_u64(*e);
        }
        (SignedEntityType::MithrilStakeDistribution(_), EntityField::Second)
        | (SignedEntityType::CardanoStakeDistribution(_), EntityField::Second) => {
            panic!(
                "BumpEntityTypeSecondField is not applicable to a single-field SignedEntityType variant"
            );
        }
        (SignedEntityType::CardanoImmutableFilesFull(beacon), which)
        | (SignedEntityType::CardanoDatabase(beacon), which) => {
            let CardanoDbBeacon {
                epoch,
                immutable_file_number,
            } = beacon;
            match which {
                EntityField::First => {
                    let Epoch(e) = epoch;
                    *e = shift_u64(*e);
                }
                EntityField::Second => {
                    let n: &mut ImmutableFileNumber = immutable_file_number;
                    *n = shift_u64(*n);
                }
            }
        }
        (SignedEntityType::CardanoTransactions(Epoch(e), block), which) => match which {
            EntityField::First => {
                *e = shift_u64(*e);
            }
            EntityField::Second => {
                let BlockNumber(b) = block;
                *b = shift_u64(*b);
            }
        },
    }
}

/// Find the first `SingleSig` whose `indexes` array has at least 2
/// entries. Real mainnet certs commonly have one-shot lottery wins, so
/// the corpus's `signatures[0]` may only have one index. The duplicate-
/// index mutation needs ≥2 entries to perturb.
fn first_single_sig_with_multi_indexes_mut(
    json: &mut serde_json::Value,
) -> Option<&mut serde_json::Value> {
    let sigs = json.get_mut("signatures")?.as_array_mut()?;
    for outer in sigs.iter_mut() {
        let outer_arr = outer.as_array_mut()?;
        let single = outer_arr.get_mut(0)?;
        let n_indexes = single.get("indexes").and_then(|v| v.as_array()).map(|a| a.len()).unwrap_or(0);
        if n_indexes >= 2 {
            return Some(single);
        }
    }
    None
}

/// Count how many top-level entries `multi_signature.signatures` has.
/// Used by `Mutation::is_applicable_to` for mutations that need a donor
/// signature (e.g. `BlsCopyFirstSigmaFromSecond`).
fn multi_sig_count(hex_str: &str) -> usize {
    let Ok(bytes) = hex::decode(hex_str) else {
        return 0;
    };
    let Ok(json) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
        return 0;
    };
    json.get("signatures")
        .and_then(|v| v.as_array())
        .map(|a| a.len())
        .unwrap_or(0)
}

/// Parse a `multi_signature` hex blob enough to count, for the largest
/// single-sig, how many `indexes` it carries. Used by
/// `Mutation::is_applicable_to` for `BlsDuplicateFirstIndex`.
fn max_indexes_per_single_sig(hex_str: &str) -> usize {
    let Ok(bytes) = hex::decode(hex_str) else {
        return 0;
    };
    let Ok(json) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
        return 0;
    };
    let Some(sigs) = json.get("signatures").and_then(|v| v.as_array()) else {
        return 0;
    };
    sigs.iter()
        .filter_map(|outer| outer.as_array())
        .filter_map(|outer_arr| outer_arr.first())
        .filter_map(|single| single.get("indexes").and_then(|v| v.as_array()))
        .map(|a| a.len())
        .max()
        .unwrap_or(0)
}

/// Parse the hex-encoded multi-signature JSON in `cert.multi_signature`,
/// apply `mutate` to the parsed `serde_json::Value`, re-encode, then
/// recompute `cert.hash` so the cheap `Certificate::compute_hash` check
/// still passes. The point of this is to put the BLS verification code
/// path on the hot path during negative testing — without the hash
/// recompute, any change to `multi_signature` is caught by the cheap
/// hash recompute long before BLS runs.
///
/// Roundtripping `multi_signature` through
/// `try_into() -> Certificate -> compute_hash()` is byte-stable for the
/// upstream pin (verified manually), so the new hash matches the
/// surrounding cert bytes.
fn mutate_multi_sig_with_hash_recompute(
    cert: &mut CertificateMessage,
    mutate: impl FnOnce(&mut serde_json::Value),
) {
    let bytes = hex::decode(&cert.multi_signature).expect("multi_signature hex decode");
    let mut json: serde_json::Value =
        serde_json::from_slice(&bytes).expect("multi_signature JSON parse");
    mutate(&mut json);
    let new_bytes = serde_json::to_vec(&json).expect("multi_signature JSON encode");
    cert.multi_signature = hex::encode(new_bytes);
    let typed: Certificate = cert
        .clone()
        .try_into()
        .expect("CertificateMessage -> Certificate after multi_signature mutation");
    cert.hash = typed.compute_hash();
}

/// Toggle one hex digit at the chosen index, treating the string as
/// ASCII. The mapping flips each digit to an adjacent one
/// (`0↔1`, `2↔3`, …, `a↔b`, `c↔d`, `e↔f`) so the result is still a
/// well-formed hex digit, preserving the JSON-hex envelope's validity
/// while changing the cryptographic payload it encodes.
fn flip_hex_char(s: &mut String, byte_idx: usize) {
    if s.is_empty() {
        return;
    }
    let idx = byte_idx % s.len();
    debug_assert!(
        s.is_ascii(),
        "flip_hex_char invariant: target string must be ASCII"
    );
    // SAFETY: This function is only called on `String`s whose contract is
    // "ASCII-only hex". The toggle table below maps every ASCII hex digit
    // to another ASCII hex digit (one-byte UTF-8 → one-byte UTF-8); for
    // any other byte the value is written back unchanged, so the byte
    // boundary is never split and UTF-8 validity is preserved. The
    // `debug_assert!` above catches violations of the input contract in
    // test builds.
    let bytes = unsafe { s.as_bytes_mut() };
    let original = bytes[idx];
    let toggled = match original {
        b'0' => b'1',
        b'1' => b'0',
        b'2' => b'3',
        b'3' => b'2',
        b'4' => b'5',
        b'5' => b'4',
        b'6' => b'7',
        b'7' => b'6',
        b'8' => b'9',
        b'9' => b'8',
        b'a' => b'b',
        b'b' => b'a',
        b'c' => b'd',
        b'd' => b'c',
        b'e' => b'f',
        b'f' => b'e',
        b'A' => b'B',
        b'B' => b'A',
        b'C' => b'D',
        b'D' => b'C',
        b'E' => b'F',
        b'F' => b'E',
        // Non-hex byte: leave as-is. debug_assert above catches this in
        // test builds; release leaves the mutation as a no-op rather than
        // producing invalid UTF-8.
        c => c,
    };
    bytes[idx] = toggled;
}

/// Append a single ASCII char to a `String`. Used for metadata fields
/// like `network` and `protocol_version` to guarantee a real change
/// regardless of the original content (case toggling on the first byte
/// is a no-op for strings starting with a digit, which protocol_version
/// often does).
fn append_suffix(s: &mut String) {
    s.push('!');
}

/// Find the first ASCII hex digit and toggle it via `flip_hex_char`.
///
/// `flip_hex_char` is a no-op on non-hex bytes, so picking a fixed index
/// (e.g. `len / 2`) can silently land on JSON punctuation (`"`, `,`,
/// `{`) inside an envelope and yield zero mutation — which would later
/// trigger the "mutation insufficient" hard failure. Scanning instead
/// guarantees a real change for any non-empty hex-bearing string. If no
/// hex digit is found, panic loudly — the input isn't what the mutation
/// expected, which is a scaffolding bug, not a verifier bug.
fn flip_first_hex_byte(s: &mut String) {
    let idx = s
        .as_bytes()
        .iter()
        .position(|b| b.is_ascii_hexdigit())
        .unwrap_or_else(|| {
            panic!(
                "flip_first_hex_byte: no ASCII hex digit found in {} bytes",
                s.len()
            )
        });
    flip_hex_char(s, idx);
}

