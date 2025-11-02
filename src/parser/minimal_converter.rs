use crate::parser::byte_parser::{
    AggregateVerificationKeyParsed, CertificateZeroCopy, MetadataBasicZeroCopy, MultiSigParsed,
    ProtocolMessageBasicZeroCopy, SignatureBasicZeroCopy, SignatureParsed,
};
use anyhow::anyhow;
use chrono::{DateTime, Utc};
use mithril_client::common::{
    BlockNumber, CardanoDbBeacon, Epoch, ProtocolMessage, ProtocolMessagePartKey,
    ProtocolParameters, SignedEntityType,
};
use mithril_common::{
    crypto_helper::{ProtocolAggregateVerificationKey, ProtocolKey, ProtocolMultiSignature},
    entities::{Certificate, CertificateMetadata, CertificateSignature, StakeDistributionParty},
};
use mithril_stm::{
    AggregateSignature, AggregateVerificationKey, BlsSignature, BlsVerificationKey,
    MerkleBatchPath, MerkleTreeBatchCommitment, MerkleTreeLeaf, SingleSignature,
    SingleSignatureWithRegisteredParty, StmAggrVerificationKey,
};
use std::collections::BTreeMap;

// Type alias from mithril-stm
type D = blake2::Blake2b<blake2::digest::consts::U32>;

#[inline]
pub fn certificate_from_zerocopy(basic: CertificateZeroCopy) -> Result<Certificate, anyhow::Error> {
    let metadata = reconstruct_metadata_fast(basic.metadata)?;
    let protocol_message = reconstruct_protocol_message_fast(basic.protocol_message)?;
    let aggregate_verification_key =
        reconstruct_aggregate_verification_key(basic.aggregate_verification_key)?;
    let signature = reconstruct_signature_fast(basic.signature)?;

    Ok(Certificate {
        hash: unsafe { String::from_utf8_unchecked(basic.hash.to_vec()) },
        previous_hash: unsafe { String::from_utf8_unchecked(basic.previous_hash.to_vec()) },
        epoch: Epoch(basic.epoch),
        metadata,
        protocol_message,
        signed_message: unsafe { String::from_utf8_unchecked(basic.signed_message.to_vec()) },
        aggregate_verification_key,
        signature,
    })
}

#[inline]
fn reconstruct_metadata_fast(
    basic: MetadataBasicZeroCopy,
) -> Result<CertificateMetadata, anyhow::Error> {
    let protocol_parameters = ProtocolParameters {
        k: basic.k,
        m: basic.m,
        phi_f: basic.phi_f,
    };

    let initiated_at = DateTime::<Utc>::from_timestamp(
        basic.initiated_at_timestamp as i64,
        basic.initiated_at_nanos,
    )
    .ok_or_else(|| anyhow!("Invalid initiated_at timestamp"))?;

    let sealed_at =
        DateTime::<Utc>::from_timestamp(basic.sealed_at_timestamp as i64, basic.sealed_at_nanos)
            .ok_or_else(|| anyhow!("Invalid sealed_at timestamp"))?;

    let signers = basic
        .signers
        .into_iter()
        .map(|s| StakeDistributionParty {
            party_id: unsafe { String::from_utf8_unchecked(s.party_id.to_vec()) },
            stake: s.stake,
        })
        .collect();

    Ok(CertificateMetadata {
        network: unsafe { String::from_utf8_unchecked(basic.network.to_vec()) },
        protocol_version: unsafe { String::from_utf8_unchecked(basic.protocol_version.to_vec()) },
        protocol_parameters,
        initiated_at,
        sealed_at,
        signers,
    })
}

#[inline]
fn reconstruct_protocol_message_fast(
    basic: ProtocolMessageBasicZeroCopy,
) -> Result<ProtocolMessage, anyhow::Error> {
    let mut message_parts = BTreeMap::new();

    for (key_discriminant, value) in basic.parts {
        let key = protocol_message_key_from_discriminant(key_discriminant)?;
        let value_string = unsafe { String::from_utf8_unchecked(value.to_vec()) };
        message_parts.insert(key, value_string);
    }

    Ok(ProtocolMessage { message_parts })
}

#[inline(always)]
fn protocol_message_key_from_discriminant(
    discriminant: u8,
) -> Result<ProtocolMessagePartKey, anyhow::Error> {
    match discriminant {
        0 => Ok(ProtocolMessagePartKey::SnapshotDigest),
        1 => Ok(ProtocolMessagePartKey::CardanoTransactionsMerkleRoot),
        2 => Ok(ProtocolMessagePartKey::NextAggregateVerificationKey),
        3 => Ok(ProtocolMessagePartKey::NextProtocolParameters),
        4 => Ok(ProtocolMessagePartKey::CurrentEpoch),
        5 => Ok(ProtocolMessagePartKey::LatestBlockNumber),
        6 => Ok(ProtocolMessagePartKey::CardanoStakeDistributionEpoch),
        7 => Ok(ProtocolMessagePartKey::CardanoStakeDistributionMerkleRoot),
        8 => Ok(ProtocolMessagePartKey::CardanoDatabaseMerkleRoot),
        _ => Err(anyhow!("Unknown protocol message key: {}", discriminant)),
    }
}

#[inline]
fn reconstruct_aggregate_verification_key(
    parsed: AggregateVerificationKeyParsed,
) -> Result<ProtocolAggregateVerificationKey, anyhow::Error> {
    use blake2::Blake2b;
    use blake2::digest::consts::U32;

    type D = Blake2b<U32>;

    // Reconstruct MerkleTreeBatchCommitment
    let mt_commitment = MerkleTreeBatchCommitment::<D>::new(
        parsed.root.to_vec(), // Must allocate for the commitment
        parsed.nr_leaves as usize,
    );

    // Reconstruct AggregateVerificationKey using the new constructor
    let avk = AggregateVerificationKey::<D>::new(mt_commitment, parsed.total_stake);

    // Wrap in ProtocolKey
    Ok(ProtocolKey::new(avk))
}

/// Reconstruct ProtocolMultiSignature from parsed zero-copy data
#[inline]
fn reconstruct_multi_signature(
    parsed: MultiSigParsed,
) -> Result<ProtocolMultiSignature, anyhow::Error> {
    // Reconstruct signatures vector
    let mut signatures = Vec::with_capacity(parsed.signatures.len());

    for sig_parsed in parsed.signatures {
        // Deserialize BLS signature from compressed G1 point (48 bytes)
        let sigma = BlsSignature::from_bytes(sig_parsed.sigma_bytes).map_err(|_| {
            anyhow!(
                "Failed to deserialize BLS signature from {} bytes",
                sig_parsed.sigma_bytes.len()
            )
        })?;

        // Deserialize BLS verification key from compressed G2 point (96 bytes)
        let vk = BlsVerificationKey::from_bytes(sig_parsed.vk_bytes).map_err(|_| {
            anyhow!(
                "Failed to deserialize BLS verification key from {} bytes",
                sig_parsed.vk_bytes.len()
            )
        })?;

        // Create SingleSignature
        let sig = SingleSignature {
            sigma,
            indexes: sig_parsed.indexes,
            signer_index: sig_parsed.signer_index,
        };

        // Create RegisteredParty (which is MerkleTreeLeaf)
        let reg_party = MerkleTreeLeaf(vk, sig_parsed.stake);

        // Create SingleSignatureWithRegisteredParty
        signatures.push(SingleSignatureWithRegisteredParty { sig, reg_party });
    }

    // Reconstruct batch proof from bytes
    let batch_proof = MerkleBatchPath::<D>::from_bytes(parsed.batch_proof_bytes)
        .map_err(|e| anyhow!("Failed to deserialize batch proof: {:?}", e))?;

    // Create AggregateSignature using the new constructor
    let aggregate_sig = AggregateSignature::<D>::new(signatures, batch_proof);

    // Wrap in ProtocolMultiSignature (which is ProtocolKey<AggregateSignature<D>>)
    Ok(ProtocolKey::new(aggregate_sig))
}

#[inline]
fn reconstruct_signature_fast(
    basic: SignatureBasicZeroCopy,
) -> Result<CertificateSignature, anyhow::Error> {
    match basic {
        SignatureBasicZeroCopy::Genesis { signature_bytes } => {
            if signature_bytes.len() != 64 {
                return Err(anyhow!(
                    "Invalid Ed25519 signature length: {}",
                    signature_bytes.len()
                ));
            }

            let sig_array: [u8; 64] = signature_bytes
                .try_into()
                .map_err(|_| anyhow!("Signature conversion failed"))?;

            let signature = ed25519_dalek::Signature::from_bytes(&sig_array);
            Ok(CertificateSignature::GenesisSignature(ProtocolKey::new(
                signature,
            )))
        }
        SignatureBasicZeroCopy::Multi {
            entity_type_discriminant,
            entity_type_data,
            signature, // MultiSigParsed
        } => {
            let entity_type =
                reconstruct_signed_entity_type(entity_type_discriminant, entity_type_data)?;

            // Reconstruct ProtocolMultiSignature from parsed data
            let multi_sig = reconstruct_multi_signature(signature)?;

            Ok(CertificateSignature::MultiSignature(entity_type, multi_sig))
        }
    }
}

#[inline]
fn reconstruct_signed_entity_type(
    discriminant: u8,
    data: Vec<u64>,
) -> Result<SignedEntityType, anyhow::Error> {
    match discriminant {
        0 if data.len() == 1 => Ok(SignedEntityType::MithrilStakeDistribution(Epoch(data[0]))),
        1 if data.len() == 1 => Ok(SignedEntityType::CardanoStakeDistribution(Epoch(data[0]))),
        2 if data.len() == 2 => Ok(SignedEntityType::CardanoImmutableFilesFull(
            CardanoDbBeacon {
                epoch: Epoch(data[0]),
                immutable_file_number: data[1],
            },
        )),
        3 if data.len() == 2 => Ok(SignedEntityType::CardanoDatabase(CardanoDbBeacon {
            epoch: Epoch(data[0]),
            immutable_file_number: data[1],
        })),
        4 if data.len() == 2 => Ok(SignedEntityType::CardanoTransactions(
            Epoch(data[0]),
            BlockNumber(data[1]),
        )),
        _ => Err(anyhow!(
            "Invalid entity type: {} with {} elements",
            discriminant,
            data.len()
        )),
    }
}
