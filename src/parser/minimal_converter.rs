//! Host-only converter: [`CertificateZeroCopy`] → upstream
//! `mithril-common::Certificate`.

use crate::parser::{
    AggregateVerificationKeyParsed, CertificateZeroCopy, MetadataBasicZeroCopy, MultiSigParsed,
    ProtocolMessageBasicZeroCopy, SignatureBasicZeroCopy,
};
use anyhow::anyhow;
use chrono::{DateTime, Utc};
use mithril_client::common::{
    BlockNumber, CardanoDbBeacon, Epoch, ProtocolMessage, ProtocolMessagePartKey,
    ProtocolParameters, SignedEntityType,
};
use mithril_common::{
    crypto_helper::{
        ProtocolAggregateVerificationKeyForConcatenation, ProtocolKey, ProtocolMembershipDigest,
        ProtocolMultiSignature,
    },
    entities::{Certificate, CertificateMetadata, CertificateSignature, StakeDistributionParty},
};
use mithril_stm::{
    AggregateSignature, AggregateVerificationKeyForConcatenation, BlsSignature, BlsVerificationKey,
    ClosedRegistrationEntry, ConcatenationProof, MembershipDigest, MerkleBatchPath,
    MerkleTreeBatchCommitment, MerkleTreeConcatenationLeaf, SingleSignature,
    SingleSignatureForConcatenation, SingleSignatureWithRegisteredParty,
};
use std::collections::BTreeMap;

type D = ProtocolMembershipDigest;
type ConcatHash = <D as MembershipDigest>::ConcatenationHash;

/// Validate `bytes` as UTF-8 and return the owned `String`. Host-only
/// path, so the cost of validation doesn't matter; the error
/// preserves the field name for callers handling adversarial input.
#[inline]
fn utf8_field(bytes: Vec<u8>, field: &'static str) -> Result<String, anyhow::Error> {
    String::from_utf8(bytes).map_err(|e| anyhow!("invalid UTF-8 in {field}: {e}"))
}

#[inline]
pub fn certificate_from_zerocopy(basic: CertificateZeroCopy) -> Result<Certificate, anyhow::Error> {
    let metadata = reconstruct_metadata_fast(basic.metadata)?;
    let protocol_message = reconstruct_protocol_message_fast(basic.protocol_message)?;
    let aggregate_verification_key =
        reconstruct_aggregate_verification_key(basic.aggregate_verification_key)?;
    let signature = reconstruct_signature_fast(basic.signature)?;

    Ok(Certificate {
        hash: utf8_field(basic.hash.to_vec(), "hash")?,
        previous_hash: utf8_field(basic.previous_hash.to_vec(), "previous_hash")?,
        epoch: Epoch(basic.epoch),
        metadata,
        protocol_message,
        signed_message: utf8_field(basic.signed_message.to_vec(), "signed_message")?,
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
        .map(|s| {
            Ok::<_, anyhow::Error>(StakeDistributionParty {
                party_id: utf8_field(s.party_id.to_vec(), "party_id")?,
                stake: s.stake,
            })
        })
        .collect::<Result<Vec<_>, _>>()?;

    Ok(CertificateMetadata {
        network: utf8_field(basic.network.to_vec(), "network")?,
        protocol_version: utf8_field(basic.protocol_version.to_vec(), "protocol_version")?,
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
        let value_string = utf8_field(value.to_vec(), "protocol_message_value")?;
        message_parts.insert(key, value_string);
    }

    Ok(ProtocolMessage { message_parts })
}

#[inline(always)]
fn protocol_message_key_from_discriminant(
    discriminant: u8,
) -> Result<ProtocolMessagePartKey, anyhow::Error> {
    // Discriminants match upstream Mithril 2617.0 declaration order.
    match discriminant {
        0 => Ok(ProtocolMessagePartKey::SnapshotDigest),
        1 => Ok(ProtocolMessagePartKey::CardanoTransactionsMerkleRoot),
        2 => Ok(ProtocolMessagePartKey::CardanoBlocksTransactionsMerkleRoot),
        3 => Ok(ProtocolMessagePartKey::NextAggregateVerificationKey),
        4 => Ok(ProtocolMessagePartKey::NextProtocolParameters),
        5 => Ok(ProtocolMessagePartKey::CurrentEpoch),
        6 => Ok(ProtocolMessagePartKey::LatestBlockNumber),
        7 => Ok(ProtocolMessagePartKey::CardanoBlocksTransactionsBlockNumberOffset),
        8 => Ok(ProtocolMessagePartKey::CardanoStakeDistributionEpoch),
        9 => Ok(ProtocolMessagePartKey::CardanoStakeDistributionMerkleRoot),
        10 => Ok(ProtocolMessagePartKey::CardanoDatabaseMerkleRoot),
        11 => Ok(ProtocolMessagePartKey::NextSnarkAggregateVerificationKey),
        _ => Err(anyhow!("Unknown protocol message key: {}", discriminant)),
    }
}

#[inline]
fn reconstruct_aggregate_verification_key(
    parsed: AggregateVerificationKeyParsed,
) -> Result<ProtocolAggregateVerificationKeyForConcatenation, anyhow::Error> {
    let mt_commitment = MerkleTreeBatchCommitment::<ConcatHash, MerkleTreeConcatenationLeaf>::new(
        parsed.root.to_vec(),
        parsed.nr_leaves as usize,
    );
    let concat_avk =
        AggregateVerificationKeyForConcatenation::<D>::new(mt_commitment, parsed.total_stake);
    Ok(ProtocolKey::new(concat_avk))
}

#[inline]
fn reconstruct_multi_signature(
    parsed: MultiSigParsed,
) -> Result<ProtocolMultiSignature, anyhow::Error> {
    let mut signatures = Vec::with_capacity(parsed.signatures.len());

    for sig_parsed in parsed.signatures {
        let sigma = BlsSignature::from_bytes(sig_parsed.sigma_bytes).map_err(|_| {
            anyhow!("BLS signature from {} bytes", sig_parsed.sigma_bytes.len())
        })?;
        let vk = BlsVerificationKey::from_bytes(sig_parsed.vk_bytes).map_err(|_| {
            anyhow!("BLS verification key from {} bytes", sig_parsed.vk_bytes.len())
        })?;

        // Materialise the borrowed index slice into a Vec at the host boundary.
        let concat_sig =
            SingleSignatureForConcatenation::new(sigma, sig_parsed.indexes().collect());
        let sig = SingleSignature::new(
            concat_sig,
            sig_parsed.signer_index,
            #[cfg(feature = "future_snark")]
            None,
        );
        let reg_party = ClosedRegistrationEntry::new(
            vk,
            sig_parsed.stake,
            #[cfg(feature = "future_snark")]
            None,
            #[cfg(feature = "future_snark")]
            None,
        );
        signatures.push(SingleSignatureWithRegisteredParty { sig, reg_party });
    }

    let batch_proof = MerkleBatchPath::<ConcatHash>::from_bytes(parsed.batch_proof_bytes)
        .map_err(|e| anyhow!("batch proof: {:?}", e))?;
    let concat_proof = ConcatenationProof::<D>::new(signatures, batch_proof);
    let aggregate_sig = AggregateSignature::<D>::Concatenation(Box::new(concat_proof));
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
                    "Ed25519 signature length: {}",
                    signature_bytes.len()
                ));
            }
            let sig_array: [u8; 64] = signature_bytes
                .try_into()
                .map_err(|_| anyhow!("signature conversion"))?;
            let signature = ed25519_dalek::Signature::from_bytes(&sig_array);
            Ok(CertificateSignature::GenesisSignature(ProtocolKey::new(
                signature,
            )))
        }
        SignatureBasicZeroCopy::Multi {
            entity_type_discriminant,
            entity_type_data,
            signature,
        } => {
            let entity_type =
                reconstruct_signed_entity_type(entity_type_discriminant, entity_type_data)?;
            let multi_sig = reconstruct_multi_signature(signature)?;
            Ok(CertificateSignature::MultiSignature(entity_type, multi_sig))
        }
    }
}

/// Rebuild the upstream `SignedEntityType` from the discriminant and
/// the fixed `[u64; 2]` slots produced by `read_entity_type_data_fast`.
#[inline]
fn reconstruct_signed_entity_type(
    discriminant: u8,
    data: [u64; 2],
) -> Result<SignedEntityType, anyhow::Error> {
    match discriminant {
        0 => Ok(SignedEntityType::MithrilStakeDistribution(Epoch(data[0]))),
        1 => Ok(SignedEntityType::CardanoStakeDistribution(Epoch(data[0]))),
        2 => Ok(SignedEntityType::CardanoImmutableFilesFull(
            CardanoDbBeacon {
                epoch: Epoch(data[0]),
                immutable_file_number: data[1],
            },
        )),
        3 => Ok(SignedEntityType::CardanoDatabase(CardanoDbBeacon {
            epoch: Epoch(data[0]),
            immutable_file_number: data[1],
        })),
        4 => Ok(SignedEntityType::CardanoTransactions(
            Epoch(data[0]),
            BlockNumber(data[1]),
        )),
        _ => Err(anyhow!("entity type discriminant: {discriminant}")),
    }
}
