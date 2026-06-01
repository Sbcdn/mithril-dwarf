//! Host-only serialiser: `mithril-common::Certificate` →
//! `CertificateZeroCopy`-shaped wire bytes.

use chrono::{DateTime, Utc};
use mithril_client::common::{ProtocolMessage, SignedEntityType};
use mithril_common::crypto_helper::{ProtocolAggregateVerificationKey, ProtocolMultiSignature};
use mithril_common::entities::{Certificate, CertificateMetadata, CertificateSignature};
// `BlsSignature` / `BlsVerificationKey` need mithril-stm's `benchmark-internals` feature.
use mithril_stm::{BlsSignature, BlsVerificationKey};

struct ByteWriter {
    buffer: Vec<u8>,
}

impl ByteWriter {
    #[inline(always)]
    fn new() -> Self {
        Self { buffer: Vec::new() }
    }

    #[inline(always)]
    fn write_u8(&mut self, val: u8) {
        self.buffer.push(val);
    }

    #[inline(always)]
    fn write_u16(&mut self, val: u16) {
        self.buffer.extend_from_slice(&val.to_le_bytes());
    }

    #[inline(always)]
    fn write_u32(&mut self, val: u32) {
        self.buffer.extend_from_slice(&val.to_le_bytes());
    }

    #[inline(always)]
    fn write_u64(&mut self, val: u64) {
        self.buffer.extend_from_slice(&val.to_le_bytes());
    }

    #[inline(always)]
    fn write_f64(&mut self, val: f64) {
        self.buffer.extend_from_slice(&val.to_le_bytes());
    }

    /// `u32` length prefix.
    #[inline(always)]
    fn write_string(&mut self, s: &str) {
        let bytes = s.as_bytes();
        self.write_u32(bytes.len() as u32);
        self.buffer.extend_from_slice(bytes);
    }

    /// `u8` length prefix — for `party_id` and similar short fields.
    #[inline(always)]
    fn write_short_string(&mut self, s: &str) {
        let bytes = s.as_bytes();
        self.write_u8(bytes.len() as u8);
        self.buffer.extend_from_slice(bytes);
    }

    /// `u32` length prefix.
    #[inline(always)]
    fn write_bytes(&mut self, bytes: &[u8]) {
        self.write_u32(bytes.len() as u32);
        self.buffer.extend_from_slice(bytes);
    }

    /// `u64` seconds + `u32` subsec nanos.
    #[inline(always)]
    fn write_datetime(&mut self, dt: &DateTime<Utc>) {
        self.write_u64(dt.timestamp() as u64);
        self.write_u32(dt.timestamp_subsec_nanos());
    }

    #[inline(always)]
    fn into_bytes(self) -> Vec<u8> {
        self.buffer
    }

    /// BLS G1 compressed (48 bytes), no length prefix.
    #[inline(always)]
    fn write_blst_sig(&mut self, sig: &BlsSignature) {
        let compressed = sig.0.to_bytes();
        self.buffer.extend_from_slice(&compressed);
    }

    /// BLS G2 compressed (96 bytes), no length prefix.
    #[inline(always)]
    fn write_blst_vk(&mut self, vk: &BlsVerificationKey) {
        let compressed = vk.to_bytes();
        self.buffer.extend_from_slice(&compressed);
    }
}

#[inline]
pub fn certificate_to_bytes(cert: &Certificate) -> Vec<u8> {
    let mut writer = ByteWriter::new();

    writer.write_string(&cert.hash);
    writer.write_string(&cert.previous_hash);
    writer.write_u64(cert.epoch.0);
    write_metadata(&mut writer, &cert.metadata);
    write_protocol_message(&mut writer, &cert.protocol_message);
    writer.write_string(&cert.signed_message);
    write_aggregate_verification_key(&mut writer, &cert.aggregate_verification_key);
    write_signature(&mut writer, &cert.signature);

    writer.into_bytes()
}

#[inline]
fn write_metadata(writer: &mut ByteWriter, metadata: &CertificateMetadata) {
    writer.write_string(&metadata.network);
    writer.write_string(&metadata.protocol_version);

    writer.write_u64(metadata.protocol_parameters.k);
    writer.write_u64(metadata.protocol_parameters.m);
    writer.write_f64(metadata.protocol_parameters.phi_f);

    writer.write_datetime(&metadata.initiated_at);
    writer.write_datetime(&metadata.sealed_at);

    writer.write_u16(metadata.signers.len() as u16);
    for signer in &metadata.signers {
        writer.write_short_string(&signer.party_id);
        writer.write_u64(signer.stake);
    }
}

#[inline]
fn write_protocol_message(writer: &mut ByteWriter, message: &ProtocolMessage) {
    writer.write_u8(message.message_parts.len() as u8);
    for (key, value) in &message.message_parts {
        writer.write_u8(*key as u8);
        writer.write_string(value);
    }
}

#[inline]
fn write_aggregate_verification_key(
    writer: &mut ByteWriter,
    avk: &ProtocolAggregateVerificationKey,
) {
    let avk_inner = &**avk;
    let mt_commitment = avk_inner.get_mt_commitment();
    let total_stake = avk_inner.get_total_stake();

    writer.write_bytes(&mt_commitment.root);
    writer.write_u64(mt_commitment.nr_leaves() as u64);
    writer.write_u64(total_stake);
}

/// Custom wire form for the multi-signature; deliberately not
/// `ProtocolMultiSignature::to_bytes()`, to match what `byte_deserializer`
/// reads directly into [`MultiSigParsed`].
#[inline]
fn write_multi_signature_optimal(writer: &mut ByteWriter, multi_sig: &ProtocolMultiSignature) {
    let agg_sig = &**multi_sig;
    let signatures = agg_sig.signatures();

    writer.write_u16(signatures.len() as u16);

    for sig_reg in signatures {
        let sig = &sig_reg.sig;
        let reg_party = &sig_reg.reg_party;

        writer.write_blst_sig(&sig.sigma);

        writer.write_u8(sig.indexes.len() as u8);
        for &idx in &sig.indexes {
            writer.write_u64(idx);
        }

        writer.write_u64(sig.signer_index);
        writer.write_blst_vk(&reg_party.0);
        writer.write_u64(reg_party.1);
    }

    let batch_proof_bytes = agg_sig.batch_proof.to_bytes();
    writer.write_bytes(&batch_proof_bytes);
}

#[inline]
fn write_signature(writer: &mut ByteWriter, signature: &CertificateSignature) {
    match signature {
        CertificateSignature::GenesisSignature(sig) => {
            writer.write_u8(0);
            writer.write_bytes(&sig.to_bytes());
        }
        CertificateSignature::MultiSignature(entity_type, multi_sig) => {
            writer.write_u8(1);
            write_signed_entity_type(writer, entity_type);
            write_multi_signature_optimal(writer, multi_sig);
        }
    }
}

/// Discriminants here track upstream's `SignedEntityType` *declaration*
/// order (which is what `*key as u8` produces), **not** upstream's
/// `ENTITY_TYPE_*` constants used by the `index()` method — those swap
/// `CardanoTransactions` and `CardanoDatabase`. The pin test
/// `signed_entity_type_discriminant_pinned` in the harness asserts
/// declaration order; if a future upstream reorder breaks it, this
/// mapping must move in lockstep.
#[inline]
fn write_signed_entity_type(writer: &mut ByteWriter, entity_type: &SignedEntityType) {
    match entity_type {
        SignedEntityType::MithrilStakeDistribution(epoch) => {
            writer.write_u8(0);
            writer.write_u64(epoch.0);
        }
        SignedEntityType::CardanoStakeDistribution(epoch) => {
            writer.write_u8(1);
            writer.write_u64(epoch.0);
        }
        SignedEntityType::CardanoImmutableFilesFull(beacon) => {
            writer.write_u8(2);
            writer.write_u64(beacon.epoch.0);
            writer.write_u64(beacon.immutable_file_number);
        }
        SignedEntityType::CardanoDatabase(beacon) => {
            writer.write_u8(3);
            writer.write_u64(beacon.epoch.0);
            writer.write_u64(beacon.immutable_file_number);
        }
        SignedEntityType::CardanoTransactions(epoch, block_number) => {
            writer.write_u8(4);
            writer.write_u64(epoch.0);
            writer.write_u64(block_number.0);
        }
    }
}

