//! Phase 2 checks: SHA-256 over canonical bytes.
//!
//! Each component (cert preimage, metadata, AVK, multi-signature, batch
//! proof) has both a streaming `_into` form that feeds an outer
//! `HashSink` and a `_digest` form that returns the raw 32 bytes.
//! `String`-returning wrappers (`compute_*_hash`, `*_to_json_hex`) exist
//! for the host API and tests; the in-zkVM verifier never calls them.

use super::{HashSink, Sha256Sink, VerifyError};
use crate::parser::{
    AggregateVerificationKeyParsed, CertificateZeroCopy, MetadataBasicZeroCopy, MultiSigParsed,
    ProtocolMessageBasicZeroCopy, SignatureBasicZeroCopy, SignatureParsed,
};
use sha2::{Digest, Sha256};

/// Lowercase hex lookup: byte → `[hi, lo]` ASCII. `const` so it lives in `.rodata`.
const HEX_LUT: [[u8; 2]; 256] = {
    let mut lut = [[0u8; 2]; 256];
    let mut i = 0;
    while i < 256 {
        let hi = (i >> 4) as u8;
        let lo = (i & 0x0f) as u8;
        lut[i][0] = if hi < 10 { b'0' + hi } else { b'a' + hi - 10 };
        lut[i][1] = if lo < 10 { b'0' + lo } else { b'a' + lo - 10 };
        i += 1;
    }
    lut
};

/// Streaming lowercase-hex encode; `hex::encode(bytes)` equivalent without
/// allocation. `?Sized` so [`JsonHexWriter`] can take `&mut dyn HashSink`.
#[inline]
pub fn hex_into<H: HashSink + ?Sized>(hasher: &mut H, bytes: &[u8]) {
    for &b in bytes {
        hasher.update(&HEX_LUT[b as usize]);
    }
}

/// Hex-encode a 32-byte digest into a stack `[u8; 64]` and emit it in one
/// `update` — the SHA-256 precompile is cheapest with large updates.
#[inline]
pub fn hex_digest_into<H: HashSink>(hasher: &mut H, digest: &[u8; 32]) {
    let mut buf = [0u8; 64];
    for (i, &b) in digest.iter().enumerate() {
        let entry = HEX_LUT[b as usize];
        buf[i * 2] = entry[0];
        buf[i * 2 + 1] = entry[1];
    }
    hasher.update(&buf);
}

/// Hex-encode a 32-byte digest into a caller-provided buffer for slice
/// comparison without allocating a `String`.
#[inline]
pub fn hex_digest_to_buf(digest: &[u8; 32], buf: &mut [u8; 64]) {
    for (i, &b) in digest.iter().enumerate() {
        let entry = HEX_LUT[b as usize];
        buf[i * 2] = entry[0];
        buf[i * 2 + 1] = entry[1];
    }
}

/// `core::fmt::Write` adapter that hex-encodes every written byte and
/// pushes it into the inner [`HashSink`]. Lets the JSON-streaming
/// helpers reuse `write!` without allocating a `String`.
///
/// Hex output is batched into a stack buffer; the residue flushes on
/// `Drop`, so the writer must go out of scope before the sink's digest
/// is consumed.
pub struct JsonHexWriter<'a, H: HashSink + ?Sized> {
    sink: &'a mut H,
    buf: [u8; HEX_BUFFER],
    len: usize,
}

/// Flush buffer size. 256 bytes ≥ the largest single JSON fragment any
/// streamer emits (the 96-byte VK array hex-encodes to 192 bytes).
const HEX_BUFFER: usize = 256;

impl<'a, H: HashSink + ?Sized> JsonHexWriter<'a, H> {
    #[inline]
    pub fn new(sink: &'a mut H) -> Self {
        Self {
            sink,
            buf: [0; HEX_BUFFER],
            len: 0,
        }
    }

    #[inline]
    fn push_hex(&mut self, bytes: &[u8]) {
        for &b in bytes {
            if self.len == HEX_BUFFER {
                self.sink.update(&self.buf);
                self.len = 0;
            }
            let entry = HEX_LUT[b as usize];
            self.buf[self.len] = entry[0];
            self.buf[self.len + 1] = entry[1];
            self.len += 2;
        }
    }
}

impl<H: HashSink + ?Sized> core::fmt::Write for JsonHexWriter<'_, H> {
    #[inline]
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        self.push_hex(s.as_bytes());
        Ok(())
    }
}

impl<H: HashSink + ?Sized> Drop for JsonHexWriter<'_, H> {
    #[inline]
    fn drop(&mut self) {
        if self.len > 0 {
            self.sink.update(&self.buf[..self.len]);
            self.len = 0;
        }
    }
}

/// Decimal-format `n` into `w` via a single `write_str`. Replacement for
/// `write!(w, "{}", n)` — `core::fmt`'s integer formatter emits multiple
/// small writes per integer, which compounds badly with hex streaming.
#[inline]
pub fn write_u8_dec<W: core::fmt::Write>(w: &mut W, n: u8) -> core::fmt::Result {
    let mut tmp = [0u8; 3];
    let mut idx = 3usize;
    let mut n = n;
    loop {
        idx -= 1;
        tmp[idx] = b'0' + (n % 10);
        n /= 10;
        if n == 0 {
            break;
        }
    }
    // SAFETY: tmp[idx..] is ASCII digits 0x30..=0x39, which is valid UTF-8.
    let s = unsafe { core::str::from_utf8_unchecked(&tmp[idx..]) };
    w.write_str(s)
}

/// Decimal-format `n` into `w`. Splits u64/u32 so the common case
/// (`n <= u32::MAX`) avoids RV32's software `__udivdi3`: u32 `/10` and
/// `%10` strength-reduce to multiply-shift, u64 doesn't.
#[inline]
pub fn write_u64_dec<W: core::fmt::Write>(w: &mut W, n: u64) -> core::fmt::Result {
    let mut tmp = [0u8; 20];
    let mut idx = 20usize;
    let mut n = n;
    while n > u32::MAX as u64 {
        idx -= 1;
        tmp[idx] = b'0' + (n % 10) as u8;
        n /= 10;
    }
    let mut n32 = n as u32;
    loop {
        idx -= 1;
        tmp[idx] = b'0' + (n32 % 10) as u8;
        n32 /= 10;
        if n32 == 0 {
            break;
        }
    }
    // SAFETY: tmp[idx..] is ASCII digits, valid UTF-8.
    let s = unsafe { core::str::from_utf8_unchecked(&tmp[idx..]) };
    w.write_str(s)
}

/// Borrow an existing [`Sha256`] as a [`HashSink`]. Separate from
/// `Sha256Sink` because that wrapper owns its inner state and can't be
/// reborrowed; the trait method must not collide with `Sha256::update`.
pub struct Sha256SinkRef<'a>(pub &'a mut Sha256);

impl HashSink for Sha256SinkRef<'_> {
    #[inline]
    fn update(&mut self, data: &[u8]) {
        sha2::digest::Update::update(self.0, data);
    }
}

/// `HashSink` that compares each `update` against an `expected` slice.
/// Short-circuits on the first mismatch so the producer can keep
/// streaming without per-byte compares.
pub struct EqSink<'a> {
    expected: &'a [u8],
    pos: usize,
    mismatch: bool,
}

impl<'a> EqSink<'a> {
    #[inline]
    pub fn new(expected: &'a [u8]) -> Self {
        Self {
            expected,
            pos: 0,
            mismatch: false,
        }
    }

    /// `true` iff the producer streamed exactly `expected` and no more.
    #[inline]
    pub fn matches(&self) -> bool {
        !self.mismatch && self.pos == self.expected.len()
    }
}

impl HashSink for EqSink<'_> {
    #[inline]
    fn update(&mut self, data: &[u8]) {
        if self.mismatch {
            return;
        }
        let end = self.pos + data.len();
        if end > self.expected.len() || self.expected[self.pos..end] != *data {
            self.mismatch = true;
        }
        self.pos = end;
    }
}

/// `cert.signed_message == hex(SHA-256(protocol_message))`.
/// Prefer [`verify_signed_message_matches_protocol_with_pm_digest`]
/// when `pm_digest` is already on hand.
#[inline]
pub fn verify_signed_message_matches_protocol(
    cert: &CertificateZeroCopy,
) -> Result<(), VerifyError> {
    let pm_digest = compute_protocol_message_digest(&cert.protocol_message);
    verify_signed_message_matches_protocol_with_pm_digest(cert, &pm_digest)
}

#[inline]
pub fn verify_signed_message_matches_protocol_with_pm_digest(
    cert: &CertificateZeroCopy,
    pm_digest: &[u8; 32],
) -> Result<(), VerifyError> {
    if cert.signed_message.len() != 64 {
        return Err(VerifyError::SignedMessageMismatch);
    }
    let mut computed_hex = [0u8; 64];
    hex_digest_to_buf(pm_digest, &mut computed_hex);
    if computed_hex != *cert.signed_message {
        return Err(VerifyError::SignedMessageMismatch);
    }
    Ok(())
}

/// `cert.hash == hex(SHA-256(canonical preimage))`.
/// Prefer [`verify_hash_matches_content_with_pm_digest`] when
/// `pm_digest` is already on hand.
#[inline]
pub fn verify_hash_matches_content(cert: &CertificateZeroCopy) -> Result<(), VerifyError> {
    if cert.hash.len() != 64 {
        return Err(VerifyError::HashMismatch);
    }
    let digest = compute_certificate_digest(cert)?;
    let mut computed_hex = [0u8; 64];
    hex_digest_to_buf(&digest, &mut computed_hex);
    if computed_hex != *cert.hash {
        return Err(VerifyError::HashMismatch);
    }
    Ok(())
}

/// Accepts `pm_digest`; recomputes `pp_digest` internally.
#[inline]
pub fn verify_hash_matches_content_with_pm_digest(
    cert: &CertificateZeroCopy,
    pm_digest: &[u8; 32],
) -> Result<(), VerifyError> {
    let pp_digest = compute_protocol_parameters_digest(
        cert.metadata.k,
        cert.metadata.m,
        cert.metadata.phi_f,
    );
    verify_hash_matches_content_with_pm_and_pp_digests(cert, pm_digest, &pp_digest)
}

/// Accepts both `pm_digest` and `pp_digest`. The top-level verifier
/// shares `pp_digest` with the cross-epoch protocol-params chain check.
#[inline]
pub fn verify_hash_matches_content_with_pm_and_pp_digests(
    cert: &CertificateZeroCopy,
    pm_digest: &[u8; 32],
    pp_digest: &[u8; 32],
) -> Result<(), VerifyError> {
    if cert.hash.len() != 64 {
        return Err(VerifyError::HashMismatch);
    }
    let mut sink = Sha256Sink::new();
    compute_certificate_hash_into_with_pm_and_pp_digests(&mut sink, cert, pm_digest, pp_digest)?;
    let digest: [u8; 32] = sink.finalize();
    let mut computed_hex = [0u8; 64];
    hex_digest_to_buf(&digest, &mut computed_hex);
    if computed_hex != *cert.hash {
        return Err(VerifyError::HashMismatch);
    }
    Ok(())
}

/// SHA-256 digest of the protocol message; matches Mithril's
/// `ProtocolMessage::compute_hash()`.
#[inline]
pub fn compute_protocol_message_digest(msg: &ProtocolMessageBasicZeroCopy) -> [u8; 32] {
    let mut h = Sha256::new();
    for (key_discriminant, value) in &msg.parts {
        let key_str = protocol_message_key_to_string(*key_discriminant);
        sha2::digest::Update::update(&mut h, key_str.as_bytes());
        sha2::digest::Update::update(&mut h, value);
    }
    h.finalize().into()
}

/// Hex form of [`compute_protocol_message_digest`]; host API + tests.
#[inline]
pub fn compute_protocol_message_hash(msg: &ProtocolMessageBasicZeroCopy) -> String {
    hex::encode(compute_protocol_message_digest(msg))
}

/// SHA-256 digest of the certificate; matches Mithril's
/// `Certificate::compute_hash()`. Streams every nested hash + JSON
/// fragment through the outer sink — no `String` is materialised.
#[inline]
pub fn compute_certificate_digest(cert: &CertificateZeroCopy) -> Result<[u8; 32], VerifyError> {
    let mut sink = Sha256Sink::new();
    compute_certificate_hash_into(&mut sink, cert)?;
    Ok(sink.finalize())
}

/// Hex form of [`compute_certificate_digest`]; host API + tests.
#[inline]
pub fn compute_certificate_hash(cert: &CertificateZeroCopy) -> Result<String, VerifyError> {
    Ok(hex::encode(compute_certificate_digest(cert)?))
}

/// Stream the cert-hash preimage into `hasher`. Recomputes `pm_digest`
/// internally; prefer [`compute_certificate_hash_into_with_pm_digest`]
/// when the caller already has it.
#[inline]
pub fn compute_certificate_hash_into<H: HashSink>(
    hasher: &mut H,
    cert: &CertificateZeroCopy,
) -> Result<(), VerifyError> {
    let pm_digest = compute_protocol_message_digest(&cert.protocol_message);
    compute_certificate_hash_into_with_pm_digest(hasher, cert, &pm_digest)
}

/// Accepts `pm_digest`; recomputes `pp_digest` internally.
#[inline]
pub fn compute_certificate_hash_into_with_pm_digest<H: HashSink>(
    hasher: &mut H,
    cert: &CertificateZeroCopy,
    pm_digest: &[u8; 32],
) -> Result<(), VerifyError> {
    let pp_digest = compute_protocol_parameters_digest(
        cert.metadata.k,
        cert.metadata.m,
        cert.metadata.phi_f,
    );
    compute_certificate_hash_into_with_pm_and_pp_digests(hasher, cert, pm_digest, &pp_digest)
}

/// Accepts both `pm_digest` and `pp_digest`. Preimage layout:
///   `previous_hash || epoch || hex(metadata_digest) ||
///    hex(pm_digest) || signed_message || hex(avk_json) || signature`.
#[inline]
pub fn compute_certificate_hash_into_with_pm_and_pp_digests<H: HashSink>(
    hasher: &mut H,
    cert: &CertificateZeroCopy,
    pm_digest: &[u8; 32],
    pp_digest: &[u8; 32],
) -> Result<(), VerifyError> {
    hasher.update(cert.previous_hash);
    hasher.update(&cert.epoch.to_be_bytes());

    compute_metadata_hash_into_with_pp_digest(hasher, &cert.metadata, pp_digest)?;

    hex_digest_into(hasher, pm_digest);

    hasher.update(cert.signed_message);

    avk_to_json_hex_into(hasher, &cert.aggregate_verification_key)?;

    hash_signature(hasher, &cert.signature)?;

    Ok(())
}

/// SHA-256 digest of metadata; matches Mithril's
/// `CertificateMetadata::compute_hash()`.
#[inline]
pub fn compute_metadata_digest(
    metadata: &MetadataBasicZeroCopy,
) -> Result<[u8; 32], VerifyError> {
    let pp_digest =
        compute_protocol_parameters_digest(metadata.k, metadata.m, metadata.phi_f);
    compute_metadata_digest_with_pp_digest(metadata, &pp_digest)
}

/// Accepts `pp_digest`. The per-signer hasher is hoisted across the
/// signer loop and reused via `finalize_reset`, paying the SHA-256 IV
/// cost once per cert instead of once per signer.
#[inline]
pub fn compute_metadata_digest_with_pp_digest(
    metadata: &MetadataBasicZeroCopy,
    pp_digest: &[u8; 32],
) -> Result<[u8; 32], VerifyError> {
    let mut h = Sha256::new();

    sha2::digest::Update::update(&mut h, metadata.network);
    sha2::digest::Update::update(&mut h, metadata.protocol_version);

    {
        let mut sink = Sha256SinkRef(&mut h);
        hex_digest_into(&mut sink, pp_digest);
    }

    let initiated_nanos =
        metadata.initiated_at_timestamp * 1_000_000_000 + metadata.initiated_at_nanos as u64;
    let sealed_nanos =
        metadata.sealed_at_timestamp * 1_000_000_000 + metadata.sealed_at_nanos as u64;
    sha2::digest::Update::update(&mut h, &initiated_nanos.to_be_bytes());
    sha2::digest::Update::update(&mut h, &sealed_nanos.to_be_bytes());

    let mut signer_h = Sha256::new();
    for signer in &metadata.signers {
        sha2::digest::Update::update(&mut signer_h, signer.party_id);
        sha2::digest::Update::update(&mut signer_h, &signer.stake.to_be_bytes());
        let signer_digest: [u8; 32] = <Sha256 as Digest>::finalize_reset(&mut signer_h).into();
        {
            let mut sink = Sha256SinkRef(&mut h);
            hex_digest_into(&mut sink, &signer_digest);
        }
    }

    Ok(h.finalize().into())
}

/// Compute SHA-256 hash of metadata (returns hex string). Thin
/// wrapper over [`compute_metadata_digest`].
#[inline]
pub fn compute_metadata_hash(metadata: &MetadataBasicZeroCopy) -> Result<String, VerifyError> {
    Ok(hex::encode(compute_metadata_digest(metadata)?))
}

/// Stream the hex of the metadata digest directly into `outer`. Used
/// by [`compute_certificate_hash_into`] to feed metadata into the
/// outer cert hash without going through a `String`.
#[inline]
pub fn compute_metadata_hash_into<H: HashSink>(
    outer: &mut H,
    metadata: &MetadataBasicZeroCopy,
) -> Result<(), VerifyError> {
    let digest = compute_metadata_digest(metadata)?;
    hex_digest_into(outer, &digest);
    Ok(())
}

/// Same as [`compute_metadata_hash_into`] but accepts a pre-computed
/// protocol-parameters digest — saves one `SHA-256` of the
/// `k || m || phi_f_fixed` triple per cert when the caller already
/// has it.
#[inline]
pub fn compute_metadata_hash_into_with_pp_digest<H: HashSink>(
    outer: &mut H,
    metadata: &MetadataBasicZeroCopy,
    pp_digest: &[u8; 32],
) -> Result<(), VerifyError> {
    let digest = compute_metadata_digest_with_pp_digest(metadata, pp_digest)?;
    hex_digest_into(outer, &digest);
    Ok(())
}

/// Compute the raw 32-byte SHA-256 digest of protocol parameters.
/// Uses fixed-point representation for `phi_f` (U8F24) to match
/// upstream Mithril byte-for-byte.
#[inline]
pub fn compute_protocol_parameters_digest(k: u64, m: u64, phi_f: f64) -> [u8; 32] {
    use fixed::types::U8F24;

    let mut h = Sha256::new();
    sha2::digest::Update::update(&mut h, &k.to_be_bytes());
    sha2::digest::Update::update(&mut h, &m.to_be_bytes());
    let phi_f_fixed = U8F24::from_num(phi_f);
    sha2::digest::Update::update(&mut h, &phi_f_fixed.to_bits().to_be_bytes());
    h.finalize().into()
}

/// Compute SHA-256 hash of protocol parameters (returns hex string).
#[inline]
pub fn compute_protocol_parameters_hash(k: u64, m: u64, phi_f: f64) -> String {
    hex::encode(compute_protocol_parameters_digest(k, m, phi_f))
}

/// Compute the raw 32-byte SHA-256 digest of a single signer.
#[inline]
pub fn compute_signer_digest(party_id: &[u8], stake: u64) -> [u8; 32] {
    let mut h = Sha256::new();
    sha2::digest::Update::update(&mut h, party_id);
    sha2::digest::Update::update(&mut h, &stake.to_be_bytes());
    h.finalize().into()
}

/// Compute SHA-256 hash of a signer (returns hex string).
#[inline]
pub fn compute_signer_hash(party_id: &[u8], stake: u64) -> String {
    hex::encode(compute_signer_digest(party_id, stake))
}

/// Write the canonical AVK JSON
/// (`{"mt_commitment":{"root":[…],"nr_leaves":N,"hasher":null},"total_stake":M}`)
/// into any [`core::fmt::Write`] target.
///
/// Pair this with a [`JsonHexWriter`] to stream the hex form into a
/// [`HashSink`], or with a `String` to get the legacy hex-string API
/// (host / tests).
#[inline]
pub fn avk_to_json_into<W: core::fmt::Write>(
    w: &mut W,
    avk: &AggregateVerificationKeyParsed,
) -> Result<(), VerifyError> {
    w.write_str(r#"{"mt_commitment":{"root":["#)
        .map_err(|_| VerifyError::FormatError)?;
    for (i, byte) in avk.root.iter().enumerate() {
        if i > 0 {
            w.write_str(",").map_err(|_| VerifyError::FormatError)?;
        }
        write_u8_dec(w, *byte).map_err(|_| VerifyError::FormatError)?;
    }
    w.write_str(r#"],"nr_leaves":"#)
        .map_err(|_| VerifyError::FormatError)?;
    write_u64_dec(w, avk.nr_leaves).map_err(|_| VerifyError::FormatError)?;
    w.write_str(r#","hasher":null},"total_stake":"#)
        .map_err(|_| VerifyError::FormatError)?;
    write_u64_dec(w, avk.total_stake).map_err(|_| VerifyError::FormatError)?;
    w.write_str("}").map_err(|_| VerifyError::FormatError)?;
    Ok(())
}

/// Stream the hex of the AVK JSON directly into `outer` — no `String`
/// allocation, every JSON byte becomes two LUT-driven hex bytes on the
/// outer hasher.
#[inline]
pub fn avk_to_json_hex_into<H: HashSink>(
    outer: &mut H,
    avk: &AggregateVerificationKeyParsed,
) -> Result<(), VerifyError> {
    let mut w = JsonHexWriter::new(outer);
    avk_to_json_into(&mut w, avk)
}

/// Hex form of the AVK JSON; host API + tests.
#[inline]
pub fn avk_to_json_hex(avk: &AggregateVerificationKeyParsed) -> Result<String, VerifyError> {
    let mut json = String::with_capacity(300);
    avk_to_json_into(&mut json, avk)?;
    Ok(hex::encode(json.as_bytes()))
}

/// Stream the signature section into the outer cert hash. Genesis: hex
/// of the 64-byte signature. Multi: entity-type fields raw, followed by
/// hex of the multi-signature JSON.
#[inline]
pub fn hash_signature<H: HashSink>(
    hasher: &mut H,
    sig: &SignatureBasicZeroCopy,
) -> Result<(), VerifyError> {
    match sig {
        SignatureBasicZeroCopy::Genesis { signature_bytes } => {
            hex_into(hasher, signature_bytes);
        }
        SignatureBasicZeroCopy::Multi {
            entity_type_discriminant,
            entity_type_data,
            signature,
        } => {
            feed_entity_type_hash(hasher, *entity_type_discriminant, entity_type_data);
            multi_signature_to_json_hex_into(hasher, signature)?;
        }
    }
    Ok(())
}

/// Mithril's `feed_hash` over a `SignedEntityType`. Discriminants 0/1
/// emit `data[0]` only; 2/3/4 emit both fields. The parser rejects any
/// other discriminant, so the `_` arm is unreachable.
#[inline]
pub fn feed_entity_type_hash<H: HashSink>(hasher: &mut H, discriminant: u8, data: &[u64; 2]) {
    match discriminant {
        0 | 1 => {
            hasher.update(&data[0].to_be_bytes());
        }
        2 | 3 | 4 => {
            hasher.update(&data[0].to_be_bytes());
            hasher.update(&data[1].to_be_bytes());
        }
        _ => debug_assert!(false, "parser rejects unknown discriminant"),
    }
}

/// Canonical multi-signature JSON: `{"signatures":[…],"batch_proof":{…}}`.
#[inline]
pub fn multi_signature_to_json_into<W: core::fmt::Write>(
    w: &mut W,
    multi_sig: &MultiSigParsed,
) -> Result<(), VerifyError> {
    w.write_str(r#"{"signatures":["#)
        .map_err(|_| VerifyError::FormatError)?;
    for (i, sig) in multi_sig.signatures.iter().enumerate() {
        if i > 0 {
            w.write_str(",").map_err(|_| VerifyError::FormatError)?;
        }
        serialize_single_signature_into(w, sig)?;
    }
    w.write_str(r#"],"batch_proof":"#)
        .map_err(|_| VerifyError::FormatError)?;
    serialize_batch_proof_into(w, multi_sig.batch_proof_bytes)?;
    w.write_str("}").map_err(|_| VerifyError::FormatError)?;
    Ok(())
}

/// Stream the hex form of the multi-signature JSON into `outer`. The
/// JSON is ~100 KB on a mainnet cert; streaming avoids materialising it.
#[inline]
pub fn multi_signature_to_json_hex_into<H: HashSink>(
    outer: &mut H,
    multi_sig: &MultiSigParsed,
) -> Result<(), VerifyError> {
    let mut w = JsonHexWriter::new(outer);
    multi_signature_to_json_into(&mut w, multi_sig)
}

/// Hex form of the multi-signature JSON; in-file tests.
#[inline]
pub fn multi_signature_to_json_hex(multi_sig: &MultiSigParsed) -> Result<String, VerifyError> {
    let mut json = String::with_capacity(2048);
    multi_signature_to_json_into(&mut json, multi_sig)?;
    Ok(hex::encode(json.as_bytes()))
}

/// Canonical single-signature JSON:
/// `[{"sigma":[…],"indexes":[…],"signer_index":N},[[vk_bytes],stake]]`.
#[inline]
pub fn serialize_single_signature_into<W: core::fmt::Write>(
    w: &mut W,
    sig: &SignatureParsed,
) -> Result<(), VerifyError> {
    w.write_str(r#"[{"sigma":["#)
        .map_err(|_| VerifyError::FormatError)?;
    for (i, byte) in sig.sigma_bytes.iter().enumerate() {
        if i > 0 {
            w.write_str(",").map_err(|_| VerifyError::FormatError)?;
        }
        write_u8_dec(w, *byte).map_err(|_| VerifyError::FormatError)?;
    }
    w.write_str(r#"],"indexes":["#)
        .map_err(|_| VerifyError::FormatError)?;
    for (i, idx) in sig.indexes().enumerate() {
        if i > 0 {
            w.write_str(",").map_err(|_| VerifyError::FormatError)?;
        }
        write_u64_dec(w, idx).map_err(|_| VerifyError::FormatError)?;
    }
    w.write_str(r#"],"signer_index":"#)
        .map_err(|_| VerifyError::FormatError)?;
    write_u64_dec(w, sig.signer_index).map_err(|_| VerifyError::FormatError)?;
    w.write_str("}").map_err(|_| VerifyError::FormatError)?;

    // `[[vk_array], stake]` — the double `[[` matches Mithril's wire form.
    w.write_str(",[[").map_err(|_| VerifyError::FormatError)?;
    for (i, byte) in sig.vk_bytes.iter().enumerate() {
        if i > 0 {
            w.write_str(",").map_err(|_| VerifyError::FormatError)?;
        }
        write_u8_dec(w, *byte).map_err(|_| VerifyError::FormatError)?;
    }
    w.write_str("],").map_err(|_| VerifyError::FormatError)?;
    write_u64_dec(w, sig.stake).map_err(|_| VerifyError::FormatError)?;
    w.write_str("]]").map_err(|_| VerifyError::FormatError)?;
    Ok(())
}

/// `String`-targeted form; tests only.
#[inline]
pub fn serialize_single_signature(
    json: &mut String,
    sig: &SignatureParsed,
) -> Result<(), VerifyError> {
    serialize_single_signature_into(json, sig)
}

/// Parse MerkleBatchPath from bytes
/// Direct translation from mithril-stm's from_bytes()
/// Format: len_v (u64 BE) | len_i (u64 BE) | values (32 bytes each) | indices (u64 BE each)
#[inline]
pub fn parse_batch_proof(bytes: &[u8]) -> Result<ParsedBatchProof<'_>, VerifyError> {
    const HASH_SIZE: usize = 32; // Blake2b<U32>

    if bytes.len() < 16 {
        return Err(VerifyError::InvalidBatchProof);
    }

    let len_v = u64::from_be_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ]) as usize;
    let len_i = u64::from_be_bytes([
        bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15],
    ]) as usize;

    if len_v > 10000 || len_i > 10000 {
        return Err(VerifyError::InvalidBatchProof);
    }

    // Values are a packed 32-byte sequence; callers index via
    // `&values[i*32..(i+1)*32]` to skip an outer Vec allocation.
    let values_start = 16;
    let values_end = values_start + (len_v * HASH_SIZE);
    if values_end > bytes.len() {
        return Err(VerifyError::InvalidBatchProof);
    }
    let values: &[u8] = &bytes[values_start..values_end];

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

/// `values` is the packed sibling-hash blob (32 bytes per entry).
pub struct ParsedBatchProof<'a> {
    pub indices: Vec<u64>,
    pub values: &'a [u8],
}

/// Canonical batch-proof JSON:
/// `{"values":[[byte,…],…],"indices":[idx,…],"hasher":null}`.
#[inline]
pub fn serialize_batch_proof_into<W: core::fmt::Write>(
    w: &mut W,
    proof_bytes: &[u8],
) -> Result<(), VerifyError> {
    let proof = parse_batch_proof(proof_bytes)?;

    w.write_str(r#"{"values":["#)
        .map_err(|_| VerifyError::FormatError)?;
    for (i, value) in proof.values.chunks_exact(32).enumerate() {
        if i > 0 {
            w.write_str(",").map_err(|_| VerifyError::FormatError)?;
        }
        w.write_str("[").map_err(|_| VerifyError::FormatError)?;
        for (j, byte) in value.iter().enumerate() {
            if j > 0 {
                w.write_str(",").map_err(|_| VerifyError::FormatError)?;
            }
            write_u8_dec(w, *byte).map_err(|_| VerifyError::FormatError)?;
        }
        w.write_str("]").map_err(|_| VerifyError::FormatError)?;
    }

    w.write_str(r#"],"indices":["#)
        .map_err(|_| VerifyError::FormatError)?;
    for (i, idx) in proof.indices.iter().enumerate() {
        if i > 0 {
            w.write_str(",").map_err(|_| VerifyError::FormatError)?;
        }
        write_u64_dec(w, *idx).map_err(|_| VerifyError::FormatError)?;
    }
    w.write_str(r#"],"hasher":null}"#)
        .map_err(|_| VerifyError::FormatError)?;
    Ok(())
}

/// `String`-targeted form; tests only.
#[inline]
pub fn serialize_batch_proof(json: &mut String, proof_bytes: &[u8]) -> Result<(), VerifyError> {
    serialize_batch_proof_into(json, proof_bytes)
}

/// `ProtocolMessagePartKey` → upstream's snake_case serde name.
#[inline]
pub fn protocol_message_key_to_string(discriminant: u8) -> &'static str {
    match discriminant {
        0 => "snapshot_digest",
        1 => "cardano_transactions_merkle_root",
        2 => "cardano_blocks_transactions_merkle_root",
        3 => "next_aggregate_verification_key",
        4 => "next_protocol_parameters",
        5 => "current_epoch",
        6 => "latest_block_number",
        7 => "cardano_blocks_transactions_block_number_offset",
        8 => "cardano_stake_distribution_epoch",
        9 => "cardano_stake_distribution_merkle_root",
        10 => "cardano_database_merkle_root",
        11 => "next_aggregate_verification_key_snark",
        _ => "unknown",
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::parser::{ParseError, certificate_from_bytes};

    pub fn test_certificate_hash_from_bytes(
        cert_bytes: &[u8],
    ) -> Result<HashTestResult, TestError> {
        let cert = certificate_from_bytes(cert_bytes).map_err(|e| TestError::ParseError(e))?;
        let original_hash = core::str::from_utf8(cert.hash)
            .map_err(|_| TestError::InvalidUtf8)?
            .to_string();
        let computed_hash =
            compute_certificate_hash(&cert).map_err(|e| TestError::VerifyError(e))?;
        let matches = original_hash == computed_hash;
        Ok(HashTestResult {
            original_hash,
            computed_hash,
            matches,
            details: compute_hash_details(&cert)?,
        })
    }

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
        pub fn print_detailed(&self) {
            println!("\n-- certificate hash test --");
            println!("match: {}", if self.matches { "yes" } else { "no" });
            println!("original: {}", self.original_hash);
            println!("computed: {}", self.computed_hash);

            if !self.matches {
                println!("\ncharacter diff:");
                for (i, (orig, comp)) in self
                    .original_hash
                    .chars()
                    .zip(self.computed_hash.chars())
                    .enumerate()
                {
                    if orig != comp {
                        println!("  position {}: '{}' != '{}'", i, orig, comp);
                    }
                }
            }

            println!("\ncomponents:");
            println!("  protocol message hash: {}", self.details.protocol_message_hash);
            println!("  metadata hash:         {}", self.details.metadata_hash);

            println!("\navk json (hex): {}", self.details.avk_json);
            if let Some(decoded) = &self.details.avk_json_decoded {
                println!("avk json: {}", decoded);
            }

            if let Some(sig_json) = &self.details.signature_json {
                println!("\nsignature json (hex): {}", sig_json);
                if let Some(decoded) = &self.details.signature_json_decoded {
                    let preview = if decoded.len() > 500 {
                        &decoded[..500]
                    } else {
                        decoded.as_str()
                    };
                    println!("signature json (first 500 chars): {}", preview);
                    if decoded.len() > 500 {
                        println!("... ({} more chars)", decoded.len() - 500);
                    }
                }
            }
        }
    }

    #[test]
    fn test_protocol_parameters_hash() {
        let k = 2422;
        let m = 20973;
        let phi_f = 0.2;
        let hash = compute_protocol_parameters_hash(k, m, phi_f);
        assert_eq!(hash.len(), 64);
    }

    #[test]
    fn test_signer_hash() {
        let party_id = b"pool1test123456789";
        let stake = 1000000;
        let hash = compute_signer_hash(party_id, stake);
        assert_eq!(hash.len(), 64);
    }

    #[test]
    fn test_avk_json_format() {
        let root = [1u8; 32];
        let avk = AggregateVerificationKeyParsed {
            root: &root,
            nr_leaves: 100,
            total_stake: 5000000000,
        };
        let json_hex = avk_to_json_hex(&avk).expect("AVK JSON");
        let json_bytes = hex::decode(&json_hex).expect("hex decode");
        let json_str = String::from_utf8(json_bytes).expect("utf-8");
        assert!(json_str.contains(r#""mt_commitment""#));
        assert!(json_str.contains(r#""root""#));
        assert!(json_str.contains(r#""nr_leaves""#));
        assert!(json_str.contains(r#""total_stake""#));
    }
}
