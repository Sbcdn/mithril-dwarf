// Lightweight error type (no string allocations!)
#[derive(Debug, Clone, Copy)]
pub enum ParseError {
    OutOfBounds,
    InvalidFormat,
}

// Zero-copy parser - no Cursor overhead
pub struct FastByteParser<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> FastByteParser<'a> {
    #[inline(always)]
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    #[inline(always)]
    fn check_bounds(&self, needed: usize) -> Result<(), ParseError> {
        if self.pos + needed > self.data.len() {
            Err(ParseError::OutOfBounds)
        } else {
            Ok(())
        }
    }

    #[inline(always)]
    fn read_u8(&mut self) -> Result<u8, ParseError> {
        self.check_bounds(1)?;
        let val = self.data[self.pos];
        self.pos += 1;
        Ok(val)
    }

    #[inline(always)]
    fn read_u16(&mut self) -> Result<u16, ParseError> {
        self.check_bounds(2)?;
        let val = u16::from_le_bytes([self.data[self.pos], self.data[self.pos + 1]]);
        self.pos += 2;
        Ok(val)
    }

    #[inline(always)]
    fn read_u32(&mut self) -> Result<u32, ParseError> {
        self.check_bounds(4)?;
        let val = u32::from_le_bytes([
            self.data[self.pos],
            self.data[self.pos + 1],
            self.data[self.pos + 2],
            self.data[self.pos + 3],
        ]);
        self.pos += 4;
        Ok(val)
    }

    #[inline(always)]
    fn read_u64(&mut self) -> Result<u64, ParseError> {
        self.check_bounds(8)?;
        let val = u64::from_le_bytes([
            self.data[self.pos],
            self.data[self.pos + 1],
            self.data[self.pos + 2],
            self.data[self.pos + 3],
            self.data[self.pos + 4],
            self.data[self.pos + 5],
            self.data[self.pos + 6],
            self.data[self.pos + 7],
        ]);
        self.pos += 8;
        Ok(val)
    }

    #[inline(always)]
    fn read_f64(&mut self) -> Result<f64, ParseError> {
        self.check_bounds(8)?;
        let val = f64::from_le_bytes([
            self.data[self.pos],
            self.data[self.pos + 1],
            self.data[self.pos + 2],
            self.data[self.pos + 3],
            self.data[self.pos + 4],
            self.data[self.pos + 5],
            self.data[self.pos + 6],
            self.data[self.pos + 7],
        ]);
        self.pos += 8;
        Ok(val)
    }

    #[inline(always)]
    fn read_bytes_slice(&mut self) -> Result<&'a [u8], ParseError> {
        let len = self.read_u32()? as usize;
        self.check_bounds(len)?;
        let bytes = &self.data[self.pos..self.pos + len];
        self.pos += len;
        Ok(bytes)
    }

    #[inline(always)]
    fn read_short_bytes_slice(&mut self) -> Result<&'a [u8], ParseError> {
        let len = self.read_u8()? as usize;
        self.check_bounds(len)?;
        let bytes = &self.data[self.pos..self.pos + len];
        self.pos += len;
        Ok(bytes)
    }

    #[inline(always)]
    fn read_fixed_48(&mut self) -> Result<&'a [u8; 48], ParseError> {
        self.check_bounds(48)?;
        let slice = &self.data[self.pos..self.pos + 48];
        self.pos += 48;
        Ok(slice.try_into().unwrap())
    }

    #[inline(always)]
    fn read_fixed_96(&mut self) -> Result<&'a [u8; 96], ParseError> {
        self.check_bounds(96)?;
        let slice = &self.data[self.pos..self.pos + 96];
        self.pos += 96;
        Ok(slice.try_into().unwrap())
    }

    #[inline(always)]
    fn _skip(&mut self, n: usize) -> Result<(), ParseError> {
        self.check_bounds(n)?;
        self.pos += n;
        Ok(())
    }

    #[inline(always)]
    fn _skip_string(&mut self) -> Result<(), ParseError> {
        let len = self.read_u32()? as usize;
        self._skip(len)
    }

    #[inline(always)]
    fn _skip_short_string(&mut self) -> Result<(), ParseError> {
        let len = self.read_u8()? as usize;
        self._skip(len)
    }
}

// Zero-copy certificate structure
#[derive(Debug)]
pub struct CertificateZeroCopy<'a> {
    pub hash: &'a [u8],
    pub previous_hash: &'a [u8],
    pub epoch: u64,
    pub metadata: MetadataBasicZeroCopy<'a>,
    pub protocol_message: ProtocolMessageBasicZeroCopy<'a>,
    pub signed_message: &'a [u8],
    pub aggregate_verification_key: AggregateVerificationKeyParsed<'a>,
    pub signature: SignatureBasicZeroCopy<'a>,
}

#[derive(Debug)]
pub struct MetadataBasicZeroCopy<'a> {
    pub network: &'a [u8],
    pub protocol_version: &'a [u8],
    pub k: u64,
    pub m: u64,
    pub phi_f: f64,
    pub initiated_at_timestamp: u64,
    pub initiated_at_nanos: u32,
    pub sealed_at_timestamp: u64,
    pub sealed_at_nanos: u32,
    pub signers: Vec<SignerBasicZeroCopy<'a>>,
}

#[derive(Debug)]
pub struct SignerBasicZeroCopy<'a> {
    pub party_id: &'a [u8],
    pub stake: u64,
}

#[derive(Debug)]
pub struct ProtocolMessageBasicZeroCopy<'a> {
    pub parts: Vec<(u8, &'a [u8])>,
}

#[derive(Debug)]
pub struct AggregateVerificationKeyParsed<'a> {
    pub root: &'a [u8], // Zero-copy merkle root (32 bytes for Blake2b)
    pub nr_leaves: u64,
    pub total_stake: u64,
}

#[derive(Debug)]
pub struct MultiSigParsed<'a> {
    pub signatures: Vec<SignatureParsed<'a>>,
    pub batch_proof_bytes: &'a [u8],
}

#[derive(Debug)]
pub struct SignatureParsed<'a> {
    pub sigma_bytes: &'a [u8; 48], // BLS G1 point (zero-copy!)
    pub indexes: Vec<u64>,         // Small Vec, must allocate
    pub signer_index: u64,
    pub vk_bytes: &'a [u8; 96], // BLS G2 point (zero-copy!)
    pub stake: u64,
}

#[derive(Debug)]
pub enum SignatureBasicZeroCopy<'a> {
    Genesis {
        signature_bytes: &'a [u8],
    },
    Multi {
        entity_type_discriminant: u8,
        entity_type_data: Vec<u64>,
        signature: MultiSigParsed<'a>, // CHANGED: Parse our format instead of ProtocolMultiSignature
    },
}

// Fast parsing function
#[inline]
pub fn certificate_from_bytes_fast<'a>(
    bytes: &'a [u8],
) -> Result<CertificateZeroCopy<'a>, ParseError> {
    let mut parser = FastByteParser::new(bytes);

    let hash = parser.read_bytes_slice()?;
    let previous_hash = parser.read_bytes_slice()?;
    let epoch = parser.read_u64()?;
    let metadata = read_metadata_fast(&mut parser)?;
    let protocol_message = read_protocol_message_fast(&mut parser)?;
    let signed_message = parser.read_bytes_slice()?;
    let aggregate_verification_key = read_aggregate_verification_key_fast(&mut parser)?;
    let signature = read_signature_fast(&mut parser)?;

    Ok(CertificateZeroCopy {
        hash,
        previous_hash,
        epoch,
        metadata,
        protocol_message,
        signed_message,
        aggregate_verification_key,
        signature,
    })
}

#[inline]
fn read_metadata_fast<'a>(
    parser: &mut FastByteParser<'a>,
) -> Result<MetadataBasicZeroCopy<'a>, ParseError> {
    let network = parser.read_bytes_slice()?;
    let protocol_version = parser.read_bytes_slice()?;
    let k = parser.read_u64()?;
    let m = parser.read_u64()?;
    let phi_f = parser.read_f64()?;
    let initiated_at_timestamp = parser.read_u64()?;
    let initiated_at_nanos = parser.read_u32()?;
    let sealed_at_timestamp = parser.read_u64()?;
    let sealed_at_nanos = parser.read_u32()?;

    let signers_count = parser.read_u16()? as usize;
    let mut signers = Vec::with_capacity(signers_count);
    for _ in 0..signers_count {
        let party_id = parser.read_short_bytes_slice()?;
        let stake = parser.read_u64()?;
        signers.push(SignerBasicZeroCopy { party_id, stake });
    }

    Ok(MetadataBasicZeroCopy {
        network,
        protocol_version,
        k,
        m,
        phi_f,
        initiated_at_timestamp,
        initiated_at_nanos,
        sealed_at_timestamp,
        sealed_at_nanos,
        signers,
    })
}

#[inline]
fn read_protocol_message_fast<'a>(
    parser: &mut FastByteParser<'a>,
) -> Result<ProtocolMessageBasicZeroCopy<'a>, ParseError> {
    let parts_count = parser.read_u8()? as usize;
    let mut parts = Vec::with_capacity(parts_count);

    for _ in 0..parts_count {
        let key = parser.read_u8()?;
        let value = parser.read_bytes_slice()?;
        parts.push((key, value));
    }

    Ok(ProtocolMessageBasicZeroCopy { parts })
}

#[inline]
fn read_aggregate_verification_key_fast<'a>(
    parser: &mut FastByteParser<'a>,
) -> Result<AggregateVerificationKeyParsed<'a>, ParseError> {
    let root = parser.read_bytes_slice()?; // Zero-copy!
    let nr_leaves = parser.read_u64()?;
    let total_stake = parser.read_u64()?;

    Ok(AggregateVerificationKeyParsed {
        root,
        nr_leaves,
        total_stake,
    })
}

// UPDATED: Parse multi-signature in our optimized format
#[inline]
fn read_multi_signature_fast<'a>(
    parser: &mut FastByteParser<'a>,
) -> Result<MultiSigParsed<'a>, ParseError> {
    let sig_count = parser.read_u16()? as usize;
    let mut signatures = Vec::with_capacity(sig_count);

    for _ in 0..sig_count {
        let sigma_bytes = parser.read_fixed_48()?;

        let idx_count = parser.read_u8()? as usize;
        let mut indexes = Vec::with_capacity(idx_count);
        for _ in 0..idx_count {
            indexes.push(parser.read_u64()?);
        }

        let signer_index = parser.read_u64()?;
        let vk_bytes = parser.read_fixed_96()?;
        let stake = parser.read_u64()?;

        signatures.push(SignatureParsed {
            sigma_bytes,
            indexes,
            signer_index,
            vk_bytes,
            stake,
        });
    }

    let batch_proof_bytes = parser.read_bytes_slice()?;

    Ok(MultiSigParsed {
        signatures,
        batch_proof_bytes,
    })
}

#[inline]
fn read_signature_fast<'a>(
    parser: &mut FastByteParser<'a>,
) -> Result<SignatureBasicZeroCopy<'a>, ParseError> {
    let discriminant = parser.read_u8()?;

    match discriminant {
        0 => {
            let signature_bytes = parser.read_bytes_slice()?;
            Ok(SignatureBasicZeroCopy::Genesis { signature_bytes })
        }
        1 => {
            let entity_type_discriminant = parser.read_u8()?;
            let entity_type_data = read_entity_type_data_fast(parser, entity_type_discriminant)?;
            let signature = read_multi_signature_fast(parser)?;

            Ok(SignatureBasicZeroCopy::Multi {
                entity_type_discriminant,
                entity_type_data,
                signature,
            })
        }
        _ => Err(ParseError::InvalidFormat),
    }
}

#[inline]
fn read_entity_type_data_fast(
    parser: &mut FastByteParser,
    discriminant: u8,
) -> Result<Vec<u64>, ParseError> {
    match discriminant {
        0 | 1 => Ok(vec![parser.read_u64()?]),
        2 | 3 | 4 => Ok(vec![parser.read_u64()?, parser.read_u64()?]),
        _ => Err(ParseError::InvalidFormat),
    }
}
