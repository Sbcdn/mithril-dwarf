//! Cycle-optimized, allocation-free Cardano [Mithril](https://mithril.network)
//! certificate verifier, sized for zkVM guests (primary target:
//! [RISC Zero](https://risczero.com)) where every cycle is proving cost.
//!
//! Verdicts are bit-equivalent to upstream `mithril-common`'s
//! `MithrilCertificateVerifier`; the equivalence harness in
//! `mithril-dwarf-harness/` is the gate, and intentional cycle/precision
//! divergences are registered in its `intentional_divergences` test.
//!
//! # Usage
//!
//! Parse a certificate from the binary wire format into a borrowing
//! zero-copy view, then verify it against its predecessor:
//!
//! ```no_run
//! use mithril_dwarf::{certificate_from_bytes, verify_standard_certificate};
//!
//! fn accepts(cert_bytes: &[u8], prev_bytes: &[u8]) -> bool {
//!     let (Ok(cert), Ok(prev)) =
//!         (certificate_from_bytes(cert_bytes), certificate_from_bytes(prev_bytes))
//!     else {
//!         return false;
//!     };
//!     verify_standard_certificate(&cert, &prev).is_ok()
//! }
//! ```
//!
//! [`verify_standard_certificate`] runs four phases cheapest-first (basic
//! comparisons → SHA-256 over canonical bytes → cross-epoch chaining → BLS
//! multi-signature, Merkle batch proof, and lottery), so a malformed chain
//! is rejected before any cryptography runs. [`CertificateZeroCopy`] borrows
//! every field from the source buffer; failure paths allocate nothing.
//!
//! # Features
//!
//! - default (no features): the guest verifier. No `serde`, no canonical-JSON
//!   on the hot path.
//! - `host`: host-only helpers ([`certificate_to_bytes`] and conversions
//!   to/from upstream `mithril-common` types) used by the equivalence
//!   harness. Pulls `mithril-*` from a pinned upstream rev.
//!
//! The RISC0 SHA-256 / BLS / Ed25519 precompile `[patch.crates-io]` block is
//! applied by the downstream zkVM guest, not this crate — see `Cargo.toml`.

pub mod certificate_verification;
pub mod parser;

#[cfg(feature = "tx-inclusion")]
pub mod tx_inclusion;

#[cfg(feature = "host")]
pub use mithril_client::{
    AggregatorDiscoveryType, CardanoTransactionsProofs, Client, ClientBuilder,
    GenesisVerificationKey,
};
#[cfg(feature = "host")]
pub use mithril_common::{
    certificate_chain::{
        CertificateRetriever, CertificateRetrieverError, CertificateVerifier,
        MithrilCertificateVerifier,
    },
    crypto_helper::ProtocolGenesisVerificationKey,
    crypto_helper::ed25519::Ed25519VerificationKey,
    entities::Certificate,
    messages::CertificateMessage,
};

#[cfg(feature = "host")]
pub use parser::certificate_to_bytes;

pub use certificate_verification::{
    verify_certificate, verify_certificate_chain, verify_genesis_certificate,
    verify_standard_certificate,
};
pub use parser::{CertificateZeroCopy, certificate_from_bytes};
