pub mod certificate_verification;
pub mod parser;

#[cfg(feature = "host")]
pub use mithril_client::{CardanoTransactionsProofs, Client, ClientBuilder};
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
