pub mod certificate_verification;
pub mod parser;

#[cfg(feature = "host")]
pub use mithril_client::{CardanoTransactionsProofs, Client, ClientBuilder, MithrilCertificate};
#[cfg(feature = "host")]
pub use mithril_common::{crypto_helper::ed25519::Ed25519VerificationKey, entities::Certificate};
#[cfg(feature = "host")]
pub use parser::certificate_to_bytes;

pub use certificate_verification::{
    verify_certificate, verify_certificate_chain, verify_genesis_certificate,
    verify_standard_certificate,
};
pub use parser::certificate_from_bytes;
