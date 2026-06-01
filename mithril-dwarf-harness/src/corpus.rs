//! Corpus loader. `load_corpus` returns the parsed entries plus an
//! explicit list of files that failed to load; callers decide whether
//! to tolerate that.

use mithril_common::messages::CertificateMessage;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Mainnet genesis Ed25519 VK in `mithril-common`'s JSON-of-bytes hex
/// form (`"[191,66,...]"` hex-encoded).
pub const MAINNET_GENESIS_VK_HEX: &str = "5b3139312c36362c3134302c3138352c3133382c31312c3233372c3230372c3235302c3134342c32372c322c3138382c33302c31322c38312c3135352c3230342c31302c3137392c37352c32332c3133382c3139362c3231372c352c31342c32302c35372c37392c33392c3137365d";

/// Preprod / Preview share the same genesis VK; see
/// `Network::get_genesis_key()` in upstream `fetch_certificates`.
pub const PREPROD_GENESIS_VK_HEX: &str = "5b3132372c37332c3132342c3136312c362c3133372c3133312c3231332c3230372c3131372c3139382c38352c3137362c3139392c3136322c3234312c36382c3132332c3131392c3134352c31332c3233322c3234332c34392c3232392c322c3234392c3230352c3230352c33392c3233352c34345d";

pub const PREVIEW_GENESIS_VK_HEX: &str = PREPROD_GENESIS_VK_HEX;

/// Genesis VK for the cert's network; `None` on an unrecognised network
/// so callers surface plumbing misses loudly rather than silently
/// falling back to mainnet.
pub fn genesis_vk_for_cert(cert: &CertificateMessage) -> Option<&'static str> {
    match cert.metadata.network.as_str() {
        "mainnet" => Some(MAINNET_GENESIS_VK_HEX),
        "preprod" => Some(PREPROD_GENESIS_VK_HEX),
        "preview" => Some(PREVIEW_GENESIS_VK_HEX),
        _ => None,
    }
}

pub const CERT_FILE_EXTENSION: &str = "cert";
pub const NULL_PARENT_HASH: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Debug, Clone)]
pub enum CorpusEntry {
    Standard {
        current: CertificateMessage,
        previous: CertificateMessage,
    },
    Genesis {
        cert: CertificateMessage,
    },
}

impl CorpusEntry {
    pub fn primary_cert(&self) -> &CertificateMessage {
        match self {
            Self::Standard { current, .. } => current,
            Self::Genesis { cert } => cert,
        }
    }

    pub fn hash(&self) -> &str {
        &self.primary_cert().hash
    }
}

#[derive(Debug, Clone)]
pub struct CorpusLoad {
    pub entries: Vec<CorpusEntry>,
    pub load_errors: Vec<LoadError>,
    pub orphans: Vec<String>,
    pub genesis_count: usize,
    pub standard_same_epoch: usize,
    pub standard_diff_epoch: usize,
}

#[derive(Debug, Clone)]
pub struct LoadError {
    pub path: PathBuf,
    pub reason: String,
}

pub fn is_genesis(cert: &CertificateMessage) -> bool {
    cert.previous_hash.is_empty() || cert.previous_hash == NULL_PARENT_HASH
}

/// Cap on the size of a deserialized `CertificateMessage` to avoid
/// `Vec`-length-of-`u64::MAX` OOM from a corrupted or malicious `.cert`
/// file. 16 MiB is well above the largest real Mithril cert (~150 KiB).
const CERT_DESERIALIZE_LIMIT: u64 = 16 * 1024 * 1024;

pub fn load_certificate_from_path(path: &Path) -> Result<CertificateMessage, String> {
    use bincode::Options;
    let bytes = std::fs::read(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    bincode::DefaultOptions::new()
        .with_limit(CERT_DESERIALIZE_LIMIT)
        .with_fixint_encoding()
        .allow_trailing_bytes()
        .deserialize(&bytes)
        .map_err(|e| format!("deserialize {}: {e}", path.display()))
}

pub fn load_corpus(dir: &Path) -> CorpusLoad {
    let mut all: HashMap<String, CertificateMessage> = HashMap::new();
    let mut load_errors = Vec::new();

    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) => {
            load_errors.push(LoadError {
                path: dir.to_path_buf(),
                reason: format!("read_dir: {e}"),
            });
            return CorpusLoad {
                entries: Vec::new(),
                load_errors,
                orphans: Vec::new(),
                genesis_count: 0,
                standard_same_epoch: 0,
                standard_diff_epoch: 0,
            };
        }
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some(CERT_FILE_EXTENSION) {
            continue;
        }
        match load_certificate_from_path(&path) {
            Ok(cert) => {
                all.insert(cert.hash.clone(), cert);
            }
            Err(reason) => {
                load_errors.push(LoadError { path, reason });
            }
        }
    }

    let mut entries = Vec::with_capacity(all.len());
    let mut orphans = Vec::new();
    let mut genesis_count = 0usize;
    let mut same_epoch = 0usize;
    let mut diff_epoch = 0usize;

    for cert in all.values() {
        if is_genesis(cert) {
            entries.push(CorpusEntry::Genesis { cert: cert.clone() });
            genesis_count += 1;
        } else if let Some(prev) = all.get(&cert.previous_hash) {
            if cert.epoch == prev.epoch {
                same_epoch += 1;
            } else {
                diff_epoch += 1;
            }
            entries.push(CorpusEntry::Standard {
                current: cert.clone(),
                previous: prev.clone(),
            });
        } else {
            orphans.push(cert.hash.clone());
        }
    }

    entries.sort_by(|a, b| a.hash().cmp(b.hash()));

    CorpusLoad {
        entries,
        load_errors,
        orphans,
        genesis_count,
        standard_same_epoch: same_epoch,
        standard_diff_epoch: diff_epoch,
    }
}
