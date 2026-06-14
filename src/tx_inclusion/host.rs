//! Host-side proof transcoder: upstream Mithril proof bytes -> dwarf's custom
//! guest wire. The tx-inclusion analog of `parser::certificate_to_bytes`, so a
//! host depends only on mithril-dwarf: it fetches via the
//! re-exported `Client`, transcodes here, and the guest only ever sees the
//! custom wire. The serde mirror decodes the upstream proof's exact shape (its
//! `MKProof` fields are private upstream) and never enters the guest graph.

use mithril_common::crypto_helper::MKTreeNode as UpNode;
use mithril_common::entities::BlockRange as UpBlockRange;
use serde::Deserialize;

use super::node::MKTreeNode;
use super::proof::{BlockRange, MKMapProof, MKProof, TxError};
use super::wire::encode_proof;

#[derive(Deserialize)]
struct ProofMirror {
    inner_root: UpNode,
    inner_leaves: Vec<(u64, UpNode)>,
    inner_proof_size: u64,
    inner_proof_items: Vec<UpNode>,
}

#[derive(Deserialize)]
struct MapProofMirror {
    master_proof: ProofMirror,
    sub_proofs: Vec<(UpBlockRange, MapProofMirror)>,
}

fn node(up: &UpNode) -> MKTreeNode {
    MKTreeNode::new(up.to_vec())
}

fn proof(m: &ProofMirror) -> MKProof {
    MKProof {
        inner_root: node(&m.inner_root),
        inner_leaves: m.inner_leaves.iter().map(|(p, n)| (*p, node(n))).collect(),
        inner_proof_size: m.inner_proof_size,
        inner_proof_items: m.inner_proof_items.iter().map(node).collect(),
    }
}

fn map_proof(m: &MapProofMirror) -> MKMapProof {
    MKMapProof {
        master_proof: proof(&m.master_proof),
        sub_proofs: m
            .sub_proofs
            .iter()
            .map(|(r, sub)| {
                (
                    BlockRange {
                        start: *r.start,
                        end: *r.end,
                    },
                    map_proof(sub),
                )
            })
            .collect(),
    }
}

/// Transcode a **v1** (`CardanoTransactions`) proof — the aggregator's json form
/// (`hex`-decoded from `MkSetProofMessagePart.proof`) — into the guest wire.
pub fn tx_proof_to_wire_v1(json: &[u8]) -> Result<Vec<u8>, TxError> {
    let mirror: MapProofMirror = serde_json::from_slice(json).map_err(|_| TxError::InvalidProof)?;
    Ok(encode_proof(&map_proof(&mirror)))
}

/// Transcode a **v2** (`CardanoBlocksTransactions`) proof — the aggregator's
/// bincode form (`hex`-decoded, `MKMapProof::to_bytes`) — into the guest wire.
pub fn tx_proof_to_wire_v2(bincode: &[u8]) -> Result<Vec<u8>, TxError> {
    let (mirror, _): (MapProofMirror, _) =
        bincode2::serde::decode_from_slice(bincode, bincode2::config::standard())
            .map_err(|_| TxError::InvalidProof)?;
    Ok(encode_proof(&map_proof(&mirror)))
}
