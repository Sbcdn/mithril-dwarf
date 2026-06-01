#!/usr/bin/env bash
# Fetch a SignedEntityType-diverse mainnet corpus for the equivalence harness.
#
# The corpus directory is .gitignored (each developer fetches their own slice),
# but the equivalence harness benefits from coverage of all 5 SignedEntityType
# variants. This script fetches one chain per variant from the mainnet
# aggregator, walking back a small number of certs per chain to keep the
# corpus size manageable.
#
# Re-run any time the corpus needs to be regenerated. Existing certs are
# preserved; the fetcher only writes new files.
#
# Variants covered:
#   * MithrilStakeDistribution (dominant — most certs are this type)
#   * CardanoTransactions
#   * CardanoDatabase
#   * CardanoImmutableFilesFull
#   * CardanoStakeDistribution
#
# After running, verify with:
#   cargo test -p mithril-dwarf-harness --test equivalence --release \
#       corpus_diversity_report -- --nocapture

set -euo pipefail

# Resolve repo root no matter where the script is invoked from.
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
REPO_ROOT="$( cd "$SCRIPT_DIR/../../.." && pwd )"
cd "$REPO_ROOT"

AGGREGATOR="https://aggregator.release-mainnet.api.mithril.network/aggregator"
FETCH="cargo run --release --bin fetch_certificates -p mithril-dwarf-harness --"

echo "Discovering recent cert hashes per SignedEntityType variant..."

# Recent CardanoTransactions / CardanoDatabase / CardanoImmutableFilesFull
# usually visible in the /certificates list endpoint.
HASHES_CERTS=$(curl -s --max-time 30 "$AGGREGATOR/certificates")

# CardanoStakeDistribution lives in a separate artifact endpoint.
HASHES_CSD=$(curl -s --max-time 30 "$AGGREGATOR/artifact/cardano-stake-distributions")

pick_first_of_type() {
    local payload="$1"
    local type_name="$2"
    echo "$payload" | python3 -c "
import json, sys
data = json.load(sys.stdin)
for c in data:
    et = c.get('signed_entity_type', {})
    key = list(et.keys())[0] if isinstance(et, dict) and et else None
    if key == '$type_name':
        print(c['hash'])
        break
"
}

pick_first_csd() {
    echo "$1" | python3 -c "
import json, sys
data = json.load(sys.stdin)
if data:
    print(data[0].get('certificate_hash', ''))
"
}

H_CT=$(pick_first_of_type "$HASHES_CERTS" "CardanoTransactions")
H_CD=$(pick_first_of_type "$HASHES_CERTS" "CardanoDatabase")
H_CIF=$(pick_first_of_type "$HASHES_CERTS" "CardanoImmutableFilesFull")
H_CSD=$(pick_first_csd "$HASHES_CSD")

echo "Starting hashes:"
echo "  CardanoTransactions:       ${H_CT:-<not found>}"
echo "  CardanoDatabase:           ${H_CD:-<not found>}"
echo "  CardanoImmutableFilesFull: ${H_CIF:-<not found>}"
echo "  CardanoStakeDistribution:  ${H_CSD:-<not found>}"

# Per-variant depth: fetch 3-5 certs per variant so we have multiple
# samples for each. Single-sample coverage was the corner-cutting flagged
# by Part 2 Step 2a audit; expanding to ≥4 each gives real variant-axis
# robustness.

# CardanoDatabase: walk back from the head + fetch a few siblings.
if [ -n "${H_CD:-}" ]; then
    echo
    echo "[1/4] CardanoDatabase chain head (40 certs back)"
    $FETCH --network mainnet --certificate-hash "$H_CD" --max-certificates 40 || true
    echo "  Sibling CardanoDatabase certs (3 more from artifact endpoint):"
    SIBLINGS=$(curl -s --max-time 30 "$AGGREGATOR/artifact/cardano-database" \
        | python3 -c "import json,sys; d=json.load(sys.stdin); print(' '.join(x['certificate_hash'] for x in d[1:4]))")
    for SIB in $SIBLINGS; do
        $FETCH --network mainnet --certificate-hash "$SIB" --max-certificates 1 2>&1 | grep -E "Saved|Error" | head -1
    done
fi

# CardanoImmutableFilesFull: 4 sibling certs for variant-axis depth.
if [ -n "${H_CIF:-}" ]; then
    echo
    echo "[2/4] CardanoImmutableFilesFull (head + 3 siblings)"
    $FETCH --network mainnet --certificate-hash "$H_CIF" --max-certificates 3 || true
    SIBLINGS=$(curl -s --max-time 30 "$AGGREGATOR/artifact/snapshots" \
        | python3 -c "import json,sys; d=json.load(sys.stdin); print(' '.join(x['certificate_hash'] for x in d[1:4]))")
    for SIB in $SIBLINGS; do
        $FETCH --network mainnet --certificate-hash "$SIB" --max-certificates 1 2>&1 | grep -E "Saved|Error" | head -1
    done
fi

# CardanoTransactions: head + 3 siblings from the cardano-transactions
# artifact endpoint. Earlier versions relied on the /certificates feed
# being CT-rich and the main chain walk pulling more, but a chain walk
# isn't variant-pure — siblings from the artifact endpoint guarantee
# we land ≥4 CT-tagged certs and lock the per-variant floor at 4.
if [ -n "${H_CT:-}" ]; then
    echo
    echo "[3/4] CardanoTransactions (head + 3 siblings)"
    $FETCH --network mainnet --certificate-hash "$H_CT" --max-certificates 3 || true
    SIBLINGS=$(curl -s --max-time 30 "$AGGREGATOR/artifact/cardano-transactions" \
        | python3 -c "import json,sys; d=json.load(sys.stdin); print(' '.join(x['certificate_hash'] for x in d[1:4]))")
    for SIB in $SIBLINGS; do
        $FETCH --network mainnet --certificate-hash "$SIB" --max-certificates 1 2>&1 | grep -E "Saved|Error" | head -1
    done
fi

# CardanoStakeDistribution: 4 sibling certs from artifact endpoint.
if [ -n "${H_CSD:-}" ]; then
    echo
    echo "[4/4] CardanoStakeDistribution (head + 3 siblings)"
    $FETCH --network mainnet --certificate-hash "$H_CSD" --max-certificates 3 || true
    SIBLINGS=$(curl -s --max-time 30 "$AGGREGATOR/artifact/cardano-stake-distributions" \
        | python3 -c "import json,sys; d=json.load(sys.stdin); print(' '.join(x['certificate_hash'] for x in d[1:4]))")
    for SIB in $SIBLINGS; do
        $FETCH --network mainnet --certificate-hash "$SIB" --max-certificates 1 2>&1 | grep -E "Saved|Error" | head -1
    done
fi

# Network diversity: add a short preprod chain so the harness exercises
# the per-network genesis VK plumbing. Preprod and preview share the
# same genesis VK (PREPROD_GENESIS_VK_HEX in corpus.rs); the harness
# auto-selects the right key via `genesis_vk_for_cert(cert)`.
echo
echo "[5/5] Preprod chain (5 certs)"
PREPROD_AGG="https://aggregator.release-preprod.api.mithril.network/aggregator"
H_PREPROD=$(curl -s --max-time 30 "$PREPROD_AGG/certificates" \
    | python3 -c "import json,sys; d=json.load(sys.stdin); print(d[0]['hash'] if d else '')")
if [ -n "$H_PREPROD" ]; then
    $FETCH --network preprod --certificate-hash "$H_PREPROD" --max-certificates 5 || true
fi

echo
echo "Done. Run the diversity report to confirm:"
echo "  cargo test -p mithril-dwarf-harness --test equivalence --release \\"
echo "      corpus_diversity_report -- --nocapture"
