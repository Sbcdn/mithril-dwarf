#!/usr/bin/env bash
# Local drift check — rebuild the harness against the LATEST upstream
# Mithril (Sbcdn/mithril.git#main) instead of the pinned rev, and run
# the equivalence harness. Any failure indicates drift.
#
# This is the local-developer equivalent of the
# `.github/workflows/upstream-drift-check.yml` weekly CI job. Use it
# before bumping the pinned rev or when investigating a CI drift alert.
#
# The script modifies the workspace Cargo.toml in place, runs the
# harness, then restores Cargo.toml — even on failure or interrupt.
#
# Usage:
#   scripts/check-upstream-drift.sh

set -euo pipefail

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
REPO_ROOT="$( cd "$SCRIPT_DIR/.." && pwd )"
cd "$REPO_ROOT"

CARGO_TOML="$REPO_ROOT/Cargo.toml"
BACKUP="$REPO_ROOT/Cargo.toml.drift-backup"

# Always restore Cargo.toml, even on Ctrl-C / failure.
restore_cargo_toml() {
    if [ -f "$BACKUP" ]; then
        mv -f "$BACKUP" "$CARGO_TOML"
        echo "[drift-check] Restored Cargo.toml from backup."
    fi
}
trap restore_cargo_toml EXIT INT TERM

echo "[drift-check] Backing up Cargo.toml..."
cp -f "$CARGO_TOML" "$BACKUP"

echo "[drift-check] Patching Cargo.toml to override pinned rev with upstream main..."
cat >> "$CARGO_TOML" <<'EOF'

# === DRIFT CHECK (temporary — automatic restore on exit) ===
[patch."https://github.com/Sbcdn/mithril.git"]
mithril-common = { git = "https://github.com/Sbcdn/mithril.git", branch = "main" }
mithril-client = { git = "https://github.com/Sbcdn/mithril.git", branch = "main" }
mithril-stm = { git = "https://github.com/Sbcdn/mithril.git", branch = "main" }
EOF

echo "[drift-check] Updating Cargo.lock to fetch upstream main..."
cargo update -p mithril-common -p mithril-client -p mithril-stm 2>&1 | tail -20 || true

echo "[drift-check] Building harness against upstream main..."
if ! cargo build -p mithril-dwarf-harness --release --tests 2>&1; then
    echo
    echo "BUILD FAILURE: upstream main has breaking type changes vs pinned rev."
    echo "   Read the build errors above to identify the affected types."
    exit 1
fi

echo "[drift-check] Running equivalence harness against upstream main..."
if cargo test -p mithril-dwarf-harness --release 2>&1; then
    echo
    echo "No drift: upstream main is bit-equivalent to pinned rev."
    exit 0
else
    echo
    echo "DRIFT DETECTED: upstream behaviour differs from pinned rev."
    echo "   Pinned: 36fd7f8818f0ff14b10336fa7f855d52698e40a8"
    echo
    echo "   Investigation path:"
    echo "   1. Compare upstream commits:"
    echo "      git log --oneline 36fd7f88..main -- mithril-common mithril-stm mithril-client"
    echo "   2. Identify the failure class:"
    echo "      a. divergence-registry entry needs update"
    echo "      b. dwarf code needs to track upstream change"
    echo "      c. new pin test needed for new variant/discriminant"
    echo "   3. Bump pinned rev in both Cargo.toml files once resolved."
    exit 1
fi
