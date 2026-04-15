#!/usr/bin/env bash
# examples/basic_cli.sh — Basic secretsh CLI walkthrough
#
# Prerequisites:
#   cargo install secretsh   (or cargo build --release)
#
# Usage:
#   export SECRETSH_KEY="your-master-passphrase-here"
#   bash examples/basic_cli.sh

set -euo pipefail

# ── Check prerequisites ───────────────────────────────────────────────────────

if ! command -v secretsh &>/dev/null; then
    echo "secretsh not found. Install with: cargo install secretsh" >&2
    exit 1
fi

if [ -z "${SECRETSH_KEY:-}" ]; then
    echo "Set SECRETSH_KEY first: export SECRETSH_KEY=\"your-passphrase\"" >&2
    exit 1
fi

# Use a temp directory so we don't touch the default vault
VAULT_DIR=$(mktemp -d)
VAULT="$VAULT_DIR/vault.bin"
trap 'rm -rf "$VAULT_DIR"' EXIT

echo "Using vault: $VAULT"
echo

# ── 1. Initialize ─────────────────────────────────────────────────────────────

echo "--- init ---"
secretsh init --vault "$VAULT" --kdf-memory 65536
echo

# ── 2. Store secrets ──────────────────────────────────────────────────────────

echo "--- set ---"
printf 'hunter2'           | secretsh set DB_PASS  --vault "$VAULT"
printf 'admin'             | secretsh set DB_USER  --vault "$VAULT"
printf 'sk-live-abc123xyz' | secretsh set API_KEY  --vault "$VAULT"
echo "Stored 3 secrets."
echo

# ── 3. List keys ──────────────────────────────────────────────────────────────

echo "--- list ---"
secretsh list --vault "$VAULT"
echo

# ── 4. Run commands — secrets injected and redacted ───────────────────────────

echo "--- run (placeholder injection) ---"
secretsh run --vault "$VAULT" --quiet -- \
    "echo {{DB_USER}}:{{DB_PASS}}"
# Output: [REDACTED_DB_USER]:[REDACTED_DB_PASS]
echo

echo "--- run (incidental secret in output is caught) ---"
secretsh run --vault "$VAULT" --quiet -- \
    "echo 'the password is hunter2'"
# Output: the password is [REDACTED_DB_PASS]
echo

# ── 5. Export & import ────────────────────────────────────────────────────────

echo "--- export ---"
BACKUP="$VAULT_DIR/backup.vault.bin"
secretsh export --vault "$VAULT" --out "$BACKUP"
echo

echo "--- delete a key ---"
secretsh delete API_KEY --vault "$VAULT"
echo "Keys after delete:"
secretsh list --vault "$VAULT"
echo

echo "--- import (restores deleted key) ---"
secretsh import --vault "$VAULT" --in "$BACKUP"
echo "Keys after import:"
secretsh list --vault "$VAULT"
echo

# ── 6. Exit codes ─────────────────────────────────────────────────────────────

echo "--- exit codes ---"
secretsh run --vault "$VAULT" --quiet -- "true"
echo "true  -> exit $?"

secretsh run --vault "$VAULT" --quiet -- "false" || true
echo "false -> exit 1 (expected)"

secretsh run --vault "$VAULT" --quiet -- "nonexistent_cmd_xyz" 2>/dev/null || true
echo "not found -> exit 127 (expected)"
echo

echo "Done."
