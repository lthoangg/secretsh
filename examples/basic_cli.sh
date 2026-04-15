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

# ── 2. Store secrets (via import-env) ─────────────────────────────────────────
# Note: `secretsh set` is interactive (hidden input) and cannot be piped.
# For scripted usage, use import-env with a .env file.

echo "--- import-env ---"
ENV_FILE="$VAULT_DIR/secrets.env"
cat > "$ENV_FILE" <<'DOTENV'
DB_PASS=hunter2
DB_USER=admin
API_KEY=sk-live-abc123xyz
DOTENV
secretsh import-env -f "$ENV_FILE" --vault "$VAULT"
rm -f "$ENV_FILE"
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

echo "--- run (incidental secret in output is redacted) ---"
secretsh run --vault "$VAULT" --quiet -- \
    "echo 'the password is hunter2'"
# Output: the password is [REDACTED_DB_PASS]
# NOTE: redaction is substring matching — if your secret is a common string
# like "123456", every occurrence in child output will be redacted, including
# unrelated content (port numbers, counts, log lines). This is a known
# limitation with no fix in the current model.
echo

# ── 5. --no-shell (AI-agent hardening) ───────────────────────────────────────
# Blocks sh, bash, zsh, dash, fish, ksh, mksh, tcsh, csh as argv[0].
# Recommended whenever secretsh is invoked by an AI agent.

echo "--- --no-shell: non-shell binary allowed ---"
secretsh run --vault "$VAULT" --quiet --no-shell -- \
    "echo {{DB_USER}}"
# Output: [REDACTED_DB_USER]
echo

echo "--- --no-shell: shell interpreter blocked (exit 125) ---"
secretsh run --vault "$VAULT" --no-shell -- sh -c "echo hello" 2>&1 || true
# Output: secretsh error: spawn error: shell delegation blocked: "sh" ...
echo

# ── 6. Export & import ────────────────────────────────────────────────────────

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

# ── 7. Exit codes ─────────────────────────────────────────────────────────────

echo "--- exit codes ---"
secretsh run --vault "$VAULT" --quiet -- "true"
echo "true  -> exit $?"

secretsh run --vault "$VAULT" --quiet -- "false" || true
echo "false -> exit 1 (expected)"

secretsh run --vault "$VAULT" --quiet -- "nonexistent_cmd_xyz" 2>/dev/null || true
echo "not found -> exit 127 (expected)"
echo

echo "Done."
