#!/usr/bin/env bash
# examples/basic_cli.sh — Basic secretsh CLI walkthrough
#
# Prerequisites:
#   cargo build
#   (or install with: cargo install secretsh)
#
# Usage:
#   ./target/debug/secretsh --env .env run -- echo {{KEY}}
#   bash examples/basic_cli.sh  (uses ./target/debug/secretsh if found)

set -euo pipefail

# ── Find secretsh binary ────────────────────────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

if [ -x "$REPO_DIR/target/debug/secretsh" ]; then
    SECRETSH="$REPO_DIR/target/debug/secretsh"
elif command -v secretsh &>/dev/null; then
    SECRETSH="secretsh"
else
    echo "secretsh not found. Run: cargo build" >&2
    exit 1
fi

echo "Using: $SECRETSH"

# Use a temp directory for our .env file
TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

ENV_FILE="$TMPDIR/.env"

# ── 1. Create .env file ───────────────────────────────────────────────────────

echo "--- create .env file ---"
cat > "$ENV_FILE" <<'DOTENV'
DB_PASS=hunter2
DB_USER=admin
API_KEY=sk-live-abc123xyz
DOTENV
echo "Using env file: $ENV_FILE"
cat "$ENV_FILE"
echo

# ── 2. Run commands — secrets injected and redacted ───────────────────────────

echo "--- run (placeholder injection) ---"
"$SECRETSH" --env "$ENV_FILE" run --quiet -- \
    "echo {{DB_USER}}:{{DB_PASS}}"
# Output: [REDACTED_DB_USER]:[REDACTED_DB_PASS]
echo

echo "--- run (multiple secrets) ---"
# curl will fail because api.example.com doesn't exist — that's expected here
"$SECRETSH" --env "$ENV_FILE" run --quiet -- \
    "curl -u {{DB_USER}}:{{DB_PASS}} https://api.example.com" || true
echo

echo "--- run (incidental secret in output is redacted) ---"
"$SECRETSH" --env "$ENV_FILE" run --quiet -- \
    "echo 'the password is hunter2'"
# Output: the password is [REDACTED_DB_PASS]
# NOTE: redaction is substring matching — if your secret is a common string
# like "123456", every occurrence in child output will be redacted, including
# unrelated content. This is a known limitation.
echo

# ── 3. --no-shell (AI-agent hardening) ─────────────────────────────────────
# Blocks sh, bash, zsh, dash, fish, ksh, mksh, tcsh, csh as argv[0].
# Recommended whenever secretsh is invoked by an AI agent.

echo "--- --no-shell: non-shell binary allowed ---"
"$SECRETSH" --env "$ENV_FILE" run --quiet --no-shell -- \
    "echo {{DB_USER}}"
# Output: [REDACTED_DB_USER]
echo

echo "--- --no-shell: shell interpreter blocked (exit 125) ---"
"$SECRETSH" --env "$ENV_FILE" run --no-shell -- sh -c "echo hello" 2>&1 || true
# Output: secretsh error: spawn error: shell delegation blocked: "sh" ...
echo

# ── 4. Exit codes ─────────────────────────────────────────────────────────────

echo "--- exit codes ---"
"$SECRETSH" --env "$ENV_FILE" run --quiet -- "true"
echo "true  -> exit $?"

"$SECRETSH" --env "$ENV_FILE" run --quiet -- "false" || true
echo "false -> exit 1 (expected)"

"$SECRETSH" --env "$ENV_FILE" run --quiet -- "nonexistent_cmd_xyz" 2>/dev/null || true
echo "not found -> exit 127 (expected)"
echo

echo "Done."
