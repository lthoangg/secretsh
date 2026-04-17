# AGENTS.md

## What this is

secretsh is a single-crate Rust binary + library that injects secrets from a `.env` file into subprocess argv and redacts them from output. It targets macOS and Linux.

## Documentation

| Document | Content |
|----------|---------|
| [docs/architecture.md](docs/architecture.md) | Execution pipeline, module map, platform spawning, memory hardening, signal handling, redaction |
| [docs/tokenizer.md](docs/tokenizer.md) | Quoting rules, metacharacter rejection, placeholder syntax, error cases |
| [docs/cli.md](docs/cli.md) | Full CLI reference, flags, exit codes |
| [docs/threat-model.md](docs/threat-model.md) | Security model, oracle attacks, known limitations |
| [docs/python-api.md](docs/python-api.md) | Python package API (`secretsh.run()`) |
| [examples/](examples/) | Runnable examples |

## Build & verify

```bash
cargo build                          # dev build
cargo test                           # all unit tests (~1s)
cargo clippy -- -D warnings          # must be zero warnings (CI enforces -D)
cargo fmt --check                    # rustfmt.toml: max_width=100
cargo build --release                # LTO + strip
```

CI runs: `check` → `fmt` → `clippy` → `test`. All must pass on PR.

## Critical conventions

- **All secret bytes must be `Zeroizing<Vec<u8>>`**. Never use `String` or plain `Vec<u8>` for secret material.
- **Argv elements passed to `spawn_child` must be null-terminated `Zeroizing<Vec<u8>>`**. The spawn module does not add terminators.
- **`spawn.rs` is macOS-specific** — it uses `posix_spawnp` only.

## Tokenizer changes are high risk

The tokenizer is the security boundary between agent-generated input and process execution. Any change to `tokenizer.rs` must:
1. Include tests for the specific edge case
2. Verify all metacharacter rejection tests still pass
3. Be fuzz-tested before merge

## E2E smoke test

```bash
echo 'MY_SECRET=hunter2' > /tmp/test.env
./target/release/secretsh --env /tmp/test.env run --quiet -- echo {{MY_SECRET}}
# Output: [REDACTED_MY_SECRET]

# --no-shell smoke test (AI-agent hardening)
./target/release/secretsh --env /tmp/test.env run --quiet --no-shell -- echo {{MY_SECRET}}
# Output: [REDACTED_MY_SECRET]
./target/release/secretsh --env /tmp/test.env run --no-shell -- sh -c "echo {{MY_SECRET}}" 2>&1
# Output: secretsh error: spawn error: shell delegation blocked: "sh" ...
```

## Security conventions

- **`--no-shell` is recommended for all AI-agent contexts.** It blocks known shell interpreters by argv[0] basename, preventing shell conditional oracle attacks.
- **Output redaction is substring matching** — false positives occur when a secret value (e.g. `123456`) appears in unrelated output. This is a known design limitation with no fix within the current model.
- See [docs/threat-model.md](docs/threat-model.md) for a full breakdown of what is and is not protected.

## Releasing a new version

Update the version in **all files** before tagging:

| File | Field |
|------|-------|
| `Cargo.toml` | `version = "X.Y.Z"` |
| `pyproject.toml` | `version = "X.Y.Z"` |
| `CHANGELOG.md` | Add `## [X.Y.Z] - YYYY-MM-DD` section with comparison link |

After updating, regenerate `Cargo.lock`:

```bash
cargo generate-lockfile
```

Commit files, merge to main, then tag and release:

```bash
git tag vX.Y.Z
git push origin vX.Y.Z
gh release create vX.Y.Z --title "vX.Y.Z" --generate-notes
```

This triggers: `release-binaries` → `publish-crates`.
