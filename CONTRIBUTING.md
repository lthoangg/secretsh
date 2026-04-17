# Contributing to secretsh

Thank you for considering contributing to secretsh. This document covers the development workflow, code standards, and how to submit changes.

## Development Setup

```bash
# Clone
git clone https://github.com/lthoangg/secretsh.git
cd secretsh

# Build
cargo build

# Run tests
cargo test

# Lint (must pass with zero warnings)
cargo clippy -- -D warnings

# Format
cargo fmt
```

### Python Tests

```bash
cd python
pip install -e ".[dev]"
pytest tests/ -v
```

The Python package is a pure-Python CLI wrapper — no compilation step needed. The tests require the `secretsh` binary to be available (built via `cargo build` in the repo root, or installed system-wide).

## Code Standards

### Rust

- **Edition:** 2021
- **MSRV:** 1.75
- **Formatting:** `cargo fmt` (default `rustfmt` settings with the project's `rustfmt.toml`)
- **Linting:** `cargo clippy -- -D warnings` must pass with zero warnings
- **Tests:** All existing tests must pass. New functionality requires tests.

### Security-Sensitive Code

This is a security tool. Extra care is required:

- **All secret data** must be wrapped in `zeroize::Zeroizing<Vec<u8>>`. Never use `String` for secret values.
- **No `println!` or `dbg!`** with secret data. Use `[REDACTED]` in debug output.
- **Unsafe code** requires a `// SAFETY:` comment explaining why it is sound.
- **New syscalls** require documentation of failure modes and graceful degradation behavior.
- **Tokenizer changes** are high-risk. Any modification to `tokenizer.rs` must include corresponding test cases and should be fuzz-tested.

### Commit Messages

Write concise commit messages that explain **why**, not just what:

```
fix: reject bare $ before { in tokenizer

Previously, `${ VAR}` was not caught as variable expansion because
the space between `{` and `V` broke the pattern match. The tokenizer
now rejects `${` regardless of what follows.
```

Use conventional commit prefixes: `fix:`, `feat:`, `refactor:`, `test:`, `docs:`, `ci:`, `chore:`.

## Submitting Changes

1. **Fork** the repository.
2. **Create a branch** from `main`: `git checkout -b fix/tokenizer-dollar-brace`.
3. **Make your changes** with tests.
4. **Run the full check suite:**
   ```bash
   cargo fmt --check
   cargo clippy -- -D warnings
   cargo test
   ```
5. **Open a Pull Request** against `main`.

### PR Checklist

- [ ] `cargo fmt --check` passes
- [ ] `cargo clippy -- -D warnings` passes
- [ ] `cargo test` passes (all existing + new tests)
- [ ] `pytest python/tests/` passes (if Python package is affected)
- [ ] New public APIs have doc comments
- [ ] Security-sensitive changes have corresponding test coverage
- [ ] Commit messages follow the conventional format

## Reporting Bugs

Open a [GitHub Issue](https://github.com/lthoangg/secretsh/issues) with:

- secretsh version (`secretsh --version`)
- OS and architecture
- Steps to reproduce
- Expected vs actual behavior

For security vulnerabilities, see [SECURITY.md](SECURITY.md) instead.

## License

By contributing, you agree that your contributions will be licensed under the [MIT License](LICENSE).
