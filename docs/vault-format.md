# Vault Format

The vault stores secrets in a versioned binary format with authenticated encryption. Every write produces a completely fresh key derivation, making nonce reuse impossible.

## Binary Layout

```
[magic: 8 bytes "SECRETSH"]
[version: 1 byte]            — always 1
[cipher_id: 1 byte]          — 0x01 = AES-256-GCM suite
[kdf_params: 12 bytes]       — m_cost:4 (u32 LE), t_cost:4 (u32 LE), p_cost:4 (u32 LE)
[kdf_salt: 16 bytes]
[entry_count: 4 bytes]       — u32 LE
[reserved: 32 bytes]         — zeroed, included in HMAC
[header_hmac: 32 bytes]      — HMAC-SHA256 over all preceding bytes

per entry:
  [nonce: 12 bytes]
  [ciphertext_len: 4 bytes]  — u32 LE
  [ciphertext + GCM tag: M bytes]
    — plaintext: [key_name_len: 2 bytes u16 LE] [key_name: N bytes] [value: remaining bytes]
    — GCM AAD: [entry_index: 4 bytes big-endian]

[commit_tag: 32 bytes]       — HMAC-SHA256 over entire file preceding this tag
```

### Header: 106 bytes

| Offset | Length | Field | Description |
|--------|--------|-------|-------------|
| 0 | 8 | magic | `SECRETSH` — identifies the file type |
| 8 | 1 | version | Format version (currently `1`) |
| 9 | 1 | cipher_id | Cipher suite identifier (`0x01`) |
| 10 | 4 | m_cost | Argon2id memory cost in KiB (u32 LE) |
| 14 | 4 | t_cost | Argon2id time cost / iterations (u32 LE) |
| 18 | 4 | p_cost | Argon2id parallelism / lanes (u32 LE) |
| 22 | 16 | kdf_salt | Random salt for Argon2id (from OS CSPRNG) |
| 38 | 4 | entry_count | Number of encrypted entries (u32 LE) |
| 42 | 32 | reserved | Zeroed; available for future non-breaking extensions |
| 74 | 32 | header_hmac | HMAC-SHA256 over bytes 0–73 |

### Entries

Each entry is independently encrypted with AES-256-GCM. The plaintext contains both the key name and value — **key names are never stored in plaintext**.

The GCM authenticated associated data (AAD) is the entry's ordinal index as a 4-byte big-endian integer. This cryptographically binds each entry to its position — swapping two entries' ciphertexts causes GCM authentication to fail.

### Commit Tag

The final 32 bytes are HMAC-SHA256 over the entire file preceding the tag. This detects structural attacks that per-entry GCM cannot catch: appending entries from a previous vault version (replay), truncating entries after the declared count, or reordering entries.

## Cipher Suite

| Version | cipher_id | Encryption | MAC | KDF | Key Expansion |
|---------|-----------|------------|-----|-----|---------------|
| 1 | `0x01` | AES-256-GCM (`ring`) | HMAC-SHA256 (`ring`) | Argon2id (`argon2`) | HKDF-SHA256 (`ring::hkdf`) |

Each version implies a complete, immutable set of algorithms. There is no mix-and-match.

## Key Derivation

```
passphrase + salt
       │
       ▼
   Argon2id(m=128MiB, t=3, p=4)  →  32-byte IKM
       │
       ├── HKDF-SHA256(IKM, info="secretsh-enc-v1")  →  32-byte encryption key
       │
       └── HKDF-SHA256(IKM, info="secretsh-mac-v1")  →  32-byte HMAC key
```

The Argon2id output is **never used directly** as a key. HKDF domain separation ensures a vulnerability in one primitive cannot leak key material usable by the other.

### Default KDF Parameters

| Parameter | Default | Override |
|-----------|---------|---------|
| Memory cost | 128 MiB (`m=131072`) | `--kdf-memory <kibibytes>` on `init` |
| Time cost | 3 iterations | Stored in header |
| Parallelism | 4 lanes | Stored in header |
| Salt | 16 random bytes | Fresh per write |

These target approximately 0.5–1 second derivation time on modern hardware. The minimum allowed memory cost is 64 MiB (`65536` KiB).

## Nonce Management

Every vault write operation (`set`, `delete`, `import`) re-encrypts the entire vault:

1. Generate a fresh 16-byte KDF salt
2. Run Argon2id → HKDF → fresh encryption + HMAC subkeys
3. Re-encrypt every entry with a fresh random 12-byte nonce
4. Recompute header_hmac and commit_tag
5. Write to temp file, atomic rename

Since every write derives fresh keys from a fresh salt, nonce collisions under the same key are impossible. The 10,000-entry limit keeps write latency under 100ms.

## Verification Order (on open)

1. **Header HMAC** — validates entry_count and KDF params before using them
2. **Per-entry GCM decrypt** — verifies each entry's authentication tag and AAD
3. **Commit tag** — validates the entire file structure

If any check fails, the vault is rejected with a typed error.

## Concurrent Access

| Operation | Lock type |
|-----------|-----------|
| Read (`run`, `list`) | Shared `flock()` |
| Write (`set`, `delete`, `import`) | Exclusive `flock()` |

### Write Atomicity

1. Acquire exclusive `flock()` on `<vault_path>.lock` (30s timeout)
2. Write new vault to `<vault_path>.tmp.<pid>` (`O_EXCL` + mode `0600`)
3. Atomic `rename()` over the original vault
4. Release lock

If secretsh crashes between steps 2 and 3, the original vault is untouched. Per-PID temp files prevent corruption from races past the advisory lock.

### Stale Lock Detection

A lock is stale if: the PID in the lockfile is not running (`kill(pid, 0)` → `ESRCH`) **or** the lockfile is older than 5 minutes. Stale locks are removed with a warning and the operation retries.

## File Permissions

| File | Mode | Enforced |
|------|------|---------|
| Vault | `0600` | Checked on open; hard error if group/world-readable |
| Parent directory | `0700` | Set on `init` if directory is newly created |
| Lockfile | `0600` | Created with restricted mode |
| Temp file | `0600` | `O_EXCL` prevents overwrite |

Use `--allow-insecure-permissions` to override the permission check.

## Limits

| Limit | Value | Rationale |
|-------|-------|-----------|
| Max entries | 10,000 | Keeps re-encryption under 100ms |
| Min passphrase | 12 characters | Enforced on `init` only; `--no-passphrase-check` to override |
| Max value size | 1 MiB | Hard error on `set` |

## Format Versioning

- secretsh always **writes** the latest format version
- secretsh **reads** versions 1 through current; newer → hard error with upgrade message
- Opening an older version for write auto-migrates to latest format
- The 32-byte reserved field allows non-breaking extensions without a version bump
