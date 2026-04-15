//! Vault module for secretsh — AES-256-GCM encrypted secret storage.
//!
//! # Binary Layout
//!
//! ```text
//! [magic: 8 bytes "SECRETSH"]
//! [version: 1 byte]            — always 1
//! [cipher_id: 1 byte]          — always 0x01
//! [kdf_params: 12 bytes]       — m_cost:4 (u32 LE), t_cost:4 (u32 LE), p_cost:4 (u32 LE)
//! [kdf_salt: 16 bytes]
//! [entry_count: 4 bytes]       — u32 LE
//! [reserved: 32 bytes]         — zeroed
//! [header_hmac: 32 bytes]      — HMAC-SHA256 over all preceding bytes
//!
//! per entry:
//!   [nonce: 12 bytes]
//!   [ciphertext_len: 4 bytes]  — u32 LE
//!   [ciphertext + GCM tag: M bytes]
//!     — plaintext: [key_name_len: 2 bytes u16 LE] [key_name: N bytes] [value: remaining bytes]
//!     — GCM AAD: [entry_index: 4 bytes big-endian]
//!
//! [commit_tag: 32 bytes]       — HMAC-SHA256 over entire file preceding this tag
//! ```

use std::fs::{self, File, OpenOptions};
use std::io::Read as IoRead;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use argon2::{Algorithm, Argon2, Params, Version};
use ring::aead::{
    Aad, BoundKey, Nonce, NonceSequence, OpeningKey, SealingKey, UnboundKey, AES_256_GCM, NONCE_LEN,
};
use ring::hmac;
use ring::rand::{SecureRandom, SystemRandom};
use zeroize::{Zeroize, Zeroizing};

use crate::error::*;
use crate::harden::{madvise_free, mlock_region, munlock_region};

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

const MAGIC: &[u8; 8] = b"SECRETSH";
const VERSION: u8 = 1;
const CIPHER_ID: u8 = 0x01;

/// Offset breakdown for the fixed-size header (before header_hmac):
///   8  magic
///   1  version
///   1  cipher_id
///  12  kdf_params (m_cost u32 LE + t_cost u32 LE + p_cost u32 LE)
///  16  kdf_salt
///   4  entry_count
///  32  reserved
/// ─────
///  74  bytes covered by header_hmac
const HEADER_COVERED_LEN: usize = 8 + 1 + 1 + 12 + 16 + 4 + 32;
const HEADER_TOTAL_LEN: usize = HEADER_COVERED_LEN + 32; // + header_hmac

const KDF_SALT_LEN: usize = 16;
const HMAC_LEN: usize = 32;
const GCM_TAG_LEN: usize = 16;
const GCM_NONCE_LEN: usize = NONCE_LEN; // 12

const MAX_ENTRIES: usize = 10_000;
const MIN_PASSPHRASE_LEN: usize = 12;

/// Default Argon2id parameters (128 MiB, 3 iterations, 4 lanes).
const DEFAULT_M_COST: u32 = 131_072; // 128 MiB in KiB
const DEFAULT_T_COST: u32 = 3;
const DEFAULT_P_COST: u32 = 4;

const HKDF_ENC_INFO: &[u8] = b"secretsh-enc-v1";
const HKDF_MAC_INFO: &[u8] = b"secretsh-mac-v1";

const LOCK_TIMEOUT_SECS: u64 = 30;
const STALE_LOCK_AGE_SECS: u64 = 300; // 5 minutes

#[cfg(unix)]
const O_CLOEXEC: libc::c_int = libc::O_CLOEXEC;

// ─────────────────────────────────────────────────────────────────────────────
// Key-name validation
// ─────────────────────────────────────────────────────────────────────────────

/// Validates that a key name matches `[A-Za-z_][A-Za-z0-9_]*`.
fn validate_key_name(name: &str) -> Result<(), SecretshError> {
    if name.is_empty() {
        return Err(SecretshError::Vault(VaultError::NotFound {
            path: PathBuf::from(name),
        }));
    }
    let mut chars = name.chars();
    let first = chars.next().unwrap();
    if !first.is_ascii_alphabetic() && first != '_' {
        return Err(SecretshError::Tokenization(
            TokenizationError::RejectedMetacharacter {
                character: first,
                offset: 0,
            },
        ));
    }
    for (i, c) in chars.enumerate() {
        if !c.is_ascii_alphanumeric() && c != '_' {
            return Err(SecretshError::Tokenization(
                TokenizationError::RejectedMetacharacter {
                    character: c,
                    offset: i + 1,
                },
            ));
        }
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// One-shot nonce wrapper (ring requires NonceSequence)
// ─────────────────────────────────────────────────────────────────────────────

struct OneShotNonce(Option<[u8; GCM_NONCE_LEN]>);

impl NonceSequence for OneShotNonce {
    fn advance(&mut self) -> Result<Nonce, ring::error::Unspecified> {
        self.0
            .take()
            .map(Nonce::assume_unique_for_key)
            .ok_or(ring::error::Unspecified)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Derived key material
// ─────────────────────────────────────────────────────────────────────────────

struct DerivedKeys {
    enc_key: Zeroizing<Vec<u8>>,
    mac_key: Zeroizing<Vec<u8>>,
}

impl Drop for DerivedKeys {
    fn drop(&mut self) {
        self.enc_key.zeroize();
        self.mac_key.zeroize();
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// KDF parameters stored in the vault header
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug)]
struct KdfParams {
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
}

impl Default for KdfParams {
    fn default() -> Self {
        Self {
            m_cost: DEFAULT_M_COST,
            t_cost: DEFAULT_T_COST,
            p_cost: DEFAULT_P_COST,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// In-memory decrypted entry
// ─────────────────────────────────────────────────────────────────────────────

struct Entry {
    key: String,
    value: Zeroizing<Vec<u8>>,
}

impl Drop for Entry {
    fn drop(&mut self) {
        self.value.zeroize();
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Public configuration
// ─────────────────────────────────────────────────────────────────────────────

/// Configuration for vault operations.
pub struct VaultConfig {
    /// Path to the vault file.
    pub vault_path: PathBuf,
    /// Name of the environment variable that holds the master passphrase.
    pub master_key_env: String,
    /// If `true`, skip the group/world-readable permission check on open.
    pub allow_insecure_permissions: bool,
    /// Argon2id memory cost in KiB (only used during `init`).
    /// Defaults to 131072 (128 MiB) when `None`.
    pub kdf_memory: Option<u32>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Vault
// ─────────────────────────────────────────────────────────────────────────────

/// An open, decrypted vault.
pub struct Vault {
    vault_path: PathBuf,
    master_key_env: String,
    // Stored for future use by callers that re-open the vault after mutation.
    #[allow(dead_code)]
    allow_insecure_permissions: bool,
    kdf_params: KdfParams,
    entries: Vec<Entry>,
    /// mlocked regions: (address as usize, length) for each entry value that was mlocked.
    /// These are tracked so `close()` can `munlock` them before zeroization.
    /// We store the address as `usize` instead of `*const u8` so that `Vault`
    /// remains `Send` (raw pointers are not `Send`).
    locked_regions: Vec<(usize, usize)>,
}

/// Manual `Debug` implementation that never exposes secret data.
impl std::fmt::Debug for Vault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Vault")
            .field("vault_path", &self.vault_path)
            .field("entry_count", &self.entries.len())
            .finish_non_exhaustive()
    }
}

impl Drop for Vault {
    fn drop(&mut self) {
        self.close();
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Key derivation helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Read the passphrase from the named environment variable.
fn read_passphrase(env_var: &str) -> Result<Zeroizing<Vec<u8>>, SecretshError> {
    let val = std::env::var(env_var).map_err(|_| {
        SecretshError::MasterKey(MasterKeyError::EnvVarNotSet {
            env_var: env_var.to_owned(),
        })
    })?;
    Ok(Zeroizing::new(val.into_bytes()))
}

/// Derive 32-byte IKM via Argon2id, then expand into enc + mac subkeys via HKDF-SHA256.
fn derive_keys(
    passphrase: &[u8],
    salt: &[u8; KDF_SALT_LEN],
    params: &KdfParams,
) -> Result<DerivedKeys, SecretshError> {
    // ── Argon2id ──────────────────────────────────────────────────────────────
    let argon2_params = Params::new(params.m_cost, params.t_cost, params.p_cost, Some(32))
        .map_err(|e| {
            SecretshError::Io(IoError(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("argon2 params error: {e}"),
            )))
        })?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon2_params);
    let mut ikm = Zeroizing::new(vec![0u8; 32]);
    argon2
        .hash_password_into(passphrase, salt, ikm.as_mut_slice())
        .map_err(|e| {
            SecretshError::Io(IoError(std::io::Error::other(format!(
                "argon2 hash error: {e}"
            ))))
        })?;

    // ── HKDF-SHA256 ───────────────────────────────────────────────────────────
    // ring's HKDF API: Salt → PRK → expand with info.
    // We use the IKM as the "key material" and an empty salt (ring uses
    // HKDF-Extract with a zero-length salt when none is provided, which is
    // valid per RFC 5869 §2.2).
    let salt_hkdf = ring::hkdf::Salt::new(ring::hkdf::HKDF_SHA256, &[]);
    let prk = salt_hkdf.extract(ikm.as_slice());

    let mut enc_key = Zeroizing::new(vec![0u8; 32]);
    let mut mac_key = Zeroizing::new(vec![0u8; 32]);

    // Expand encryption key
    prk.expand(&[HKDF_ENC_INFO], MyLen(32))
        .and_then(|okm| okm.fill(enc_key.as_mut_slice()))
        .map_err(|_| {
            SecretshError::Io(IoError(std::io::Error::other("HKDF expand (enc) failed")))
        })?;

    // Expand MAC key
    prk.expand(&[HKDF_MAC_INFO], MyLen(32))
        .and_then(|okm| okm.fill(mac_key.as_mut_slice()))
        .map_err(|_| {
            SecretshError::Io(IoError(std::io::Error::other("HKDF expand (mac) failed")))
        })?;

    ikm.zeroize();

    Ok(DerivedKeys { enc_key, mac_key })
}

/// ring HKDF requires a type that implements `ring::hkdf::KeyType`.
struct MyLen(usize);
impl ring::hkdf::KeyType for MyLen {
    fn len(&self) -> usize {
        self.0
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// HMAC helpers
// ─────────────────────────────────────────────────────────────────────────────

fn hmac_sign(key_bytes: &[u8], data: &[u8]) -> [u8; HMAC_LEN] {
    let key = hmac::Key::new(hmac::HMAC_SHA256, key_bytes);
    let tag = hmac::sign(&key, data);
    let mut out = [0u8; HMAC_LEN];
    out.copy_from_slice(tag.as_ref());
    out
}

fn hmac_verify(key_bytes: &[u8], data: &[u8], expected: &[u8; HMAC_LEN]) -> bool {
    let key = hmac::Key::new(hmac::HMAC_SHA256, key_bytes);
    hmac::verify(&key, data, expected).is_ok()
}

// ─────────────────────────────────────────────────────────────────────────────
// AES-256-GCM helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Encrypt `plaintext` with AES-256-GCM.
/// Returns `nonce_bytes || ciphertext_with_tag`.
fn aes_gcm_seal(
    enc_key: &[u8],
    plaintext: &[u8],
    aad: &[u8],
    rng: &SystemRandom,
) -> Result<(Vec<u8>, Vec<u8>), SecretshError> {
    let mut nonce_bytes = [0u8; GCM_NONCE_LEN];
    rng.fill(&mut nonce_bytes)
        .map_err(|_| SecretshError::Io(IoError(std::io::Error::other("RNG fill failed"))))?;

    let unbound = UnboundKey::new(&AES_256_GCM, enc_key).map_err(|_| {
        SecretshError::Io(IoError(std::io::Error::other(
            "AES-256-GCM key construction failed",
        )))
    })?;
    let mut sealing_key = SealingKey::new(unbound, OneShotNonce(Some(nonce_bytes)));

    let mut in_out = plaintext.to_vec();
    // ring appends the GCM tag in-place; we need to extend the buffer.
    in_out.extend_from_slice(&[0u8; GCM_TAG_LEN]);

    sealing_key
        .seal_in_place_separate_tag(Aad::from(aad), &mut in_out[..plaintext.len()])
        .map(|tag| {
            in_out.truncate(plaintext.len());
            in_out.extend_from_slice(tag.as_ref());
        })
        .map_err(|_| {
            SecretshError::Io(IoError(std::io::Error::other("AES-256-GCM seal failed")))
        })?;

    Ok((nonce_bytes.to_vec(), in_out))
}

/// Decrypt `ciphertext_with_tag` with AES-256-GCM.
fn aes_gcm_open(
    enc_key: &[u8],
    nonce_bytes: &[u8; GCM_NONCE_LEN],
    ciphertext_with_tag: &[u8],
    aad: &[u8],
) -> Result<Zeroizing<Vec<u8>>, ()> {
    let unbound = UnboundKey::new(&AES_256_GCM, enc_key).map_err(|_| ())?;
    let mut opening_key = OpeningKey::new(unbound, OneShotNonce(Some(*nonce_bytes)));

    let mut in_out = ciphertext_with_tag.to_vec();
    let plaintext_len = opening_key
        .open_in_place(Aad::from(aad), &mut in_out)
        .map_err(|_| ())?
        .len();

    in_out.truncate(plaintext_len);
    Ok(Zeroizing::new(in_out))
}

// ─────────────────────────────────────────────────────────────────────────────
// File permission check
// ─────────────────────────────────────────────────────────────────────────────

fn check_permissions(path: &Path, allow_insecure: bool) -> Result<(), SecretshError> {
    let meta = fs::metadata(path).map_err(|e| SecretshError::Io(IoError(e)))?;
    let mode = meta.permissions().mode();
    // Check group-readable (0o040) or world-readable (0o004) bits.
    if mode & 0o077 != 0 {
        if allow_insecure {
            return Ok(());
        }
        return Err(SecretshError::Vault(VaultError::InsecurePermissions {
            path: path.to_owned(),
            mode,
        }));
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Advisory locking
// ─────────────────────────────────────────────────────────────────────────────

struct LockGuard {
    lock_path: PathBuf,
    lock_file: Option<File>,
}

impl Drop for LockGuard {
    fn drop(&mut self) {
        if let Some(ref f) = self.lock_file {
            // Release flock
            unsafe {
                libc::flock(std::os::unix::io::AsRawFd::as_raw_fd(f), libc::LOCK_UN);
            }
        }
        // Best-effort: truncate the lockfile (don't delete — avoids TOCTOU).
        if let Ok(f) = OpenOptions::new()
            .write(true)
            .custom_flags(O_CLOEXEC)
            .open(&self.lock_path)
        {
            let _ = f.set_len(0);
        }
    }
}

/// Acquire an exclusive advisory lock on `<vault_path>.lock`.
/// Writes PID + ISO8601 timestamp to the lockfile.
/// Retries with exponential backoff for up to `LOCK_TIMEOUT_SECS` seconds.
fn acquire_lock(vault_path: &Path) -> Result<LockGuard, SecretshError> {
    let lock_path = lock_path_for(vault_path);
    let start = Instant::now();
    let timeout = Duration::from_secs(LOCK_TIMEOUT_SECS);
    let mut backoff = Duration::from_millis(10);

    loop {
        // Try to open / create the lockfile.
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(O_CLOEXEC)
            .open(&lock_path)
            .map_err(|e| SecretshError::Io(IoError(e)))?;

        let fd = std::os::unix::io::AsRawFd::as_raw_fd(&file);

        // Non-blocking exclusive lock attempt.
        let ret = unsafe { libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB) };

        if ret == 0 {
            // Lock acquired — write PID + timestamp.
            let pid = std::process::id();
            let ts = chrono::Utc::now().to_rfc3339();
            let content = format!("{pid}\n{ts}\n");
            let mut f = &file;
            let _ = f.write_all(content.as_bytes());
            let _ = f.flush();

            return Ok(LockGuard {
                lock_path,
                lock_file: Some(file),
            });
        }

        // Lock not acquired — check for stale lock.
        let elapsed = start.elapsed();
        if elapsed >= timeout {
            return Err(SecretshError::Vault(VaultError::LockTimeout {
                lockfile_path: lock_path,
                elapsed_secs: elapsed.as_secs(),
            }));
        }

        // Try to detect stale lock.
        if let Ok(content) = fs::read_to_string(&lock_path) {
            let mut lines = content.lines();
            if let (Some(pid_str), Some(ts_str)) = (lines.next(), lines.next()) {
                if let Ok(pid) = pid_str.trim().parse::<u32>() {
                    // Check if PID is still running.
                    let pid_alive = unsafe { libc::kill(pid as libc::pid_t, 0) } == 0;

                    // Parse timestamp.
                    let lock_age_secs = chrono::DateTime::parse_from_rfc3339(ts_str.trim())
                        .ok()
                        .map(|t| {
                            let now = chrono::Utc::now();
                            (now - t.with_timezone(&chrono::Utc)).num_seconds().max(0) as u64
                        })
                        .unwrap_or(0);

                    if !pid_alive || lock_age_secs > STALE_LOCK_AGE_SECS {
                        // Stale lock — remove and retry immediately.
                        let _ = fs::remove_file(&lock_path);
                        // Emit the StaleLock error as a warning (non-fatal).
                        // We just continue the loop; the next iteration will
                        // recreate and acquire the lockfile.
                        eprintln!(
                            "secretsh: stale vault lockfile removed (pid={pid}, age={lock_age_secs}s)"
                        );
                        continue;
                    }
                }
            }
        }

        // Back off and retry.
        std::thread::sleep(backoff);
        backoff = (backoff * 2).min(Duration::from_secs(1));
    }
}

fn lock_path_for(vault_path: &Path) -> PathBuf {
    let mut p = vault_path.to_owned();
    let name = p
        .file_name()
        .map(|n| format!("{}.lock", n.to_string_lossy()))
        .unwrap_or_else(|| "vault.lock".to_owned());
    p.set_file_name(name);
    p
}

fn tmp_path_for(vault_path: &Path) -> PathBuf {
    let pid = std::process::id();
    let mut p = vault_path.to_owned();
    let name = p
        .file_name()
        .map(|n| format!("{}.tmp.{pid}", n.to_string_lossy()))
        .unwrap_or_else(|| format!("vault.tmp.{pid}"));
    p.set_file_name(name);
    p
}

// ─────────────────────────────────────────────────────────────────────────────
// Serialization helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Build the raw header bytes (everything before header_hmac).
fn build_header_covered(
    kdf_params: &KdfParams,
    kdf_salt: &[u8; KDF_SALT_LEN],
    entry_count: u32,
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(HEADER_COVERED_LEN);
    buf.extend_from_slice(MAGIC);
    buf.push(VERSION);
    buf.push(CIPHER_ID);
    buf.extend_from_slice(&kdf_params.m_cost.to_le_bytes());
    buf.extend_from_slice(&kdf_params.t_cost.to_le_bytes());
    buf.extend_from_slice(&kdf_params.p_cost.to_le_bytes());
    buf.extend_from_slice(kdf_salt);
    buf.extend_from_slice(&entry_count.to_le_bytes());
    buf.extend_from_slice(&[0u8; 32]); // reserved
    debug_assert_eq!(buf.len(), HEADER_COVERED_LEN);
    buf
}

/// Serialize all entries into their binary representation (nonce + len + ciphertext).
fn serialize_entries(
    entries: &[Entry],
    enc_key: &[u8],
    rng: &SystemRandom,
) -> Result<Vec<u8>, SecretshError> {
    let mut buf = Vec::new();
    for (idx, entry) in entries.iter().enumerate() {
        // Plaintext: [key_name_len: u16 LE] [key_name bytes] [value bytes]
        let key_bytes = entry.key.as_bytes();
        let key_len = key_bytes.len() as u16;
        let mut plaintext = Vec::with_capacity(2 + key_bytes.len() + entry.value.len());
        plaintext.extend_from_slice(&key_len.to_le_bytes());
        plaintext.extend_from_slice(key_bytes);
        plaintext.extend_from_slice(&entry.value);

        // AAD: entry index as 4-byte big-endian.
        let aad = (idx as u32).to_be_bytes();

        let (nonce, ciphertext) = aes_gcm_seal(enc_key, &plaintext, &aad, rng)?;

        // Zero the plaintext immediately.
        plaintext.zeroize();

        let ct_len = ciphertext.len() as u32;
        buf.extend_from_slice(&nonce);
        buf.extend_from_slice(&ct_len.to_le_bytes());
        buf.extend_from_slice(&ciphertext);
    }
    Ok(buf)
}

// ─────────────────────────────────────────────────────────────────────────────
// Vault impl
// ─────────────────────────────────────────────────────────────────────────────

impl Vault {
    // ── init ──────────────────────────────────────────────────────────────────

    /// Create a new empty vault at `config.vault_path`.
    ///
    /// Fails if the vault already exists (use `--force` at the CLI layer to
    /// remove it first).  Validates passphrase length unless
    /// `no_passphrase_check` is `true`.
    pub fn init(config: &VaultConfig) -> Result<(), SecretshError> {
        Self::init_inner(config, false)
    }

    /// Same as `init` but skips the passphrase length check.
    pub fn init_no_passphrase_check(config: &VaultConfig) -> Result<(), SecretshError> {
        Self::init_inner(config, true)
    }

    fn init_inner(config: &VaultConfig, no_passphrase_check: bool) -> Result<(), SecretshError> {
        // Read passphrase.
        let passphrase = read_passphrase(&config.master_key_env)?;

        // Validate passphrase length.
        if !no_passphrase_check && passphrase.len() < MIN_PASSPHRASE_LEN {
            return Err(SecretshError::MasterKey(
                MasterKeyError::PassphraseTooShort {
                    length: passphrase.len(),
                    minimum: MIN_PASSPHRASE_LEN,
                },
            ));
        }

        // Create parent directory if needed.
        if let Some(parent) = config.vault_path.parent() {
            if !parent.as_os_str().is_empty() && !parent.exists() {
                fs::create_dir_all(parent).map_err(|e| SecretshError::Io(IoError(e)))?;
                // Set directory permissions to 0700 on the newly created directory.
                #[cfg(unix)]
                {
                    fs::set_permissions(parent, fs::Permissions::from_mode(0o700))
                        .map_err(|e| SecretshError::Io(IoError(e)))?;
                }
            }
        }

        // Acquire advisory lock.
        let _lock = acquire_lock(&config.vault_path)?;

        // Determine KDF params.
        let kdf_params = KdfParams {
            m_cost: config.kdf_memory.unwrap_or(DEFAULT_M_COST),
            t_cost: DEFAULT_T_COST,
            p_cost: DEFAULT_P_COST,
        };

        // Generate fresh KDF salt.
        let rng = SystemRandom::new();
        let mut kdf_salt = [0u8; KDF_SALT_LEN];
        rng.fill(&mut kdf_salt)
            .map_err(|_| SecretshError::Io(IoError(std::io::Error::other("RNG fill failed"))))?;

        // Derive keys.
        let keys = derive_keys(&passphrase, &kdf_salt, &kdf_params)?;

        // Build header.
        let header_covered = build_header_covered(&kdf_params, &kdf_salt, 0);
        let header_hmac = hmac_sign(&keys.mac_key, &header_covered);

        // Assemble vault bytes: header + header_hmac + commit_tag.
        let mut vault_bytes = Vec::new();
        vault_bytes.extend_from_slice(&header_covered);
        vault_bytes.extend_from_slice(&header_hmac);
        // No entries.
        // Commit tag over everything so far.
        let commit_tag = hmac_sign(&keys.mac_key, &vault_bytes);
        vault_bytes.extend_from_slice(&commit_tag);

        // Atomic write.
        write_atomic(&config.vault_path, &vault_bytes)?;

        Ok(())
    }

    // ── open ──────────────────────────────────────────────────────────────────

    /// Open and decrypt an existing vault.
    pub fn open(config: &VaultConfig) -> Result<Self, SecretshError> {
        let path = &config.vault_path;

        // Check existence.
        if !path.exists() {
            return Err(SecretshError::Vault(VaultError::NotFound {
                path: path.to_owned(),
            }));
        }

        // Check permissions.
        check_permissions(path, config.allow_insecure_permissions)?;

        // Acquire shared lock (we use LOCK_SH for reads).
        let lock_path = lock_path_for(path);
        let lock_file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(O_CLOEXEC)
            .open(&lock_path)
            .map_err(|e| SecretshError::Io(IoError(e)))?;
        let fd = std::os::unix::io::AsRawFd::as_raw_fd(&lock_file);
        // Blocking shared lock for reads.
        unsafe { libc::flock(fd, libc::LOCK_SH) };

        // Read vault file with O_CLOEXEC so the FD is not inherited by children.
        let mut vault_file = OpenOptions::new()
            .read(true)
            .custom_flags(O_CLOEXEC)
            .open(path)
            .map_err(|e| SecretshError::Io(IoError(e)))?;
        let mut vault_bytes = Vec::new();
        vault_file
            .read_to_end(&mut vault_bytes)
            .map_err(|e| SecretshError::Io(IoError(e)))?;
        drop(vault_file);

        // Release shared lock.
        unsafe { libc::flock(fd, libc::LOCK_UN) };
        drop(lock_file);

        // Parse and decrypt.
        let (entries, kdf_params) = parse_and_decrypt(&vault_bytes, &config.master_key_env, path)?;

        // mlock all decrypted entry value pages to prevent swap-out.
        let mut locked_regions = Vec::with_capacity(entries.len());
        for entry in &entries {
            let ptr = entry.value.as_ptr();
            let len = entry.value.len();
            if mlock_region(ptr, len) {
                locked_regions.push((ptr as usize, len));
            }
        }

        Ok(Vault {
            vault_path: path.to_owned(),
            master_key_env: config.master_key_env.clone(),
            allow_insecure_permissions: config.allow_insecure_permissions,
            kdf_params,
            entries,
            locked_regions,
        })
    }

    // ── set ───────────────────────────────────────────────────────────────────

    /// Insert or update a secret entry, then re-encrypt and persist the vault.
    pub fn set(&mut self, key: &str, value: &[u8]) -> Result<(), SecretshError> {
        validate_key_name(key)?;

        // Check entry limit (only applies when adding a new key).
        let existing = self.entries.iter().position(|e| e.key == key);
        if existing.is_none() && self.entries.len() >= MAX_ENTRIES {
            return Err(SecretshError::Vault(VaultError::EntryLimitExceeded {
                limit: MAX_ENTRIES,
            }));
        }

        // Update or insert.
        if let Some(idx) = existing {
            self.entries[idx].value = Zeroizing::new(value.to_vec());
        } else {
            self.entries.push(Entry {
                key: key.to_owned(),
                value: Zeroizing::new(value.to_vec()),
            });
        }

        self.persist()
    }

    // ── delete ────────────────────────────────────────────────────────────────

    /// Remove a secret entry by key name.
    ///
    /// Returns `true` if the entry existed and was removed, `false` if it was
    /// not found.
    pub fn delete(&mut self, key: &str) -> Result<bool, SecretshError> {
        let pos = self.entries.iter().position(|e| e.key == key);
        if let Some(idx) = pos {
            self.entries.remove(idx);
            self.persist()?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    // ── list_keys ─────────────────────────────────────────────────────────────

    /// Return all key names in the vault (values are never exposed).
    pub fn list_keys(&self) -> Vec<String> {
        self.entries.iter().map(|e| e.key.clone()).collect()
    }

    // ── resolve_placeholder ───────────────────────────────────────────────────

    /// Look up a secret value by key name.
    ///
    /// Returns `None` if the key does not exist.
    pub fn resolve_placeholder(&self, key: &str) -> Option<&[u8]> {
        self.entries
            .iter()
            .find(|e| e.key == key)
            .map(|e| e.value.as_slice())
    }

    // ── all_secret_values ─────────────────────────────────────────────────────

    /// Return all (key, value) pairs for redaction pattern construction.
    ///
    /// Values are returned as byte slices backed by the vault's in-memory
    /// storage — they are zeroized when the vault is closed.
    pub fn all_secret_values(&self) -> Vec<(&str, &[u8])> {
        self.entries
            .iter()
            .map(|e| (e.key.as_str(), e.value.as_slice()))
            .collect()
    }

    // ── export ────────────────────────────────────────────────────────────────

    /// Export all vault entries to a new encrypted vault file at `out_path`.
    ///
    /// The export file uses the same binary format with a fresh salt, fresh
    /// nonces, and the same passphrase.  The output file is created with
    /// mode `0600`.
    pub fn export(&self, out_path: &Path) -> Result<(), SecretshError> {
        let passphrase = read_passphrase(&self.master_key_env)?;

        // Create parent directory if needed.
        if let Some(parent) = out_path.parent() {
            if !parent.as_os_str().is_empty() && !parent.exists() {
                fs::create_dir_all(parent).map_err(|e| SecretshError::Io(IoError(e)))?;
                #[cfg(unix)]
                {
                    fs::set_permissions(parent, fs::Permissions::from_mode(0o700))
                        .map_err(|e| SecretshError::Io(IoError(e)))?;
                }
            }
        }

        // Generate fresh KDF salt and derive keys.
        let rng = SystemRandom::new();
        let mut kdf_salt = [0u8; KDF_SALT_LEN];
        rng.fill(&mut kdf_salt)
            .map_err(|_| SecretshError::Io(IoError(std::io::Error::other("RNG fill failed"))))?;

        let keys = derive_keys(&passphrase, &kdf_salt, &self.kdf_params)?;

        // Build header.
        let entry_count = self.entries.len() as u32;
        let header_covered = build_header_covered(&self.kdf_params, &kdf_salt, entry_count);
        let header_hmac = hmac_sign(&keys.mac_key, &header_covered);

        // Serialize entries.
        let entries_bytes = serialize_entries(&self.entries, &keys.enc_key, &rng)?;

        // Assemble vault bytes.
        let mut vault_bytes = Vec::new();
        vault_bytes.extend_from_slice(&header_covered);
        vault_bytes.extend_from_slice(&header_hmac);
        vault_bytes.extend_from_slice(&entries_bytes);

        let commit_tag = hmac_sign(&keys.mac_key, &vault_bytes);
        vault_bytes.extend_from_slice(&commit_tag);

        // Write the export file atomically.
        write_atomic(out_path, &vault_bytes)?;

        Ok(())
    }

    // ── import ────────────────────────────────────────────────────────────────

    /// Import entries from an encrypted vault file at `import_path`.
    ///
    /// - If `import_key_env` is `Some`, it specifies the env var name for the
    ///   import file's passphrase (may differ from the current vault's passphrase).
    /// - If `overwrite` is `true`, existing entries with the same key name are
    ///   replaced; otherwise, they are skipped.
    /// - Returns `(added, skipped, replaced)` counts.
    pub fn import(
        &mut self,
        import_path: &Path,
        import_key_env: Option<&str>,
        overwrite: bool,
    ) -> Result<(usize, usize, usize), SecretshError> {
        // Read and decrypt the import file.
        let import_bytes = {
            let mut f = OpenOptions::new()
                .read(true)
                .custom_flags(O_CLOEXEC)
                .open(import_path)
                .map_err(|e| SecretshError::Io(IoError(e)))?;
            let mut buf = Vec::new();
            f.read_to_end(&mut buf)
                .map_err(|e| SecretshError::Io(IoError(e)))?;
            buf
        };

        // Use the import-specific key env or fall back to the vault's own.
        let key_env = import_key_env.unwrap_or(&self.master_key_env);
        let (import_entries, _kdf_params) = parse_and_decrypt(&import_bytes, key_env, import_path)?;

        // Merge entries.
        let mut added = 0usize;
        let mut skipped = 0usize;
        let mut replaced = 0usize;

        // We need to consume entries without moving out of a Drop type.
        // Collect key names first, then handle values via index.
        let import_keys: Vec<String> = import_entries.iter().map(|e| e.key.clone()).collect();

        for (i, key) in import_keys.iter().enumerate() {
            let existing = self.entries.iter().position(|e| e.key == *key);
            match existing {
                Some(idx) => {
                    if overwrite {
                        let old_value = std::mem::replace(
                            &mut self.entries[idx].value,
                            Zeroizing::new(import_entries[i].value.as_slice().to_vec()),
                        );
                        drop(old_value);
                        replaced += 1;
                    } else {
                        skipped += 1;
                    }
                }
                None => {
                    if self.entries.len() >= MAX_ENTRIES {
                        return Err(SecretshError::Vault(VaultError::EntryLimitExceeded {
                            limit: MAX_ENTRIES,
                        }));
                    }
                    let ptr = import_entries[i].value.as_ptr();
                    let len = import_entries[i].value.len();
                    if mlock_region(ptr, len) {
                        self.locked_regions.push((ptr as usize, len));
                    }
                    self.entries.push(Entry {
                        key: key.clone(),
                        value: Zeroizing::new(import_entries[i].value.as_slice().to_vec()),
                    });
                    added += 1;
                }
            }
        }

        // Persist the merged vault.
        self.persist()?;

        Ok((added, skipped, replaced))
    }

    // ── close ─────────────────────────────────────────────────────────────────

    /// Zeroize all in-memory secret data.
    ///
    /// Called automatically by `Drop`.  Safe to call multiple times.
    pub fn close(&mut self) {
        // munlock and hint reclaim for all mlocked regions before zeroizing.
        for &(addr, len) in &self.locked_regions {
            munlock_region(addr as *const u8, len);
            madvise_free(addr as *mut u8, len);
        }
        self.locked_regions.clear();

        for entry in &mut self.entries {
            entry.value.zeroize();
        }
        self.entries.clear();
    }

    // ── persist (private) ─────────────────────────────────────────────────────

    /// Re-encrypt the entire vault with fresh salt + nonces and write atomically.
    fn persist(&self) -> Result<(), SecretshError> {
        let passphrase = read_passphrase(&self.master_key_env)?;

        // Fresh KDF salt.
        let rng = SystemRandom::new();
        let mut kdf_salt = [0u8; KDF_SALT_LEN];
        rng.fill(&mut kdf_salt)
            .map_err(|_| SecretshError::Io(IoError(std::io::Error::other("RNG fill failed"))))?;

        // Derive fresh keys.
        let keys = derive_keys(&passphrase, &kdf_salt, &self.kdf_params)?;

        // Build header.
        let entry_count = self.entries.len() as u32;
        let header_covered = build_header_covered(&self.kdf_params, &kdf_salt, entry_count);
        let header_hmac = hmac_sign(&keys.mac_key, &header_covered);

        // Serialize entries.
        let entries_bytes = serialize_entries(&self.entries, &keys.enc_key, &rng)?;

        // Assemble vault bytes.
        let mut vault_bytes = Vec::new();
        vault_bytes.extend_from_slice(&header_covered);
        vault_bytes.extend_from_slice(&header_hmac);
        vault_bytes.extend_from_slice(&entries_bytes);

        // Commit tag over everything so far.
        let commit_tag = hmac_sign(&keys.mac_key, &vault_bytes);
        vault_bytes.extend_from_slice(&commit_tag);

        // Acquire exclusive lock and write atomically.
        let _lock = acquire_lock(&self.vault_path)?;
        write_atomic(&self.vault_path, &vault_bytes)?;

        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Atomic write
// ─────────────────────────────────────────────────────────────────────────────

fn write_atomic(vault_path: &Path, data: &[u8]) -> Result<(), SecretshError> {
    let tmp = tmp_path_for(vault_path);

    // Remove stale temp file if it exists.
    if tmp.exists() {
        fs::remove_file(&tmp).map_err(|e| SecretshError::Io(IoError(e)))?;
    }

    // Write to temp file with O_WRONLY | O_CREAT | O_EXCL | mode 0600.
    {
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(O_CLOEXEC)
            .open(&tmp)
            .map_err(|e| SecretshError::Io(IoError(e)))?;
        f.write_all(data)
            .map_err(|e| SecretshError::Io(IoError(e)))?;
        f.flush().map_err(|e| SecretshError::Io(IoError(e)))?;
        f.sync_all().map_err(|e| SecretshError::Io(IoError(e)))?;
    }

    // Atomic rename.
    fs::rename(&tmp, vault_path).map_err(|e| SecretshError::Io(IoError(e)))?;

    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Parsing and decryption
// ─────────────────────────────────────────────────────────────────────────────

/// Parse the raw vault bytes, verify all integrity tags, and decrypt entries.
fn parse_and_decrypt(
    data: &[u8],
    master_key_env: &str,
    _vault_path: &Path,
) -> Result<(Vec<Entry>, KdfParams), SecretshError> {
    // ── Minimum size check ────────────────────────────────────────────────────
    // Header (74) + header_hmac (32) + commit_tag (32) = 138 bytes minimum.
    let min_size = HEADER_TOTAL_LEN + HMAC_LEN;
    if data.len() < min_size {
        return Err(SecretshError::Vault(VaultError::Truncated {
            expected: min_size,
            found: data.len(),
        }));
    }

    // ── Magic ─────────────────────────────────────────────────────────────────
    let magic: [u8; 8] = data[0..8].try_into().unwrap();
    if &magic != MAGIC {
        return Err(SecretshError::Vault(VaultError::BadMagic { found: magic }));
    }

    // ── Version ───────────────────────────────────────────────────────────────
    let version = data[8];
    if version == 0 {
        return Err(SecretshError::Vault(VaultError::VersionInvalid {
            found: version,
        }));
    }
    if version > VERSION {
        return Err(SecretshError::Vault(VaultError::VersionTooNew {
            found: version,
            supported: VERSION,
        }));
    }

    // ── KDF params ────────────────────────────────────────────────────────────
    // Offsets: magic(8) + version(1) + cipher_id(1) = 10
    let m_cost = u32::from_le_bytes(data[10..14].try_into().unwrap());
    let t_cost = u32::from_le_bytes(data[14..18].try_into().unwrap());
    let p_cost = u32::from_le_bytes(data[18..22].try_into().unwrap());
    let kdf_params = KdfParams {
        m_cost,
        t_cost,
        p_cost,
    };

    // ── KDF salt ──────────────────────────────────────────────────────────────
    // Offset: 22
    let kdf_salt: [u8; KDF_SALT_LEN] = data[22..38].try_into().unwrap();

    // ── Entry count ───────────────────────────────────────────────────────────
    // Offset: 38
    let entry_count = u32::from_le_bytes(data[38..42].try_into().unwrap()) as usize;

    // ── Derive keys ───────────────────────────────────────────────────────────
    let passphrase = read_passphrase(master_key_env)?;
    let keys = derive_keys(&passphrase, &kdf_salt, &kdf_params)?;

    // ── Verify header HMAC ────────────────────────────────────────────────────
    // Covered bytes: data[0..HEADER_COVERED_LEN]
    let header_hmac_stored: [u8; HMAC_LEN] = data[HEADER_COVERED_LEN..HEADER_TOTAL_LEN]
        .try_into()
        .unwrap();
    if !hmac_verify(
        &keys.mac_key,
        &data[..HEADER_COVERED_LEN],
        &header_hmac_stored,
    ) {
        return Err(SecretshError::Vault(VaultError::HmacMismatch));
    }

    // ── Verify commit tag ─────────────────────────────────────────────────────
    // The commit tag is the last 32 bytes of the file.
    if data.len() < HMAC_LEN {
        return Err(SecretshError::Vault(VaultError::Truncated {
            expected: HMAC_LEN,
            found: data.len(),
        }));
    }
    let commit_tag_offset = data.len() - HMAC_LEN;
    let commit_tag_stored: [u8; HMAC_LEN] = data[commit_tag_offset..].try_into().unwrap();
    if !hmac_verify(
        &keys.mac_key,
        &data[..commit_tag_offset],
        &commit_tag_stored,
    ) {
        return Err(SecretshError::Vault(VaultError::CommitTagMismatch));
    }

    // ── Decrypt entries ───────────────────────────────────────────────────────
    let mut cursor = HEADER_TOTAL_LEN;
    let entries_end = commit_tag_offset;
    let mut entries = Vec::with_capacity(entry_count);

    for idx in 0..entry_count {
        // Nonce: 12 bytes
        if cursor + GCM_NONCE_LEN > entries_end {
            return Err(SecretshError::Vault(VaultError::Truncated {
                expected: cursor + GCM_NONCE_LEN,
                found: data.len(),
            }));
        }
        let nonce: [u8; GCM_NONCE_LEN] = data[cursor..cursor + GCM_NONCE_LEN].try_into().unwrap();
        cursor += GCM_NONCE_LEN;

        // Ciphertext length: 4 bytes
        if cursor + 4 > entries_end {
            return Err(SecretshError::Vault(VaultError::Truncated {
                expected: cursor + 4,
                found: data.len(),
            }));
        }
        let ct_len = u32::from_le_bytes(data[cursor..cursor + 4].try_into().unwrap()) as usize;
        cursor += 4;

        // Ciphertext + GCM tag
        if cursor + ct_len > entries_end {
            return Err(SecretshError::Vault(VaultError::Truncated {
                expected: cursor + ct_len,
                found: data.len(),
            }));
        }
        let ciphertext = &data[cursor..cursor + ct_len];
        cursor += ct_len;

        // AAD: entry index as 4-byte big-endian.
        let aad = (idx as u32).to_be_bytes();

        // Decrypt.
        let plaintext = aes_gcm_open(&keys.enc_key, &nonce, ciphertext, &aad).map_err(|_| {
            // Distinguish wrong passphrase (first entry) from later corruption.
            if idx == 0 {
                SecretshError::Vault(VaultError::WrongPassphrase)
            } else {
                SecretshError::Vault(VaultError::GcmMismatch { index: idx as u32 })
            }
        })?;

        // Parse plaintext: [key_name_len: u16 LE] [key_name] [value]
        if plaintext.len() < 2 {
            return Err(SecretshError::Vault(VaultError::Truncated {
                expected: 2,
                found: plaintext.len(),
            }));
        }
        let key_name_len = u16::from_le_bytes(plaintext[0..2].try_into().unwrap()) as usize;
        if plaintext.len() < 2 + key_name_len {
            return Err(SecretshError::Vault(VaultError::Truncated {
                expected: 2 + key_name_len,
                found: plaintext.len(),
            }));
        }
        let key_name = std::str::from_utf8(&plaintext[2..2 + key_name_len])
            .map_err(|_| {
                SecretshError::Io(IoError(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "key name is not valid UTF-8",
                )))
            })?
            .to_owned();
        let value = Zeroizing::new(plaintext[2 + key_name_len..].to_vec());

        entries.push(Entry {
            key: key_name,
            value,
        });
    }

    // Sanity: cursor should be at entries_end.
    if cursor != entries_end {
        return Err(SecretshError::Vault(VaultError::Truncated {
            expected: entries_end,
            found: cursor,
        }));
    }

    Ok((entries, kdf_params))
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use tempfile::TempDir;

    // ── Helpers ───────────────────────────────────────────────────────────────

    /// Create a temporary directory and return a `VaultConfig` pointing to a
    /// vault file inside it.  The passphrase is set in the environment under
    /// the given env-var name.
    fn make_config(dir: &TempDir, env_var: &str, passphrase: &str) -> VaultConfig {
        std::env::set_var(env_var, passphrase);
        VaultConfig {
            vault_path: dir.path().join("vault.bin"),
            master_key_env: env_var.to_owned(),
            allow_insecure_permissions: false,
            kdf_memory: Some(8192), // 8 MiB — fast for tests
        }
    }

    // ── Round-trip ────────────────────────────────────────────────────────────

    #[test]
    fn round_trip_set_and_read() {
        let dir = TempDir::new().unwrap();
        let cfg = make_config(&dir, "VAULT_TEST_RT", "correct-horse-battery-staple");

        Vault::init(&cfg).expect("init failed");

        {
            let mut vault = Vault::open(&cfg).expect("open failed");
            vault
                .set("MY_KEY", b"super-secret-value")
                .expect("set failed");
        }

        {
            let vault = Vault::open(&cfg).expect("re-open failed");
            let val = vault.resolve_placeholder("MY_KEY").expect("key missing");
            assert_eq!(val, b"super-secret-value");
        }
    }

    #[test]
    fn round_trip_multiple_keys() {
        let dir = TempDir::new().unwrap();
        let cfg = make_config(&dir, "VAULT_TEST_MULTI", "correct-horse-battery-staple");

        Vault::init(&cfg).expect("init failed");

        {
            let mut vault = Vault::open(&cfg).expect("open failed");
            vault.set("KEY_A", b"value_a").unwrap();
            vault.set("KEY_B", b"value_b").unwrap();
            vault.set("KEY_C", b"value_c").unwrap();
        }

        {
            let vault = Vault::open(&cfg).expect("re-open failed");
            assert_eq!(vault.resolve_placeholder("KEY_A").unwrap(), b"value_a");
            assert_eq!(vault.resolve_placeholder("KEY_B").unwrap(), b"value_b");
            assert_eq!(vault.resolve_placeholder("KEY_C").unwrap(), b"value_c");
            assert_eq!(vault.list_keys().len(), 3);
        }
    }

    #[test]
    fn round_trip_update_existing_key() {
        let dir = TempDir::new().unwrap();
        let cfg = make_config(&dir, "VAULT_TEST_UPDATE", "correct-horse-battery-staple");

        Vault::init(&cfg).expect("init failed");

        {
            let mut vault = Vault::open(&cfg).unwrap();
            vault.set("K", b"old").unwrap();
        }
        {
            let mut vault = Vault::open(&cfg).unwrap();
            vault.set("K", b"new").unwrap();
        }
        {
            let vault = Vault::open(&cfg).unwrap();
            assert_eq!(vault.resolve_placeholder("K").unwrap(), b"new");
            assert_eq!(vault.list_keys().len(), 1);
        }
    }

    #[test]
    fn round_trip_delete() {
        let dir = TempDir::new().unwrap();
        let cfg = make_config(&dir, "VAULT_TEST_DEL", "correct-horse-battery-staple");

        Vault::init(&cfg).expect("init failed");

        {
            let mut vault = Vault::open(&cfg).unwrap();
            vault.set("TO_DELETE", b"gone").unwrap();
            vault.set("KEEP", b"here").unwrap();
        }
        {
            let mut vault = Vault::open(&cfg).unwrap();
            let removed = vault.delete("TO_DELETE").unwrap();
            assert!(removed);
            let not_found = vault.delete("NONEXISTENT").unwrap();
            assert!(!not_found);
        }
        {
            let vault = Vault::open(&cfg).unwrap();
            assert!(vault.resolve_placeholder("TO_DELETE").is_none());
            assert_eq!(vault.resolve_placeholder("KEEP").unwrap(), b"here");
        }
    }

    // ── HMAC verification failure ─────────────────────────────────────────────

    #[test]
    fn header_hmac_mismatch_detected() {
        let dir = TempDir::new().unwrap();
        let cfg = make_config(&dir, "VAULT_TEST_HMAC", "correct-horse-battery-staple");

        Vault::init(&cfg).expect("init failed");

        // Flip a byte in the header (byte 5, inside the magic field area but
        // after the magic — actually let's flip a reserved byte at offset 42).
        let mut raw = fs::read(&cfg.vault_path).unwrap();
        // Offset 42 is inside the reserved field (bytes 42..74).
        raw[42] ^= 0xFF;
        fs::write(&cfg.vault_path, &raw).unwrap();

        let err = Vault::open(&cfg).unwrap_err();
        assert!(
            matches!(err, SecretshError::Vault(VaultError::HmacMismatch)),
            "expected HmacMismatch, got: {err:?}"
        );
    }

    #[test]
    fn commit_tag_mismatch_detected() {
        let dir = TempDir::new().unwrap();
        let cfg = make_config(&dir, "VAULT_TEST_COMMIT", "correct-horse-battery-staple");

        Vault::init(&cfg).expect("init failed");

        // Flip the last byte of the file (inside the commit tag).
        let mut raw = fs::read(&cfg.vault_path).unwrap();
        let last = raw.len() - 1;
        raw[last] ^= 0xFF;
        fs::write(&cfg.vault_path, &raw).unwrap();

        let err = Vault::open(&cfg).unwrap_err();
        assert!(
            matches!(
                err,
                SecretshError::Vault(VaultError::CommitTagMismatch)
                    | SecretshError::Vault(VaultError::HmacMismatch)
            ),
            "expected CommitTagMismatch or HmacMismatch, got: {err:?}"
        );
    }

    // ── Wrong passphrase ──────────────────────────────────────────────────────

    #[test]
    fn wrong_passphrase_returns_error() {
        let dir = TempDir::new().unwrap();
        let cfg = make_config(&dir, "VAULT_TEST_PASS", "correct-horse-battery-staple");

        Vault::init(&cfg).expect("init failed");

        // Set a key so there is at least one entry to decrypt.
        {
            let mut vault = Vault::open(&cfg).unwrap();
            vault.set("SECRET", b"value").unwrap();
        }

        // Change the passphrase env var to something wrong.
        std::env::set_var("VAULT_TEST_PASS", "wrong-passphrase-here");

        let err = Vault::open(&cfg).unwrap_err();
        // With a wrong passphrase the header HMAC will fail (different derived
        // MAC key), so we accept either HmacMismatch or WrongPassphrase.
        assert!(
            matches!(
                err,
                SecretshError::Vault(VaultError::WrongPassphrase)
                    | SecretshError::Vault(VaultError::HmacMismatch)
            ),
            "expected WrongPassphrase or HmacMismatch, got: {err:?}"
        );
    }

    // ── Key name validation ───────────────────────────────────────────────────

    #[test]
    fn valid_key_names_accepted() {
        for name in &["A", "_", "ABC", "a_b_c", "KEY123", "_PRIVATE"] {
            validate_key_name(name).unwrap_or_else(|e| panic!("rejected valid name {name:?}: {e}"));
        }
    }

    #[test]
    fn invalid_key_names_rejected() {
        for name in &["", "1START", "has-hyphen", "has space", "has.dot"] {
            assert!(
                validate_key_name(name).is_err(),
                "should have rejected {name:?}"
            );
        }
    }

    #[test]
    fn set_with_invalid_key_name_returns_error() {
        let dir = TempDir::new().unwrap();
        let cfg = make_config(&dir, "VAULT_TEST_KEYVAL", "correct-horse-battery-staple");
        Vault::init(&cfg).unwrap();

        let mut vault = Vault::open(&cfg).unwrap();
        let err = vault.set("invalid-key!", b"value").unwrap_err();
        assert!(
            matches!(err, SecretshError::Tokenization(_)),
            "expected Tokenization error, got: {err:?}"
        );
    }

    // ── Entry count limit ─────────────────────────────────────────────────────

    #[test]
    fn entry_limit_enforced() {
        let dir = TempDir::new().unwrap();
        let cfg = make_config(&dir, "VAULT_TEST_LIMIT", "correct-horse-battery-staple");
        Vault::init(&cfg).unwrap();

        let mut vault = Vault::open(&cfg).unwrap();

        // Manually fill entries to the limit without persisting each time
        // (to keep the test fast).
        for i in 0..MAX_ENTRIES {
            vault.entries.push(Entry {
                key: format!("KEY_{i:05}"),
                value: Zeroizing::new(b"v".to_vec()),
            });
        }

        // Now attempting to set a new key should fail.
        let err = vault.set("NEW_KEY", b"value").unwrap_err();
        assert!(
            matches!(
                err,
                SecretshError::Vault(VaultError::EntryLimitExceeded { .. })
            ),
            "expected EntryLimitExceeded, got: {err:?}"
        );
    }

    // ── Permission checking ───────────────────────────────────────────────────

    #[test]
    fn insecure_permissions_rejected() {
        let dir = TempDir::new().unwrap();
        let cfg = make_config(&dir, "VAULT_TEST_PERM", "correct-horse-battery-staple");
        Vault::init(&cfg).unwrap();

        // Make the vault world-readable.
        fs::set_permissions(&cfg.vault_path, fs::Permissions::from_mode(0o644)).unwrap();

        let err = Vault::open(&cfg).unwrap_err();
        assert!(
            matches!(
                err,
                SecretshError::Vault(VaultError::InsecurePermissions { .. })
            ),
            "expected InsecurePermissions, got: {err:?}"
        );
    }

    #[test]
    fn insecure_permissions_allowed_with_flag() {
        let dir = TempDir::new().unwrap();
        let mut cfg = make_config(
            &dir,
            "VAULT_TEST_PERM_ALLOW",
            "correct-horse-battery-staple",
        );
        Vault::init(&cfg).unwrap();

        // Make the vault world-readable.
        fs::set_permissions(&cfg.vault_path, fs::Permissions::from_mode(0o644)).unwrap();

        cfg.allow_insecure_permissions = true;
        // Should succeed.
        Vault::open(&cfg).expect("should open with allow_insecure_permissions=true");
    }

    // ── Passphrase length check ───────────────────────────────────────────────

    #[test]
    fn short_passphrase_rejected_on_init() {
        let dir = TempDir::new().unwrap();
        let cfg = make_config(&dir, "VAULT_TEST_SHORT_PASS", "short");

        let err = Vault::init(&cfg).unwrap_err();
        assert!(
            matches!(
                err,
                SecretshError::MasterKey(MasterKeyError::PassphraseTooShort { .. })
            ),
            "expected PassphraseTooShort, got: {err:?}"
        );
    }

    #[test]
    fn short_passphrase_allowed_with_no_check() {
        let dir = TempDir::new().unwrap();
        let cfg = make_config(&dir, "VAULT_TEST_SHORT_PASS_OK", "short");

        Vault::init_no_passphrase_check(&cfg)
            .expect("should succeed with no_passphrase_check=true");
    }

    // ── Vault not found ───────────────────────────────────────────────────────

    #[test]
    fn open_nonexistent_vault_returns_not_found() {
        let dir = TempDir::new().unwrap();
        let cfg = make_config(&dir, "VAULT_TEST_NF", "correct-horse-battery-staple");
        // Do NOT call init — vault file does not exist.

        let err = Vault::open(&cfg).unwrap_err();
        assert!(
            matches!(err, SecretshError::Vault(VaultError::NotFound { .. })),
            "expected NotFound, got: {err:?}"
        );
    }

    // ── Binary values ─────────────────────────────────────────────────────────

    #[test]
    fn binary_value_round_trip() {
        let dir = TempDir::new().unwrap();
        let cfg = make_config(&dir, "VAULT_TEST_BIN", "correct-horse-battery-staple");
        Vault::init(&cfg).unwrap();

        let binary_val: Vec<u8> = (0u8..=255).collect();

        {
            let mut vault = Vault::open(&cfg).unwrap();
            vault.set("BIN_KEY", &binary_val).unwrap();
        }
        {
            let vault = Vault::open(&cfg).unwrap();
            assert_eq!(
                vault.resolve_placeholder("BIN_KEY").unwrap(),
                &binary_val[..]
            );
        }
    }

    // ── all_secret_values ─────────────────────────────────────────────────────

    #[test]
    fn all_secret_values_returns_all_entries() {
        let dir = TempDir::new().unwrap();
        let cfg = make_config(&dir, "VAULT_TEST_ALL", "correct-horse-battery-staple");
        Vault::init(&cfg).unwrap();

        {
            let mut vault = Vault::open(&cfg).unwrap();
            vault.set("A", b"1").unwrap();
            vault.set("B", b"2").unwrap();
        }

        let vault = Vault::open(&cfg).unwrap();
        let all = vault.all_secret_values();
        assert_eq!(all.len(), 2);
        let keys: Vec<&str> = all.iter().map(|(k, _)| *k).collect();
        assert!(keys.contains(&"A"));
        assert!(keys.contains(&"B"));
    }

    // ── close / zeroize ───────────────────────────────────────────────────────

    #[test]
    fn close_clears_entries() {
        let dir = TempDir::new().unwrap();
        let cfg = make_config(&dir, "VAULT_TEST_CLOSE", "correct-horse-battery-staple");
        Vault::init(&cfg).unwrap();

        let mut vault = Vault::open(&cfg).unwrap();
        vault.set("K", b"secret").unwrap();

        // Re-open to get a fresh vault with the entry.
        let mut vault2 = Vault::open(&cfg).unwrap();
        assert!(vault2.resolve_placeholder("K").is_some());
        vault2.close();
        assert!(vault2.resolve_placeholder("K").is_none());
        assert!(vault2.list_keys().is_empty());
    }

    // ── Bad magic ─────────────────────────────────────────────────────────────

    #[test]
    fn bad_magic_detected() {
        let dir = TempDir::new().unwrap();
        let cfg = make_config(&dir, "VAULT_TEST_MAGIC", "correct-horse-battery-staple");
        Vault::init(&cfg).unwrap();

        let mut raw = fs::read(&cfg.vault_path).unwrap();
        raw[0] = b'X'; // corrupt the magic
        fs::write(&cfg.vault_path, &raw).unwrap();

        let err = Vault::open(&cfg).unwrap_err();
        assert!(
            matches!(err, SecretshError::Vault(VaultError::BadMagic { .. })),
            "expected BadMagic, got: {err:?}"
        );
    }

    // ── Truncated file ────────────────────────────────────────────────────────

    #[test]
    fn truncated_file_detected() {
        let dir = TempDir::new().unwrap();
        let cfg = make_config(&dir, "VAULT_TEST_TRUNC", "correct-horse-battery-staple");
        Vault::init(&cfg).unwrap();

        let raw = fs::read(&cfg.vault_path).unwrap();
        // Write only the first 10 bytes.
        fs::write(&cfg.vault_path, &raw[..10]).unwrap();

        let err = Vault::open(&cfg).unwrap_err();
        assert!(
            matches!(err, SecretshError::Vault(VaultError::Truncated { .. })),
            "expected Truncated, got: {err:?}"
        );
    }

    // ── Export / Import round-trip ──────────────────────────────────────────────

    #[test]
    fn export_import_round_trip() {
        let dir = TempDir::new().unwrap();
        let cfg = make_config(&dir, "VAULT_TEST_EXPORT", "correct-horse-battery-staple");
        Vault::init(&cfg).unwrap();

        // Populate the vault.
        {
            let mut vault = Vault::open(&cfg).unwrap();
            vault.set("KEY_A", b"value_a").unwrap();
            vault.set("KEY_B", b"value_b").unwrap();
        }

        // Export.
        let export_path = dir.path().join("export.vault.bin");
        {
            let vault = Vault::open(&cfg).unwrap();
            vault.export(&export_path).unwrap();
        }
        assert!(export_path.exists(), "export file should exist");

        // Verify the export file is a valid vault by opening it.
        {
            let export_cfg = VaultConfig {
                vault_path: export_path.clone(),
                master_key_env: "VAULT_TEST_EXPORT".to_owned(),
                allow_insecure_permissions: false,
                kdf_memory: None,
            };
            let vault = Vault::open(&export_cfg).unwrap();
            assert_eq!(vault.list_keys().len(), 2);
            assert_eq!(vault.resolve_placeholder("KEY_A").unwrap(), b"value_a");
            assert_eq!(vault.resolve_placeholder("KEY_B").unwrap(), b"value_b");
        }
    }

    #[test]
    fn import_merges_new_entries() {
        let dir = TempDir::new().unwrap();
        let cfg = make_config(&dir, "VAULT_TEST_IMPORT", "correct-horse-battery-staple");
        Vault::init(&cfg).unwrap();

        // Set up the main vault with one key.
        {
            let mut vault = Vault::open(&cfg).unwrap();
            vault.set("EXISTING_KEY", b"existing_value").unwrap();
        }

        // Create a separate import-source vault with different keys.
        let import_vault_path = dir.path().join("import_vault.bin");
        let import_cfg = VaultConfig {
            vault_path: import_vault_path.clone(),
            master_key_env: "VAULT_TEST_IMPORT".to_owned(),
            allow_insecure_permissions: false,
            kdf_memory: Some(8192),
        };
        Vault::init(&import_cfg).unwrap();
        {
            let mut vault = Vault::open(&import_cfg).unwrap();
            vault.set("NEW_KEY", b"new_value").unwrap();
        }

        // Import from the separate vault.
        {
            let mut vault = Vault::open(&cfg).unwrap();
            assert_eq!(vault.list_keys(), vec!["EXISTING_KEY"]);

            let (added, skipped, replaced) = vault.import(&import_vault_path, None, false).unwrap();
            assert_eq!(added, 1);
            assert_eq!(skipped, 0);
            assert_eq!(replaced, 0);
        }

        // Verify merged state.
        {
            let vault = Vault::open(&cfg).unwrap();
            assert_eq!(vault.list_keys().len(), 2);
            assert_eq!(
                vault.resolve_placeholder("EXISTING_KEY").unwrap(),
                b"existing_value"
            );
            assert_eq!(vault.resolve_placeholder("NEW_KEY").unwrap(), b"new_value");
        }
    }

    #[test]
    fn import_skips_existing_without_overwrite() {
        let dir = TempDir::new().unwrap();
        let cfg = make_config(&dir, "VAULT_TEST_IMP_SKIP", "correct-horse-battery-staple");
        Vault::init(&cfg).unwrap();

        // Set up vault with a key.
        {
            let mut vault = Vault::open(&cfg).unwrap();
            vault.set("SHARED_KEY", b"original_value").unwrap();
        }

        // Create separate import vault with same key name, different value.
        let import_vault_path = dir.path().join("import_vault.bin");
        let import_cfg = VaultConfig {
            vault_path: import_vault_path.clone(),
            master_key_env: "VAULT_TEST_IMP_SKIP".to_owned(),
            allow_insecure_permissions: false,
            kdf_memory: Some(8192),
        };
        Vault::init(&import_cfg).unwrap();
        {
            let mut vault = Vault::open(&import_cfg).unwrap();
            vault.set("SHARED_KEY", b"new_value").unwrap();
        }

        // Import without overwrite.
        {
            let mut vault = Vault::open(&cfg).unwrap();
            let (added, skipped, replaced) = vault.import(&import_vault_path, None, false).unwrap();
            assert_eq!(added, 0);
            assert_eq!(skipped, 1);
            assert_eq!(replaced, 0);

            // Original value should be preserved.
            assert_eq!(
                vault.resolve_placeholder("SHARED_KEY").unwrap(),
                b"original_value"
            );
        }
    }

    #[test]
    fn import_overwrites_with_flag() {
        let dir = TempDir::new().unwrap();
        let cfg = make_config(&dir, "VAULT_TEST_IMP_OVER", "correct-horse-battery-staple");
        Vault::init(&cfg).unwrap();

        // Set up vault with a key.
        {
            let mut vault = Vault::open(&cfg).unwrap();
            vault.set("SHARED_KEY", b"original_value").unwrap();
        }

        // Create separate import vault with same key name, different value.
        let import_vault_path = dir.path().join("import_vault.bin");
        let import_cfg = VaultConfig {
            vault_path: import_vault_path.clone(),
            master_key_env: "VAULT_TEST_IMP_OVER".to_owned(),
            allow_insecure_permissions: false,
            kdf_memory: Some(8192),
        };
        Vault::init(&import_cfg).unwrap();
        {
            let mut vault = Vault::open(&import_cfg).unwrap();
            vault.set("SHARED_KEY", b"new_value").unwrap();
        }

        // Import with overwrite.
        {
            let mut vault = Vault::open(&cfg).unwrap();
            let (added, skipped, replaced) = vault.import(&import_vault_path, None, true).unwrap();
            assert_eq!(added, 0);
            assert_eq!(skipped, 0);
            assert_eq!(replaced, 1);

            // Value should be overwritten.
            assert_eq!(
                vault.resolve_placeholder("SHARED_KEY").unwrap(),
                b"new_value"
            );
        }
    }
}
