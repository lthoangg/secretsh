//! Process spawning module for secretsh.
//!
//! Uses `posix_spawnp(3)` — Apple's recommended API for launching child
//! processes on macOS.  `fork(2)` is unsafe in multithreaded processes on
//! macOS because system frameworks (e.g. `libdispatch`, `CoreFoundation`) hold
//! internal locks that may be owned by a non-forking thread at the moment of
//! the fork, causing the child to deadlock immediately.  `posix_spawnp` avoids
//! this by performing the exec atomically inside the kernel without ever
//! running arbitrary user-space code in the child.
//!
//! # Architecture
//!
//! ```text
//!  caller
//!    │
//!    ▼
//! spawn_child()
//!    ├─ create stdout_pipe + stderr_pipe
//!    ├─ build posix_spawn_file_actions (dup2 write-ends → fd 1, fd 2)
//!    ├─ build posix_spawnattr (default flags; FD_CLOEXEC set on pipes instead)
//!    ├─ posix_spawnp()  ──────────────────────────────► child process
//!    ├─ close write-ends in parent
//!    ├─ zeroize CString argv immediately
//!    ├─ install SIGINT/SIGTERM/SIGHUP forwarding handlers
//!    ├─ spawn reader threads (stdout + stderr) with byte-limit enforcement
//!    ├─ deadline loop: waitpid(WNOHANG) + timeout + limit checks
//!    └─ redact + return SpawnResult
//! ```

use std::ffi::CString;
use std::io::Read;
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use libc::{
    c_char, c_int, pid_t, EACCES, ENOENT, ENOEXEC, SIGHUP, SIGINT, SIGKILL, SIGTERM, WNOHANG,
};
use zeroize::{Zeroize, Zeroizing};

use crate::error::{SecretshError, SpawnError};
use crate::redact::Redactor;

// ─────────────────────────────────────────────────────────────────────────────
// ZeroizingCString — a CString whose heap bytes are wiped on drop
// ─────────────────────────────────────────────────────────────────────────────

/// A `CString` wrapper that overwrites the underlying heap allocation with
/// zeroes before freeing it.
///
/// `CString` does not implement `Zeroize` because it is not a plain-old-data
/// type (`DefaultIsZeroes`).  We implement the zeroing manually by obtaining a
/// mutable slice of the inner bytes via `into_bytes_with_nul` and zeroing them
/// before the allocation is freed.
struct ZeroizingCString(Option<CString>);

impl ZeroizingCString {
    fn new(cs: CString) -> Self {
        Self(Some(cs))
    }

    /// Return a raw pointer to the C string (valid as long as `self` is alive).
    fn as_ptr(&self) -> *const c_char {
        self.0
            .as_ref()
            .expect("ZeroizingCString already consumed")
            .as_ptr()
    }
}

impl Drop for ZeroizingCString {
    fn drop(&mut self) {
        if let Some(cs) = self.0.take() {
            // Convert to a mutable byte vec, zero it, then let it drop.
            let mut bytes = cs.into_bytes_with_nul();
            bytes.zeroize();
            // `bytes` is dropped here, freeing the allocation.
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

/// Default execution timeout in seconds (5 minutes).
const DEFAULT_TIMEOUT_SECS: u64 = 300;

/// Default maximum stdout size (50 MiB).
const DEFAULT_MAX_OUTPUT_BYTES: usize = 50 * 1024 * 1024;

/// Default maximum stderr size (1 MiB).
const DEFAULT_MAX_STDERR_BYTES: usize = 1024 * 1024;

/// Grace period between SIGTERM and SIGKILL during shutdown (seconds).
const SIGKILL_GRACE_SECS: u64 = 5;

/// Exit code used for timeout and output-limit kills (GNU `timeout` convention).
const EXIT_TIMEOUT: i32 = 124;

/// How often the main wait loop polls `waitpid` (milliseconds).
const POLL_INTERVAL_MS: u64 = 50;

/// Read chunk size for the pipe-reader threads (64 KiB).
const READ_CHUNK: usize = 65_536;

// ─────────────────────────────────────────────────────────────────────────────
// Global child PID for signal forwarding
// ─────────────────────────────────────────────────────────────────────────────

/// Stores the PID of the currently-running child so that the signal handlers
/// installed by [`install_signal_forwarders`] can forward signals to it.
///
/// `0` means no child is running.  Written once before the handlers are
/// installed; read inside the handlers.  `AtomicI32` is signal-handler-safe.
static CHILD_PID: AtomicI32 = AtomicI32::new(0);

// ─────────────────────────────────────────────────────────────────────────────
// Public types
// ─────────────────────────────────────────────────────────────────────────────

/// Configuration knobs for [`spawn_child`].
#[derive(Debug, Clone)]
pub struct SpawnConfig {
    /// Maximum wall-clock seconds the child may run before being killed.
    ///
    /// Default: 300 (5 minutes).
    pub timeout_secs: u64,

    /// Maximum number of bytes accepted from the child's stdout.
    ///
    /// If the child writes more than this the child is killed and the partial
    /// output (redacted) is returned with `exit_code = 124`.
    ///
    /// Default: 52_428_800 (50 MiB).
    pub max_output_bytes: usize,

    /// Maximum number of bytes accepted from the child's stderr.
    ///
    /// Default: 1_048_576 (1 MiB).
    pub max_stderr_bytes: usize,
}

impl Default for SpawnConfig {
    fn default() -> Self {
        Self {
            timeout_secs: DEFAULT_TIMEOUT_SECS,
            max_output_bytes: DEFAULT_MAX_OUTPUT_BYTES,
            max_stderr_bytes: DEFAULT_MAX_STDERR_BYTES,
        }
    }
}

/// The outcome of a successfully-spawned child process.
///
/// Both `stdout` and `stderr` have been passed through the [`Redactor`] before
/// being stored here — no raw secret values will appear in these fields.
#[derive(Debug)]
pub struct SpawnResult {
    /// Redacted stdout output (UTF-8 lossy).
    pub stdout: String,

    /// Redacted stderr output (UTF-8 lossy).
    pub stderr: String,

    /// The child's exit code, or 124 on timeout/limit, or 128+N on signal.
    pub exit_code: i32,

    /// `true` when the child was killed because it exceeded `timeout_secs`.
    pub timed_out: bool,
}

// ─────────────────────────────────────────────────────────────────────────────
// Internal helpers — pipe
// ─────────────────────────────────────────────────────────────────────────────

/// A raw Unix pipe represented as `(read_fd, write_fd)`.
struct Pipe {
    read_fd: c_int,
    write_fd: c_int,
}

impl Pipe {
    /// Create a new pipe via `libc::pipe()`.
    fn new() -> Result<Self, SecretshError> {
        let mut fds: [c_int; 2] = [-1, -1];
        // SAFETY: `fds` is a valid two-element array; `pipe` writes exactly
        // two file descriptors into it.
        let rc = unsafe { libc::pipe(fds.as_mut_ptr()) };
        if rc != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(Self {
            read_fd: fds[0],
            write_fd: fds[1],
        })
    }

    /// Close the read end, ignoring errors (best-effort cleanup).
    fn close_read(&self) {
        unsafe { libc::close(self.read_fd) };
    }

    /// Close the write end, ignoring errors (best-effort cleanup).
    fn close_write(&self) {
        unsafe { libc::close(self.write_fd) };
    }

    /// Set `FD_CLOEXEC` on both ends of the pipe so they are not inherited by
    /// unrelated child processes spawned later (e.g. via `posix_spawnp` without
    /// explicit file actions).
    ///
    /// We do **not** use `POSIX_SPAWN_CLOEXEC_DEFAULT` because on macOS that
    /// flag closes all fds *before* the file actions run, which would close the
    /// pipe write-ends before `adddup2` can redirect them to fd 1/2.
    fn set_cloexec(&self) {
        unsafe {
            libc::fcntl(self.read_fd, libc::F_SETFD, libc::FD_CLOEXEC);
            libc::fcntl(self.write_fd, libc::F_SETFD, libc::FD_CLOEXEC);
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Internal helpers — signal forwarding
// ─────────────────────────────────────────────────────────────────────────────

/// Signal handler that forwards the received signal to the child PID stored in
/// [`CHILD_PID`].
///
/// # Safety
///
/// This function is called from a signal handler context.  Only async-signal-
/// safe operations are used: `AtomicI32::load` and `libc::kill`.
extern "C" fn forward_signal(sig: c_int) {
    let pid = CHILD_PID.load(Ordering::Relaxed);
    if pid > 0 {
        // SAFETY: `kill` is async-signal-safe.
        unsafe { libc::kill(pid as pid_t, sig) };
    }
}

/// Install `forward_signal` as the handler for SIGINT, SIGTERM, and SIGHUP.
///
/// Returns the previous `sigaction` structs so the caller can restore them
/// after the child exits.
///
/// # Safety
///
/// Must be called from the main thread before spawning the child.
unsafe fn install_signal_forwarders() -> [libc::sigaction; 3] {
    let mut new_action: libc::sigaction = std::mem::zeroed();
    new_action.sa_sigaction = forward_signal as *const () as libc::sighandler_t;
    // SA_RESTART: restart interrupted syscalls automatically.
    new_action.sa_flags = libc::SA_RESTART;
    libc::sigemptyset(&mut new_action.sa_mask);

    let mut old_actions: [libc::sigaction; 3] = [std::mem::zeroed(); 3];
    let signals = [SIGINT, SIGTERM, SIGHUP];
    for (i, &sig) in signals.iter().enumerate() {
        libc::sigaction(sig, &new_action, &mut old_actions[i]);
    }
    old_actions
}

/// Restore the signal handlers saved by [`install_signal_forwarders`].
///
/// # Safety
///
/// Must be called with the same `old_actions` array returned by
/// `install_signal_forwarders`.
unsafe fn restore_signal_handlers(old_actions: &[libc::sigaction; 3]) {
    let signals = [SIGINT, SIGTERM, SIGHUP];
    for (i, &sig) in signals.iter().enumerate() {
        libc::sigaction(sig, &old_actions[i], std::ptr::null_mut());
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Internal helpers — kill escalation
// ─────────────────────────────────────────────────────────────────────────────

/// Send SIGTERM to `pid`, wait up to `grace_secs`, then send SIGKILL.
///
/// Returns when the child has exited (or after SIGKILL is sent).
fn kill_with_escalation(pid: pid_t, grace_secs: u64) {
    // SAFETY: `kill` is a simple syscall; `pid` is a valid child PID.
    unsafe { libc::kill(pid, SIGTERM) };

    let deadline = Instant::now() + Duration::from_secs(grace_secs);
    loop {
        // SAFETY: `waitpid` with WNOHANG is safe; we own the child.
        let rc = unsafe { libc::waitpid(pid, std::ptr::null_mut(), WNOHANG) };
        if rc == pid || rc < 0 {
            // Child exited or already reaped.
            return;
        }
        if Instant::now() >= deadline {
            break;
        }
        std::thread::sleep(Duration::from_millis(POLL_INTERVAL_MS));
    }

    // Grace period expired — escalate to SIGKILL.
    unsafe { libc::kill(pid, SIGKILL) };
    // Reap the zombie.
    unsafe { libc::waitpid(pid, std::ptr::null_mut(), 0) };
}

// ─────────────────────────────────────────────────────────────────────────────
// Internal helpers — waitpid result decoding
// ─────────────────────────────────────────────────────────────────────────────

/// Decode a `waitpid` status word into a process exit code following the
/// secretsh convention:
///
/// - Normal exit → child exit code (0–255)
/// - Killed by signal N → 128 + N
fn decode_wait_status(status: c_int) -> i32 {
    if libc::WIFEXITED(status) {
        libc::WEXITSTATUS(status)
    } else if libc::WIFSIGNALED(status) {
        128 + libc::WTERMSIG(status)
    } else {
        // Stopped / continued — treat as still running; caller handles.
        -1
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Internal helpers — pipe reader thread
// ─────────────────────────────────────────────────────────────────────────────

/// Shared state produced by a pipe-reader thread.
#[derive(Default)]
struct ReaderState {
    /// Accumulated bytes read from the pipe.
    buf: Vec<u8>,
    /// Set to `true` when the byte limit was exceeded.
    limit_exceeded: bool,
    /// Set to `true` when the pipe reached EOF (write-end closed by child).
    done: bool,
}

/// Spawn a thread that reads from `read_fd` until EOF or `limit` bytes.
///
/// The thread takes ownership of `read_fd` and closes it when done.
/// The shared [`ReaderState`] is updated atomically via a `Mutex`.
fn spawn_reader_thread(
    read_fd: c_int,
    limit: usize,
    state: Arc<Mutex<ReaderState>>,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        // SAFETY: we take ownership of `read_fd`; no other thread uses it.
        let mut file =
            unsafe { <std::fs::File as std::os::unix::io::FromRawFd>::from_raw_fd(read_fd) };
        let mut chunk = vec![0u8; READ_CHUNK];

        loop {
            match file.read(&mut chunk) {
                Ok(0) => {
                    // EOF — write-end was closed.
                    let mut st = state.lock().unwrap();
                    st.done = true;
                    break;
                }
                Ok(n) => {
                    let mut st = state.lock().unwrap();
                    let remaining = limit.saturating_sub(st.buf.len());
                    if remaining == 0 {
                        // Already at limit — discard further bytes.
                        st.limit_exceeded = true;
                        st.done = true;
                        break;
                    }
                    let to_take = n.min(remaining);
                    st.buf.extend_from_slice(&chunk[..to_take]);
                    if to_take < n {
                        st.limit_exceeded = true;
                        st.done = true;
                        break;
                    }
                }
                Err(_) => {
                    // Read error (e.g. EBADF after child exit) — treat as EOF.
                    let mut st = state.lock().unwrap();
                    st.done = true;
                    break;
                }
            }
        }
        // `file` is dropped here, closing `read_fd`.
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Public API
// ─────────────────────────────────────────────────────────────────────────────

/// Spawn a child process with the given `argv`, collect its output, and return
/// a [`SpawnResult`] with redacted stdout/stderr.
///
/// # Arguments
///
/// * `argv` — The argument vector.  Each element is a `Zeroizing<Vec<u8>>`
///   containing a null-terminated C string (no interior NUL bytes).  The first
///   element is used as the executable name for `PATH` resolution via
///   `posix_spawnp`.
/// * `redactor` — Scans stdout and stderr for secret values and replaces them
///   with bracketed labels before the output is returned.
/// * `config` — Timeout and output-size limits.
///
/// # Errors
///
/// | Error variant              | Condition                                      |
/// |----------------------------|------------------------------------------------|
/// | `SpawnError::NotFound`     | Binary not found on `PATH` (errno `ENOENT`)    |
/// | `SpawnError::NotExecutable`| Binary not executable (errno `EACCES`/`ENOEXEC`)|
/// | `SpawnError::ForkExecFailed`| Any other `posix_spawnp` failure              |
///
/// Timeout and output-limit kills are **not** errors — they are reflected in
/// `SpawnResult::exit_code = 124` and `SpawnResult::timed_out = true`.
///
/// # Panics
///
/// Panics if `argv` is empty.
pub fn spawn_child(
    argv: Vec<Zeroizing<Vec<u8>>>,
    redactor: &Redactor,
    config: &SpawnConfig,
) -> Result<SpawnResult, SecretshError> {
    assert!(!argv.is_empty(), "spawn_child: argv must not be empty");

    // ── 1. Extract the command name for error messages (before zeroizing) ────
    //
    // The first argv element is null-terminated; strip the trailing NUL for
    // display purposes.  Run the result through the redactor so that a secret
    // value substituted into argv[0] (e.g. `{{KEY}}` used as the executable
    // name) is never exposed in the error message.
    let command_name: String = {
        let raw = argv[0].as_slice();
        let without_nul = raw.strip_suffix(b"\0").unwrap_or(raw);
        let display = String::from_utf8_lossy(without_nul).into_owned();
        redactor.redact_str(&display)
    };

    // ── 2. Build CString argv ─────────────────────────────────────────────────
    //
    // Each `Zeroizing<Vec<u8>>` is already null-terminated (per the contract).
    // `CString::from_vec_with_nul` validates that there are no interior NULs
    // and that the last byte is NUL.
    //
    // We wrap each CString in a `ZeroizingCString` so the heap allocation is
    // overwritten with zeroes before being freed.
    let mut cstrings: Vec<ZeroizingCString> = Vec::with_capacity(argv.len());
    for arg in &argv {
        let bytes = arg.as_slice().to_vec();
        let cs = CString::from_vec_with_nul(bytes).map_err(|_| {
            SecretshError::Spawn(SpawnError::ForkExecFailed {
                command: command_name.clone(),
                reason: "argv element contains interior NUL byte".into(),
            })
        })?;
        cstrings.push(ZeroizingCString::new(cs));
    }

    // Build the null-terminated pointer array required by `posix_spawnp`.
    // The pointers borrow from `cstrings`; they must not outlive it.
    let mut argv_ptrs: Vec<*const c_char> = cstrings.iter().map(|cs| cs.as_ptr()).collect();
    argv_ptrs.push(std::ptr::null()); // null terminator

    // ── 3. Create stdout and stderr pipes ─────────────────────────────────────
    let stdout_pipe = Pipe::new()?;
    let stderr_pipe = Pipe::new()?;

    // Mark all four pipe fds as close-on-exec so they are not accidentally
    // inherited by unrelated children spawned later.  The file actions below
    // will dup2 the write-ends to fd 1/2 in *this* child (dup2 clears
    // FD_CLOEXEC on the destination fd), so the child will still have valid
    // stdout/stderr.
    stdout_pipe.set_cloexec();
    stderr_pipe.set_cloexec();

    // ── 4. Set up posix_spawn_file_actions ────────────────────────────────────
    //
    // In the child:
    //   a) Close the read ends (they belong to the parent).
    //   b) Dup the write ends to fd 1 (stdout) and fd 2 (stderr).
    //   c) Close the original write-end fds (now redundant after dup2).
    //
    // SAFETY: All `posix_spawn_file_actions_*` calls operate on a properly
    // initialised `posix_spawn_file_actions_t` value.
    let mut file_actions: libc::posix_spawn_file_actions_t = unsafe { std::mem::zeroed() };
    unsafe {
        let rc = libc::posix_spawn_file_actions_init(&mut file_actions);
        if rc != 0 {
            return Err(std::io::Error::from_raw_os_error(rc).into());
        }

        // Close read ends in child.
        libc::posix_spawn_file_actions_addclose(&mut file_actions, stdout_pipe.read_fd);
        libc::posix_spawn_file_actions_addclose(&mut file_actions, stderr_pipe.read_fd);

        // Dup write ends to fd 1 and fd 2.
        libc::posix_spawn_file_actions_adddup2(&mut file_actions, stdout_pipe.write_fd, 1);
        libc::posix_spawn_file_actions_adddup2(&mut file_actions, stderr_pipe.write_fd, 2);

        // Close the original write-end fds (now redundant).
        libc::posix_spawn_file_actions_addclose(&mut file_actions, stdout_pipe.write_fd);
        libc::posix_spawn_file_actions_addclose(&mut file_actions, stderr_pipe.write_fd);
    }

    // ── 5. Set up posix_spawnattr ─────────────────────────────────────────────
    //
    // We intentionally do NOT set `POSIX_SPAWN_CLOEXEC_DEFAULT` here.
    //
    // Although that Apple-specific flag sounds ideal for preventing FD leaks,
    // it closes *all* file descriptors in the child **before** the file actions
    // run.  This means the pipe write-ends are closed before `adddup2` can
    // redirect them to fd 1/2, leaving the child with no stdout/stderr and
    // causing the parent's `read()` to block forever.
    //
    // Instead we set `FD_CLOEXEC` on the pipe fds in the parent (see
    // `Pipe::set_cloexec`) so they are automatically closed in any *other*
    // child processes spawned later.  The file actions in the current spawn
    // explicitly dup2 the write-ends to fd 1/2 (which clears `FD_CLOEXEC` on
    // the new fd) and then close the originals.
    let mut spawnattr: libc::posix_spawnattr_t = unsafe { std::mem::zeroed() };
    unsafe {
        let rc = libc::posix_spawnattr_init(&mut spawnattr);
        if rc != 0 {
            libc::posix_spawn_file_actions_destroy(&mut file_actions);
            return Err(std::io::Error::from_raw_os_error(rc).into());
        }
        // No flags — default behaviour is sufficient.
    }

    // ── 6. Call posix_spawnp ──────────────────────────────────────────────────
    let mut child_pid: pid_t = 0;

    // `posix_spawnp` resolves the executable via PATH when the path contains
    // no `/`.  We pass `argv_ptrs[0]` (the command name) as the `file`
    // argument and `std::ptr::null()` for `envp` to inherit the parent's
    // environment.
    //
    // SAFETY:
    // - `argv_ptrs` is a valid null-terminated array of C strings.
    // - `file_actions` and `spawnattr` are properly initialised.
    // - `child_pid` is a valid output pointer.
    let spawn_rc = unsafe {
        libc::posix_spawnp(
            &mut child_pid,
            argv_ptrs[0], // file (PATH-resolved)
            &file_actions,
            &spawnattr,
            argv_ptrs.as_ptr() as *const *mut c_char,
            std::ptr::null(), // inherit parent environment
        )
    };

    // Destroy the spawn attributes — no longer needed.
    unsafe {
        libc::posix_spawn_file_actions_destroy(&mut file_actions);
        libc::posix_spawnattr_destroy(&mut spawnattr);
    }

    // ── 7. Handle posix_spawnp errors ────────────────────────────────────────
    if spawn_rc != 0 {
        // Close all pipe ends — child never started.
        stdout_pipe.close_read();
        stdout_pipe.close_write();
        stderr_pipe.close_read();
        stderr_pipe.close_write();

        // Zeroize argv before returning the error.
        drop(cstrings);
        drop(argv);

        return Err(SecretshError::Spawn(match spawn_rc {
            ENOENT => SpawnError::NotFound {
                command: command_name,
            },
            EACCES | ENOEXEC => SpawnError::NotExecutable {
                command: command_name,
            },
            _ => SpawnError::ForkExecFailed {
                command: command_name,
                reason: std::io::Error::from_raw_os_error(spawn_rc).to_string(),
            },
        }));
    }

    // ── 8. Parent post-spawn ──────────────────────────────────────────────────

    // Close the write ends in the parent — the child owns them now.
    stdout_pipe.close_write();
    stderr_pipe.close_write();

    // Zeroize the CString argv immediately — secrets are in the child now.
    drop(cstrings);
    drop(argv);

    // ── 9. Install signal forwarding handlers ─────────────────────────────────
    CHILD_PID.store(child_pid as i32, Ordering::Relaxed);
    // SAFETY: called from the main thread; no concurrent signal handler
    // installation is happening.
    let old_signal_handlers = unsafe { install_signal_forwarders() };

    // ── 10. Spawn reader threads ──────────────────────────────────────────────
    //
    // We read stdout and stderr concurrently on separate threads to prevent
    // pipe-buffer deadlock: if the child fills one pipe while the parent is
    // blocking on the other, both sides deadlock.
    let stdout_state = Arc::new(Mutex::new(ReaderState::default()));
    let stderr_state = Arc::new(Mutex::new(ReaderState::default()));

    let stdout_thread = spawn_reader_thread(
        stdout_pipe.read_fd,
        config.max_output_bytes,
        Arc::clone(&stdout_state),
    );
    let stderr_thread = spawn_reader_thread(
        stderr_pipe.read_fd,
        config.max_stderr_bytes,
        Arc::clone(&stderr_state),
    );

    // ── 11. Wait loop ─────────────────────────────────────────────────────────
    //
    // Poll `waitpid(WNOHANG)` every `POLL_INTERVAL_MS` milliseconds.
    // Simultaneously check the timeout deadline and the output-size limits.
    let deadline = Instant::now() + Duration::from_secs(config.timeout_secs);
    let mut timed_out = false;
    let mut limit_exceeded = false;
    let mut final_status: c_int = 0;
    let exit_code: i32;

    'wait: loop {
        // ── Check output limits first ─────────────────────────────────────
        //
        // We check limits *before* waitpid so that if the child exits due to
        // SIGPIPE (because the reader thread stopped draining the pipe after
        // hitting the limit), we still override the exit code to 124 rather
        // than propagating the signal exit code.
        {
            let out_exceeded = stdout_state.lock().unwrap().limit_exceeded;
            let err_exceeded = stderr_state.lock().unwrap().limit_exceeded;
            if out_exceeded || err_exceeded {
                limit_exceeded = true;
                // Child may already be dead (SIGPIPE) or still running.
                // kill_with_escalation handles both cases gracefully.
                kill_with_escalation(child_pid, SIGKILL_GRACE_SECS);
                exit_code = EXIT_TIMEOUT;
                break 'wait;
            }
        }

        // ── Check if child has exited ─────────────────────────────────────
        let rc = unsafe { libc::waitpid(child_pid, &mut final_status, WNOHANG) };

        if rc == child_pid {
            // Child exited — check limits one final time in case the child
            // exited due to SIGPIPE after the reader thread hit the limit but
            // before the limit check above ran.
            let out_exceeded = stdout_state.lock().unwrap().limit_exceeded;
            let err_exceeded = stderr_state.lock().unwrap().limit_exceeded;
            if out_exceeded || err_exceeded {
                limit_exceeded = true;
                exit_code = EXIT_TIMEOUT;
            } else {
                exit_code = decode_wait_status(final_status);
            }
            break 'wait;
        } else if rc < 0 {
            // waitpid error (e.g. ECHILD — child already reaped).
            exit_code = 1;
            break 'wait;
        }
        // rc == 0 → child still running.

        // ── Check timeout ─────────────────────────────────────────────────
        if Instant::now() >= deadline {
            timed_out = true;
            kill_with_escalation(child_pid, SIGKILL_GRACE_SECS);
            exit_code = EXIT_TIMEOUT;
            break 'wait;
        }

        std::thread::sleep(Duration::from_millis(POLL_INTERVAL_MS));
    }

    // ── 12. Clear child PID and restore signal handlers ───────────────────────
    CHILD_PID.store(0, Ordering::Relaxed);
    // SAFETY: restoring previously-saved sigaction structs.
    unsafe { restore_signal_handlers(&old_signal_handlers) };

    // ── 13. Join reader threads ───────────────────────────────────────────────
    //
    // The child has exited (or been killed), so the write-ends of both pipes
    // are closed.  The reader threads will see EOF and terminate shortly.
    let _ = stdout_thread.join();
    let _ = stderr_thread.join();

    // ── 14. Extract output buffers ────────────────────────────────────────────
    let stdout_bytes = {
        let st = stdout_state.lock().unwrap();
        st.buf.clone()
    };
    let stderr_bytes = {
        let st = stderr_state.lock().unwrap();
        st.buf.clone()
    };

    // ── 15. Redact output ─────────────────────────────────────────────────────
    let stdout_redacted = redactor.redact_str(&String::from_utf8_lossy(&stdout_bytes));
    let stderr_redacted = redactor.redact_str(&String::from_utf8_lossy(&stderr_bytes));

    // ── 16. Adjust exit code for limit-exceeded ───────────────────────────────
    //
    // `timed_out` already sets exit_code = 124 above.  For limit_exceeded we
    // do the same (already set), but we distinguish the two in the result via
    // `timed_out` (limit-exceeded is not surfaced as a separate field — the
    // caller can detect it via exit_code == 124 and timed_out == false).
    let _ = limit_exceeded; // used above for kill; no separate field needed

    Ok(SpawnResult {
        stdout: stdout_redacted,
        stderr: stderr_redacted,
        exit_code,
        timed_out,
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Helpers ───────────────────────────────────────────────────────────────

    /// Build a `Zeroizing<Vec<u8>>` from a string slice (null-terminated).
    fn arg(s: &str) -> Zeroizing<Vec<u8>> {
        let mut v = s.as_bytes().to_vec();
        v.push(0); // null terminator
        Zeroizing::new(v)
    }

    /// Build a no-op [`Redactor`] (no secrets to redact).
    fn noop_redactor() -> Redactor {
        Redactor::new(&[]).expect("empty Redactor should always succeed")
    }

    // ── SpawnConfig::default ──────────────────────────────────────────────────

    #[test]
    fn spawn_config_default_values() {
        let cfg = SpawnConfig::default();
        assert_eq!(cfg.timeout_secs, 300, "default timeout should be 300 s");
        assert_eq!(
            cfg.max_output_bytes,
            50 * 1024 * 1024,
            "default max_output_bytes should be 50 MiB"
        );
        assert_eq!(
            cfg.max_stderr_bytes,
            1024 * 1024,
            "default max_stderr_bytes should be 1 MiB"
        );
    }

    // ── echo hello ────────────────────────────────────────────────────────────

    #[test]
    fn echo_hello_stdout() {
        let argv = vec![arg("echo"), arg("hello")];
        let redactor = noop_redactor();
        let config = SpawnConfig::default();

        let result = spawn_child(argv, &redactor, &config).expect("echo hello should succeed");

        assert_eq!(result.exit_code, 0);
        assert!(!result.timed_out);
        assert_eq!(result.stdout.trim(), "hello");
        assert!(result.stderr.is_empty());
    }

    // ── exit code passthrough ─────────────────────────────────────────────────

    #[test]
    fn exit_code_passthrough() {
        // `false` exits with code 1.
        let argv = vec![arg("false")];
        let redactor = noop_redactor();
        let config = SpawnConfig::default();

        let result =
            spawn_child(argv, &redactor, &config).expect("false should spawn successfully");

        assert_eq!(result.exit_code, 1);
        assert!(!result.timed_out);
    }

    // ── command not found ─────────────────────────────────────────────────────

    #[test]
    fn command_not_found_returns_error() {
        let argv = vec![arg("__secretsh_nonexistent_binary_xyz__")];
        let redactor = noop_redactor();
        let config = SpawnConfig::default();

        let err = spawn_child(argv, &redactor, &config)
            .expect_err("nonexistent binary should return an error");

        assert!(
            matches!(err, SecretshError::Spawn(SpawnError::NotFound { .. })),
            "expected SpawnError::NotFound, got: {err:?}"
        );
        assert_eq!(err.exit_code(), 127);
    }

    // ── secret must not appear in command-not-found error message ────────────

    #[test]
    fn secret_value_in_argv0_is_redacted_in_not_found_error() {
        // Simulates `secretsh run -- "{{MY_KEY}}"` where MY_KEY="s3cr3t_cmd".
        // After substitution argv[0] = "s3cr3t_cmd", which is not on PATH.
        // The error message must NOT contain "s3cr3t_cmd".
        let secret = b"s3cr3t_cmd";
        let redactor = Redactor::new(&[("MY_KEY", secret)]).expect("Redactor::new should succeed");
        let argv = vec![arg("s3cr3t_cmd")];
        let config = SpawnConfig::default();

        let err = spawn_child(argv, &redactor, &config)
            .expect_err("nonexistent binary should return an error");

        assert!(
            matches!(err, SecretshError::Spawn(SpawnError::NotFound { .. })),
            "expected SpawnError::NotFound, got: {err:?}"
        );
        let msg = err.to_string();
        assert!(
            !msg.contains("s3cr3t_cmd"),
            "error message must not contain the secret value, got: {msg:?}"
        );
        assert!(
            msg.contains("[REDACTED_MY_KEY]"),
            "error message should contain the redaction label, got: {msg:?}"
        );
    }

    // ── stderr capture ────────────────────────────────────────────────────────

    #[test]
    fn stderr_is_captured() {
        // Write to stderr via sh -c.
        let argv = vec![arg("sh"), arg("-c"), arg("echo error_output >&2")];
        let redactor = noop_redactor();
        let config = SpawnConfig::default();

        let result = spawn_child(argv, &redactor, &config).expect("sh -c should succeed");

        assert_eq!(result.exit_code, 0);
        assert!(result.stdout.is_empty() || result.stdout.trim().is_empty());
        assert!(
            result.stderr.contains("error_output"),
            "stderr should contain 'error_output', got: {:?}",
            result.stderr
        );
    }

    // ── redaction applied to stdout ───────────────────────────────────────────

    #[test]
    fn secret_in_stdout_is_redacted() {
        let secret = b"supersecret42";
        let redactor = Redactor::new(&[("MY_KEY", secret)]).expect("Redactor::new should succeed");

        // `echo supersecret42` will print the secret to stdout.
        let argv = vec![arg("echo"), arg("supersecret42")];
        let config = SpawnConfig::default();

        let result = spawn_child(argv, &redactor, &config).expect("echo should succeed");

        assert_eq!(result.exit_code, 0);
        assert!(
            !result.stdout.contains("supersecret42"),
            "stdout should not contain the raw secret"
        );
        assert!(
            result.stdout.contains("[REDACTED_MY_KEY]"),
            "stdout should contain the redaction label, got: {:?}",
            result.stdout
        );
    }

    // ── timeout ───────────────────────────────────────────────────────────────

    #[test]
    fn timeout_kills_child_and_sets_flag() {
        // `sleep 60` will be killed by the 1-second timeout.
        let argv = vec![arg("sleep"), arg("60")];
        let redactor = noop_redactor();
        let config = SpawnConfig {
            timeout_secs: 1,
            ..SpawnConfig::default()
        };

        let result = spawn_child(argv, &redactor, &config)
            .expect("spawn should succeed even when child is killed");

        assert!(result.timed_out, "timed_out should be true");
        assert_eq!(result.exit_code, 124, "exit_code should be 124 on timeout");
    }

    // ── output limit ─────────────────────────────────────────────────────────

    #[test]
    fn output_limit_kills_child() {
        // Generate a large amount of output; limit to 1 KiB.
        // `yes` writes "y\n" in an infinite loop.
        let argv = vec![arg("yes")];
        let redactor = noop_redactor();
        let config = SpawnConfig {
            max_output_bytes: 1024,
            timeout_secs: 10,
            ..SpawnConfig::default()
        };

        let result = spawn_child(argv, &redactor, &config)
            .expect("spawn should succeed even when output limit is hit");

        assert_eq!(
            result.exit_code, 124,
            "exit_code should be 124 when output limit exceeded"
        );
        assert!(
            result.stdout.len() <= 1024,
            "stdout should be at most 1024 bytes, got {}",
            result.stdout.len()
        );
    }

    // ── multiple argv elements ────────────────────────────────────────────────

    #[test]
    fn multiple_args_passed_correctly() {
        // `printf '%s %s\n' foo bar` should print "foo bar".
        let argv = vec![arg("printf"), arg("%s %s\\n"), arg("foo"), arg("bar")];
        let redactor = noop_redactor();
        let config = SpawnConfig::default();

        let result = spawn_child(argv, &redactor, &config).expect("printf should succeed");

        assert_eq!(result.exit_code, 0);
        assert!(
            result.stdout.contains("foo") && result.stdout.contains("bar"),
            "stdout should contain both args, got: {:?}",
            result.stdout
        );
    }

    // ── secret redacted in NotExecutable error ────────────────────────────────

    #[test]
    fn secret_value_in_argv0_is_redacted_in_not_executable_error() {
        // Create a non-executable file whose name IS the secret value, then
        // try to spawn it.  The error must not expose the secret.
        use std::fs;
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().expect("tempdir");
        let secret_str = "s3cr3t_noexec";
        let path = dir.path().join(secret_str);
        fs::write(&path, b"not a script").expect("write");
        // Explicitly remove execute permission.
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).expect("set_permissions");

        let secret = secret_str.as_bytes();
        let redactor = Redactor::new(&[("MY_KEY", secret)]).expect("Redactor::new should succeed");
        let argv = vec![arg(path.to_str().unwrap())];
        let config = SpawnConfig::default();

        let err = spawn_child(argv, &redactor, &config)
            .expect_err("non-executable file should return an error");

        assert!(
            matches!(
                err,
                SecretshError::Spawn(SpawnError::NotExecutable { .. })
                    | SecretshError::Spawn(SpawnError::NotFound { .. })
            ),
            "expected NotExecutable or NotFound, got: {err:?}"
        );
        let msg = err.to_string();
        assert!(
            !msg.contains(secret_str),
            "error message must not contain the secret value, got: {msg:?}"
        );
    }

    // ── secret redacted in ForkExecFailed error ───────────────────────────────

    #[test]
    fn secret_value_in_argv0_is_redacted_in_fork_exec_failed_error() {
        // Trigger a ForkExecFailed by passing a path with an interior NUL byte,
        // which CString::from_vec_with_nul rejects before reaching posix_spawnp.
        // The command name extracted before the CString conversion must still
        // be redacted.
        let secret = b"s3cr3t_fork";
        let redactor = Redactor::new(&[("MY_KEY", secret)]).expect("Redactor::new should succeed");

        // Build argv[0] = "s3cr3t_fork\0" (valid null-terminated).
        // Then smuggle an interior NUL into argv[1] to trigger ForkExecFailed.
        let mut bad_arg = b"arg\0with_nul".to_vec();
        bad_arg.push(0); // second NUL so from_vec_with_nul sees interior NUL
                         // Actually from_vec_with_nul requires exactly one trailing NUL.
                         // Pass a vec that has NUL in the middle: b"bad\0arg\0"
        let interior_nul_arg = Zeroizing::new(b"bad\0arg\0".to_vec());

        let argv = vec![arg("s3cr3t_fork"), interior_nul_arg];
        let config = SpawnConfig::default();

        let err =
            spawn_child(argv, &redactor, &config).expect_err("interior NUL should return an error");

        let msg = err.to_string();
        assert!(
            !msg.contains("s3cr3t_fork"),
            "ForkExecFailed error must not contain the secret value, got: {msg:?}"
        );
    }

    // ── secret redacted in argv0 with trailing literal suffix ─────────────────

    #[test]
    fn secret_value_in_argv0_with_suffix_is_redacted_in_error() {
        // Simulates `secretsh run -- "{{MY_KEY}}==literal"` where
        // MY_KEY="s3cr3t_pfx".  After substitution argv[0] = "s3cr3t_pfx==literal",
        // which is not on PATH.  Neither "s3cr3t_pfx" nor the resolved
        // "s3cr3t_pfx==literal" must appear in the error message.
        let secret = b"s3cr3t_pfx";
        let redactor = Redactor::new(&[("MY_KEY", secret)]).expect("Redactor::new should succeed");
        let argv = vec![arg("s3cr3t_pfx==literal")];
        let config = SpawnConfig::default();

        let err = spawn_child(argv, &redactor, &config)
            .expect_err("nonexistent binary should return an error");

        let msg = err.to_string();
        assert!(
            !msg.contains("s3cr3t_pfx"),
            "error message must not contain the secret value, got: {msg:?}"
        );
        assert!(
            msg.contains("[REDACTED_MY_KEY]"),
            "error message should contain the redaction label, got: {msg:?}"
        );
    }

    // ── redaction oracle: matching literal also gets redacted ─────────────────

    #[test]
    fn secret_value_appearing_twice_in_output_both_redacted() {
        // This is the oracle-defence test: if secret="development" and output
        // is "development==development", BOTH occurrences must be redacted.
        // An AI probing `echo {{KEY}}==development` gets
        // "[REDACTED_K]==[REDACTED_K]" regardless of whether the guess matched,
        // because the redactor finds every byte-level occurrence of the secret.
        // The *wrong* value ("wrongguess") does NOT get redacted.
        let secret = b"development";
        let redactor = Redactor::new(&[("APP_ENV", secret)]).expect("Redactor::new should succeed");

        // Simulate child output when guess matches: "development==development"
        let output_match = "development==development";
        let redacted_match = redactor.redact_str(output_match);
        assert_eq!(
            redacted_match, "[REDACTED_APP_ENV]==[REDACTED_APP_ENV]",
            "both occurrences of the secret must be redacted when guess matches"
        );

        // Simulate child output when guess does NOT match: "development==wrongguess"
        let output_nomatch = "development==wrongguess";
        let redacted_nomatch = redactor.redact_str(output_nomatch);
        assert_eq!(
            redacted_nomatch, "[REDACTED_APP_ENV]==wrongguess",
            "only the secret occurrence is redacted when guess does not match"
        );

        // Confirm: an AI cannot distinguish match from no-match via redaction
        // alone — both outputs contain "[REDACTED_APP_ENV]==" but the match
        // case shows a second label while no-match shows the literal suffix.
        // This means the oracle still leaks one bit of information (whether
        // the suffix was also redacted), which is a known design limitation
        // documented in docs/threat-model.md.
    }

    // ── redaction applied to stderr ───────────────────────────────────────────

    #[test]
    fn secret_in_stderr_is_redacted() {
        let secret = b"stderr_s3cr3t";
        let redactor = Redactor::new(&[("ERR_KEY", secret)]).expect("Redactor::new should succeed");

        // Write secret to stderr via sh -c.
        let argv = vec![arg("sh"), arg("-c"), arg("echo stderr_s3cr3t >&2")];
        let config = SpawnConfig::default();

        let result = spawn_child(argv, &redactor, &config).expect("sh -c should succeed");

        assert_eq!(result.exit_code, 0);
        assert!(
            !result.stderr.contains("stderr_s3cr3t"),
            "stderr must not contain the raw secret, got: {:?}",
            result.stderr
        );
        assert!(
            result.stderr.contains("[REDACTED_ERR_KEY]"),
            "stderr should contain the redaction label, got: {:?}",
            result.stderr
        );
    }

    // ── true exits 0 ─────────────────────────────────────────────────────────

    #[test]
    fn true_exits_zero() {
        let argv = vec![arg("true")];
        let redactor = noop_redactor();
        let config = SpawnConfig::default();

        let result = spawn_child(argv, &redactor, &config).expect("true should succeed");

        assert_eq!(result.exit_code, 0);
        assert!(!result.timed_out);
        assert!(result.stdout.is_empty());
        assert!(result.stderr.is_empty());
    }
}
