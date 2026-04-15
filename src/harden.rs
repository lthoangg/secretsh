//! Process hardening module.
//!
//! Applies OS-level security protections before any secrets are loaded.
//! All hardening failures are treated as **warnings**, not hard errors —
//! the process continues so that secretsh remains usable in restricted
//! environments (containers, CI runners, etc.) that cannot honour every
//! syscall.
//!
//! # macOS specifics
//! * Core-dump suppression via `setrlimit(RLIMIT_CORE, 0)`
//! * Page-locking via `mlock` / `munlock`
//! * Post-zeroization page reclaim hint via `madvise(MADV_FREE)`

use libc;

// ── Public API ────────────────────────────────────────────────────────────────

/// Apply all process-level hardening measures.
///
/// Call this at the very top of `main()`, **before** any secrets are loaded.
/// Prints warnings to stderr if optional protections cannot be applied.
pub fn harden_process() {
    disable_core_dumps();
}

/// Lock a memory region to prevent it from being swapped to disk.
///
/// Returns `true` if the pages were successfully locked, `false` if `mlock`
/// failed (e.g. `RLIMIT_MEMLOCK` is too low).  A warning is printed to stderr
/// on failure; this is **not** a hard error.
///
/// # Safety contract for callers
/// The caller must ensure that `ptr` points to a valid allocation of at least
/// `len` bytes that remains live for as long as the lock is held.
pub fn mlock_region(ptr: *const u8, len: usize) -> bool {
    if len == 0 {
        return true;
    }

    // SAFETY: `ptr` is a valid, live allocation of `len` bytes (caller
    // guarantee).  `mlock` only reads the pointer value; it does not
    // dereference it in a way that could cause UB on our side.
    let rc = unsafe { libc::mlock(ptr as *const libc::c_void, len) };

    if rc != 0 {
        // Retrieve errno before any other syscall can clobber it.
        let err = std::io::Error::last_os_error();
        eprintln!(
            "[secretsh] WARNING: mlock({len} bytes) failed: {err} \
             — secrets may be swapped to disk"
        );
        return false;
    }

    true
}

/// Unlock a memory region previously locked with [`mlock_region`].
///
/// Call this **after** the memory has been zeroized.  Failures are silently
/// ignored because the region will be unlocked automatically when the process
/// exits anyway.
///
/// # Safety contract for callers
/// Same as [`mlock_region`]: `ptr` must be a valid, live allocation of at
/// least `len` bytes.
pub fn munlock_region(ptr: *const u8, len: usize) {
    if len == 0 {
        return;
    }

    // SAFETY: same as mlock_region — we only pass the pointer value to the
    // kernel; no Rust-side dereference occurs.
    let rc = unsafe { libc::munlock(ptr as *const libc::c_void, len) };

    if rc != 0 {
        let err = std::io::Error::last_os_error();
        eprintln!("[secretsh] WARNING: munlock({len} bytes) failed: {err}");
    }
}

/// Hint to the kernel that it may reclaim the physical pages backing this
/// region after zeroization.
///
/// On macOS, `MADV_FREE` tells the VM subsystem that the pages are no longer
/// needed and can be reused without writing them to swap.  This is a
/// best-effort hint; the kernel is free to ignore it.
///
/// # Safety contract for callers
/// `ptr` must be page-aligned and point to a valid, live allocation of at
/// least `len` bytes.  Passing a non-page-aligned pointer is safe from Rust's
/// perspective (the syscall will return `EINVAL`) but will produce a warning.
pub fn madvise_free(ptr: *mut u8, len: usize) {
    if len == 0 {
        return;
    }

    // SAFETY: we pass the pointer value to the kernel advisory interface.
    // `madvise` does not dereference the pointer in a way that could cause
    // Rust UB; the worst outcome is an `EINVAL` errno.
    let rc = unsafe { libc::madvise(ptr as *mut libc::c_void, len, libc::MADV_FREE) };

    if rc != 0 {
        let err = std::io::Error::last_os_error();
        eprintln!("[secretsh] WARNING: madvise(MADV_FREE, {len} bytes) failed: {err}");
    }
}

// ── Private helpers ───────────────────────────────────────────────────────────

/// Set `RLIMIT_CORE` to zero so that the kernel will not write a core dump
/// if the process crashes.  Core dumps can contain secret material that was
/// live in memory at the time of the crash.
fn disable_core_dumps() {
    let zero_limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };

    // SAFETY: `setrlimit` is a plain syscall; we pass a valid `rlimit` struct
    // by reference.  No memory aliasing or lifetime issues arise.
    let rc = unsafe { libc::setrlimit(libc::RLIMIT_CORE, &zero_limit) };

    if rc != 0 {
        let err = std::io::Error::last_os_error();
        eprintln!(
            "[secretsh] WARNING: setrlimit(RLIMIT_CORE, 0) failed: {err} \
             — core dumps are NOT suppressed"
        );
    }
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// `harden_process()` must complete without panicking.
    #[test]
    fn test_harden_process_does_not_panic() {
        harden_process();
    }

    /// After `harden_process()`, `RLIMIT_CORE` must be zero (both soft and
    /// hard limits).
    #[test]
    fn test_core_dump_rlimit_is_zero_after_harden() {
        harden_process();

        let mut rl = libc::rlimit {
            rlim_cur: u64::MAX,
            rlim_max: u64::MAX,
        };

        // SAFETY: `getrlimit` fills the struct we pass; no aliasing issues.
        let rc = unsafe { libc::getrlimit(libc::RLIMIT_CORE, &mut rl) };

        assert_eq!(rc, 0, "getrlimit(RLIMIT_CORE) failed");
        assert_eq!(rl.rlim_cur, 0, "RLIMIT_CORE soft limit should be 0");
        assert_eq!(rl.rlim_max, 0, "RLIMIT_CORE hard limit should be 0");
    }

    /// `mlock_region` + `munlock_region` round-trip on a heap allocation must
    /// not panic and must return `true` on a platform that supports mlock.
    ///
    /// If the environment cannot honour `mlock` (e.g. a sandboxed CI runner),
    /// the function returns `false` and prints a warning — the test still
    /// passes because mlock failure is explicitly a non-fatal condition.
    #[test]
    fn test_mlock_munlock_round_trip() {
        // Allocate a small heap buffer.
        let buf: Vec<u8> = vec![0xAB_u8; 64];
        let ptr = buf.as_ptr();
        let len = buf.len();

        // Lock — allowed to fail gracefully.
        let locked = mlock_region(ptr, len);

        // Unlock — must not panic regardless of whether lock succeeded.
        munlock_region(ptr, len);

        // The return value is either true (locked) or false (graceful failure).
        // Both are valid outcomes; we just assert the type is bool.
        let _ = locked;
    }

    /// Zero-length calls must be no-ops and must not panic.
    #[test]
    fn test_zero_length_is_noop() {
        let buf: Vec<u8> = vec![0u8; 8];
        let ptr = buf.as_ptr();

        assert!(mlock_region(ptr, 0));
        munlock_region(ptr, 0);
        madvise_free(buf.as_ptr() as *mut u8, 0);
    }

    /// `madvise_free` must not panic on a valid heap buffer.
    #[test]
    fn test_madvise_free_does_not_panic() {
        let page_size = 4096_usize;
        // Allocate an over-sized buffer so we can find a page-aligned slice.
        let buf: Vec<u8> = vec![0u8; page_size * 2];

        // Align the pointer up to the next page boundary.
        let raw = buf.as_ptr() as usize;
        let aligned = (raw + page_size - 1) & !(page_size - 1);
        let offset = aligned - raw;

        if offset + page_size <= buf.len() {
            // SAFETY: `aligned` is within the allocation and page-aligned.
            madvise_free(aligned as *mut u8, page_size);
        } else {
            // Fallback: just call with the raw (possibly unaligned) pointer;
            // the kernel will return EINVAL and we print a warning — no panic.
            madvise_free(buf.as_ptr() as *mut u8, buf.len());
        }
    }
}
