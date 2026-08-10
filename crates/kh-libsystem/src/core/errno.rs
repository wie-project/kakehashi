//! Darwin `___error` — per-thread errno via guest TLS (`TPIDR_EL0`).
//!
//! Guests assign through the pointer (`errno = 0` → `*__error() = 0`). The
//! cell is the single source of truth; never overwrite it on `__error()` entry
//! or direct writes are lost (classic false ENOENT after `readdir` EOF).
//!
//! Layout (must match `kh-runtime::tls`):
//! ```text
//! TPIDR_EL0 → magic u64 | errno i32 | pad | pthread_self u64
//!             | host_tpidr u64 | alt_top u64   (host-owned A1 mirrors)
//! ```
//! When TPIDR is unset or magic mismatches (early boot / real Darwin), fall
//! back to a process-global cell so single-thread scaffolds still work.

use core::ffi::c_int;

/// Freestanding guest TLS magic — keep in sync with `kh-runtime::tls::GUEST_TLS_MAGIC`.
const GUEST_TLS_MAGIC: u64 = 0x4B48_544C_5301;
const GUEST_TLS_ERRNO_OFF: usize = 8;

struct ErrnoCell {
    value: core::cell::UnsafeCell<c_int>,
}

// SAFETY: process-global fallback for threads without guest TLS.
unsafe impl Sync for ErrnoCell {}

static FALLBACK_ERRNO: ErrnoCell = ErrnoCell {
    value: core::cell::UnsafeCell::new(0),
};

#[inline]
fn errno_cell_ptr() -> *mut c_int {
    #[cfg(target_arch = "aarch64")]
    {
        let tpidr = read_tpidr_el0();
        if tpidr != 0 {
            let base = usize::try_from(tpidr).unwrap_or(0);
            if base != 0 {
                // SAFETY: identity-mapped guest TLS when magic matches; otherwise
                // we only read the magic word and fall back.
                let magic =
                    unsafe { core::ptr::with_exposed_provenance::<u64>(base).read_volatile() };
                if magic == GUEST_TLS_MAGIC {
                    return core::ptr::with_exposed_provenance_mut::<c_int>(
                        base.saturating_add(GUEST_TLS_ERRNO_OFF),
                    );
                }
            }
        }
    }
    FALLBACK_ERRNO.value.get()
}

#[cfg(target_arch = "aarch64")]
#[inline]
fn read_tpidr_el0() -> u64 {
    let val: u64;
    // SAFETY: pure register read.
    unsafe {
        core::arch::asm!(
            "mrs {}, tpidr_el0",
            out(reg) val,
            options(nomem, nostack, preserves_flags),
        );
    }
    val
}

/// Stores a positive errno for C `errno` / `*__error()`.
#[inline]
pub(crate) fn set_errno(err: i32) {
    let v = if err < 0 { err.saturating_neg() } else { err };
    // SAFETY: points at this thread's errno cell or process fallback.
    unsafe {
        errno_cell_ptr().write(v);
    }
}

/// Reads the current errno value (for diagnostics / soft paths).
#[inline]
#[allow(dead_code)]
pub(crate) fn get_errno() -> i32 {
    // SAFETY: same as set_errno.
    unsafe { errno_cell_ptr().read() }
}

/// `int *__error(void);` → nlist `___error`.
///
/// # Safety
///
/// Returns a stable address for this thread's errno cell; callers may
/// read/write the `int`. Must not clobber an in-place assignment through a
/// previous pointer return.
#[unsafe(export_name = "__error")]
pub unsafe extern "C" fn __error() -> *mut c_int {
    // Hot path: no stderr spam (was a major cost under multi-thread I/O).
    errno_cell_ptr()
}
