//! Darwin `___error` — process-global errno cell (TLS later).
//!
//! Guests assign through the pointer (`errno = 0` → `*__error() = 0`). The
//! cell is the single source of truth; never overwrite it on `__error()` entry
//! or direct writes are lost (classic false ENOENT after `readdir` EOF).

use core::ffi::c_int;

struct ErrnoCell {
    value: core::cell::UnsafeCell<c_int>,
}

// SAFETY: single static errno cell for scaffold guests.
unsafe impl Sync for ErrnoCell {}

static ERRNO_CELL: ErrnoCell = ErrnoCell {
    value: core::cell::UnsafeCell::new(0),
};

/// Stores a positive errno for C `errno` / `*__error()`.
#[inline]
pub(crate) fn set_errno(err: i32) {
    let v = if err < 0 { err.saturating_neg() } else { err };
    // SAFETY: exclusive static cell.
    unsafe {
        ERRNO_CELL.value.get().write(v);
    }
}

/// Reads the current errno value (for diagnostics / soft paths).
#[inline]
#[allow(dead_code)]
pub(crate) fn get_errno() -> i32 {
    // SAFETY: exclusive static cell.
    unsafe { ERRNO_CELL.value.get().read() }
}

/// `int *__error(void);` → nlist `___error`.
///
/// # Safety
///
/// Returns a stable address; callers may read/write the `int`. Must not clobber
/// an in-place assignment through a previous pointer return.
#[unsafe(export_name = "__error")]
pub unsafe extern "C" fn __error() -> *mut c_int {
    crate::trace::note(b"[kh-libsystem] __error()\n");
    ERRNO_CELL.value.get()
}
