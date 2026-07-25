//! Darwin `___error` — process-global errno cell (TLS later).

use core::ffi::c_int;
use core::sync::atomic::{AtomicI32, Ordering};

static ERRNO: AtomicI32 = AtomicI32::new(0);

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
    ERRNO.store(v, Ordering::Relaxed);
    // SAFETY: exclusive static cell.
    unsafe {
        ERRNO_CELL.value.get().write(v);
    }
}

/// `int *__error(void);` → nlist `___error`.
///
/// # Safety
///
/// Returns a stable address; callers may read/write the `int`.
#[unsafe(export_name = "__error")]
pub unsafe extern "C" fn __error() -> *mut c_int {
    crate::trace::note(b"[kh-libsystem] __error()\n");
    let p = ERRNO_CELL.value.get();
    let v = ERRNO.load(Ordering::Relaxed);
    // SAFETY: static errno cell.
    unsafe {
        p.write(v);
    }
    p
}
