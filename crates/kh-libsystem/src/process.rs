//! Process control: `exit` / `_exit` / bottle probe.

use core::ffi::c_int;

use crate::KH_BOTTLE_MARK_VALUE;
use crate::sys::{self, SYS_EXIT};
use crate::trace;

/// C `_exit` → nlist `__exit` (Rust name avoids `clippy::used_underscore_items`).
#[unsafe(export_name = "_exit")]
pub unsafe extern "C" fn exit_now(status: c_int) -> ! {
    trace::note_size(b"_exit", usize::try_from(status.max(0)).unwrap_or(0));
    let code = u64::from(status.cast_unsigned());
    // SAFETY: Darwin exit.
    let _ = unsafe { sys::syscall3(SYS_EXIT, code, 0, 0) };
    loop {
        core::hint::spin_loop();
    }
}

/// C `exit` → nlist `_exit` (no atexit handlers yet).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn exit(status: c_int) -> ! {
    trace::note_size(b"exit", usize::try_from(status.max(0)).unwrap_or(0));
    // SAFETY: forward to Darwin `_exit`.
    unsafe {
        exit_now(status);
    }
}

/// C `atexit` → nlist `_atexit` (register ignored; handlers not run on exit).
///
/// Apple `git init` calls this once; a hard missing trampoline aborts with 127.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn atexit(_func: Option<unsafe extern "C" fn()>) -> c_int {
    0
}

/// Smoke probe → nlist `_kh_bottle_mark` (returns **77**).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kh_bottle_mark() -> c_int {
    trace::note(b"[kh-libsystem] kh_bottle_mark() -> 77\n");
    KH_BOTTLE_MARK_VALUE
}

/// C `abort` → nlist `_abort` (curl G1; exit 134 ≈ SIGABRT).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn abort() -> ! {
    trace::note(b"[kh-libsystem] abort()\n");
    // SAFETY: never returns.
    unsafe {
        exit_now(134);
    }
}
