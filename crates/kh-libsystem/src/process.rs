//! Process control: `exit` / `_exit` / bottle probe.

use core::ffi::c_int;

use crate::KH_BOTTLE_MARK_VALUE;
use crate::sys::{self, SYS_EXIT};
use crate::trace;

/// C `_exit` → nlist `__exit`.
#[unsafe(export_name = "_exit")]
pub unsafe extern "C" fn _exit(status: c_int) -> ! {
    trace::note_size(b"_exit", usize::try_from(status.max(0)).unwrap_or(0));
    let code = u64::from(status.cast_unsigned());
    // SAFETY: Darwin exit.
    let _ = unsafe { sys::syscall3(SYS_EXIT, code, 0, 0) };
    loop {
        core::hint::spin_loop();
    }
}

/// C `exit` → nlist `_exit` (no atexit yet).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn exit(status: c_int) -> ! {
    trace::note_size(b"exit", usize::try_from(status.max(0)).unwrap_or(0));
    // SAFETY: forward to `_exit`.
    unsafe {
        _exit(status);
    }
}

/// Smoke probe → nlist `_kh_bottle_mark` (returns **77**).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kh_bottle_mark() -> c_int {
    trace::note(b"[kh-libsystem] kh_bottle_mark() -> 77\n");
    KH_BOTTLE_MARK_VALUE
}
