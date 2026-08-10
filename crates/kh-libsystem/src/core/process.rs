//! Process control: `exit` / `_exit` / bottle probe / progname.

use core::ffi::{c_char, c_int};

use crate::KH_BOTTLE_MARK_VALUE;
use crate::kh_core::sys::{self, SYS_EXIT};
use crate::kh_core::trace;

// ── progname (libtool warning path: `"%s: warning: '%s' has no symbols"`) ────
//
// Darwin exports `char *__progname` (nlist `___progname`) plus get/setprogname.
// Uninitialized __progname → SEGV in freestanding vsnprintf when libtool warns
// about empty .o (Lua `ltests.o` under !LUA_DEBUG). Soft static default.

const PROGNAME_CAP: usize = 64;

/// Mutable basename buffer; `__progname` points here after init / setprogname.
#[allow(static_mut_refs)]
static mut PROGNAME_BUF: [u8; PROGNAME_CAP] = {
    let mut b = [0_u8; PROGNAME_CAP];
    b[0] = b'k';
    b[1] = b'h';
    b[2] = b'-';
    b[3] = b'g';
    b[4] = b'u';
    b[5] = b'e';
    b[6] = b's';
    b[7] = b't';
    b
};

/// C `__progname` → nlist `___progname`.
///
/// Must be a **valid** C string pointer at load (libtool reads it for warnings
/// without calling `getprogname`). Initialized to the soft default buffer.
#[unsafe(export_name = "__progname")]
#[used]
#[allow(non_upper_case_globals, static_mut_refs)]
pub(crate) static mut __progname: *mut c_char =
    core::ptr::addr_of!(PROGNAME_BUF).cast_mut().cast::<c_char>();

/// C `getprogname` → nlist `_getprogname`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn getprogname() -> *const c_char {
    unsafe {
        let p = __progname;
        if p.is_null() {
            core::ptr::addr_of!(PROGNAME_BUF).cast::<c_char>()
        } else {
            p.cast_const()
        }
    }
}

/// C `setprogname` → nlist `_setprogname` (stores basename of `name` into soft buf).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn setprogname(name: *const c_char) {
    if name.is_null() {
        return;
    }
    // SAFETY: walk NUL-terminated path; copy last component into PROGNAME_BUF
    // via raw pointer (no `&mut` to `static mut` — rust_2024 static_mut_refs).
    unsafe {
        let mut start = name;
        let mut p = name;
        loop {
            let b = p.read().cast_unsigned();
            if b == 0 {
                break;
            }
            if b == b'/' {
                start = p.add(1);
            }
            p = p.add(1);
        }
        let buf = core::ptr::addr_of_mut!(PROGNAME_BUF).cast::<u8>();
        let mut i = 0_usize;
        let mut q = start;
        // Leave room for a trailing NUL (`PROGNAME_CAP - 1`).
        while i < PROGNAME_CAP.saturating_sub(1) {
            let b = q.read().cast_unsigned();
            if b == 0 {
                break;
            }
            buf.add(i).write(b);
            i = i.saturating_add(1);
            q = q.add(1);
        }
        if i == 0 {
            // Soft default when basename is empty (path ended with `/`).
            for (off, &b) in b"kh-guest\0".iter().enumerate() {
                buf.add(off).write(b);
            }
        } else {
            buf.add(i).write(0);
        }
        __progname = buf.cast::<c_char>();
    }
}

/// C `_exit` → nlist `__exit` (Rust name avoids `clippy::used_underscore_items`).
#[unsafe(export_name = "_exit")]
pub unsafe extern "C" fn exit_now(status: c_int) -> ! {
    // Dump freestanding heap counters before the process vanishes (opt-in /
    // dig-default via `KAKEHASHI_HEAP_STATS` soft env seed in heap.rs).
    crate::kh_core::heap::dump_stats_if_enabled();
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
    // Same dump as `_exit` (exit_now also dumps; double-call is cheap / idempotent
    // enough for dig — second dump sees same counters). Prefer single path:
    // only `_exit` dumps to avoid duplicate lines when `exit` → `exit_now`.
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
