//! Soft leftovers that do not map cleanly to a single Darwin dylib name.

#![allow(unused_imports, dead_code)]

#![allow(
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::indexing_slicing,
    clippy::bool_to_int_with_if,
    clippy::manual_c_str_literals,
    clippy::manual_is_ascii_check,
    clippy::many_single_char_names,
    clippy::used_underscore_binding
)]

use core::ffi::{c_char, c_int, c_void};

use crate::kh_core::errno;
use crate::kh_core::heap::{free, malloc};
use crate::dylib::libsystem_c::stdio::strlen;
use crate::dylib::libsystem_c::string::{strcmp, strcpy};
use crate::kh_core::process;

const EINVAL: i32 = 22;
const ENOTTY: i32 = 25;
const ENOSYS: i32 = 78;

pub(crate) mod coreanalytics_xar;
pub(crate) mod os_lock_ld;
pub(crate) mod ld_misc;
pub(crate) use ld_misc::mkpath_np;

/// C `imaxabs` → nlist `_imaxabs` (`intmax_t` = `i64` on Darwin arm64).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn imaxabs(j: i64) -> i64 {
    j.saturating_abs()
}


/// C `backtrace` → nlist `_backtrace`.
///
/// Soft: report zero frames. Real stack walk is out of scope for freestanding
/// libSystem; guests that only probe crash reporting survive.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn backtrace(_buffer: *mut *mut c_void, _size: c_int) -> c_int {
    0
}

/// C `backtrace_symbols` → nlist `_backtrace_symbols` (null = failure).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn backtrace_symbols(
    _buffer: *mut *mut c_void,
    _size: c_int,
) -> *mut *mut c_char {
    core::ptr::null_mut()
}

/// C `backtrace_symbols_fd` → nlist `_backtrace_symbols_fd` (no-op).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn backtrace_symbols_fd(
    _buffer: *mut *mut c_void,
    _size: c_int,
    _fd: c_int,
) {
}


/// C `kdebug_trace_string` → nlist `_kdebug_trace_string`.
///
/// Soft: accept and return 0 (no kernel trace facility under kh).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn kdebug_trace_string(
    _debugid: u32,
    _str_id: u64,
    _str: *const c_char,
) -> c_int {
    0
}

/// C `kdebug_trace` → nlist `_kdebug_trace` (soft success).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn kdebug_trace(
    _debugid: u32,
    _a: u64,
    _b: u64,
    _c: u64,
    _d: u64,
) -> c_int {
    0
}

/// C `kdebug_is_enabled` → nlist `_kdebug_is_enabled` (always off).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn kdebug_is_enabled(_debugid: u32) -> c_int {
    0
}

// `arc4random*` lives in `net.rs` (curl-era buf + clang scalar).


/// C `setjmp` → always 0 (context not restored by our soft `longjmp`).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn setjmp(_env: *mut c_void) -> c_int {
    0
}

/// Darwin `_setjmp` → nlist `__setjmp`.
#[unsafe(export_name = "_setjmp")]
pub(crate) unsafe extern "C" fn _setjmp(env: *mut c_void) -> c_int {
    unsafe { setjmp(env) }
}

/// C `longjmp` → exit guest (no real context restore).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn longjmp(_env: *mut c_void, val: c_int) -> ! {
    let code = if val == 0 { 1 } else { val };
    unsafe {
        crate::kh_core::process::exit_now(code);
    }
}

/// Darwin `_longjmp` → nlist `__longjmp`.
#[unsafe(export_name = "_longjmp")]
pub(crate) unsafe extern "C" fn _longjmp(env: *mut c_void, val: c_int) -> ! {
    unsafe { longjmp(env, val) }
}

/// C `getcontext` → soft ENOSYS.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn getcontext(_ucp: *mut c_void) -> c_int {
    errno::set_errno(ENOSYS);
    -1
}

/// C `setcontext` → soft ENOSYS.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn setcontext(_ucp: *const c_void) -> c_int {
    errno::set_errno(ENOSYS);
    -1
}

/// C `makecontext` → no-op.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn makecontext(
    _ucp: *mut c_void,
    _func: *mut c_void,
    _argc: c_int,
    // varargs ignored
) {
}


/// C `tcgetattr` → ENOTTY (no guest tty).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn tcgetattr(_fd: c_int, _termios_p: *mut c_void) -> c_int {
    errno::set_errno(ENOTTY);
    -1
}

/// C `tcsetattr` → ENOTTY.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn tcsetattr(
    _fd: c_int,
    _optional_actions: c_int,
    _termios_p: *const c_void,
) -> c_int {
    errno::set_errno(ENOTTY);
    -1
}


/// C `kqueue` → anonymous pipe read end (kevent will soft-return 0).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn kqueue() -> c_int {
    // pipe() returns read in low 32 / write high on Darwin via our wrapper...
    // Use open("/dev/null") style: allocate a pipe via net::pipe.
    let mut fds = [0_i32; 2];
    let rc = unsafe { crate::dylib::libsystem_c::net::pipe(fds.as_mut_ptr()) };
    if rc != 0 {
        return -1;
    }
    // Close write end; return read end as a pollable fd.
    let _ = unsafe { crate::dylib::libsystem_c::posix::close(fds[1]) };
    fds[0]
}

/// C `kevent` → always 0 events (timeout / idle).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn kevent(
    _kq: c_int,
    _changelist: *const c_void,
    nchanges: c_int,
    _eventlist: *mut c_void,
    _nevents: c_int,
    _timeout: *const c_void,
) -> c_int {
    let _ = nchanges;
    0
}


/// C `setitimer` → soft success (no real interval timers).
///
/// Apple `git` clone uses this for the progress ticker; missing export was a
/// hard trampoline exit mid-checkout (`index.lock` left behind).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn setitimer(
    _which: c_int,
    _value: *const c_void,
    _ovalue: *mut c_void,
) -> c_int {
    0
}

/// C `getitimer` → zeroed soft success.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn getitimer(_which: c_int, value: *mut c_void) -> c_int {
    if !value.is_null() {
        // struct itimerval { timeval it_interval; timeval it_value; } — 32 bytes on arm64.
        unsafe {
            core::ptr::write_bytes(value.cast::<u8>(), 0, 32);
        }
    }
    0
}


