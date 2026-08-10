//! Path/string soft helpers (fnmatch, realpath, …).

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

const EINVAL: i32 = 22;
const ENOTTY: i32 = 25;
const ENOSYS: i32 = 78;
const EAI_NONAME: i32 = 8;
const EAI_FAMILY: i32 = 1;

/// C `fnmatch` → basic `*` / `?` / literal (enough for curl glob off paths).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn fnmatch(
    pattern: *const c_char,
    string: *const c_char,
    _flags: c_int,
) -> c_int {
    if pattern.is_null() || string.is_null() {
        return 1;
    }
    if unsafe { fnmatch_inner(pattern, string) } {
        0
    } else {
        1 // FNM_NOMATCH
    }
}

unsafe fn fnmatch_inner(mut pat: *const c_char, mut s: *const c_char) -> bool {
    loop {
        let p = unsafe { pat.read().cast_unsigned() };
        let c = unsafe { s.read().cast_unsigned() };
        if p == 0 {
            return c == 0;
        }
        if p == b'*' {
            // greedy *
            unsafe {
                pat = pat.add(1);
            }
            if unsafe { pat.read() } == 0 {
                return true;
            }
            loop {
                if unsafe { fnmatch_inner(pat, s) } {
                    return true;
                }
                if unsafe { s.read() } == 0 {
                    return false;
                }
                unsafe {
                    s = s.add(1);
                }
            }
        }
        if p == b'?' {
            if c == 0 {
                return false;
            }
        } else if p != c {
            return false;
        }
        if c == 0 {
            return p == 0;
        }
        unsafe {
            pat = pat.add(1);
            s = s.add(1);
        }
    }
}

/// C `realpath` → nlist `_realpath`.
///
/// Soft: copy the path, but still require the path to exist (Darwin
/// `realpath` returns `NULL` + `ENOENT` when the target is missing). Modern
/// `ld` uses this when processing `-syslibroot` before adding default
/// `$root/usr/lib` library search paths.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn realpath(
    path: *const c_char,
    resolved: *mut c_char,
) -> *mut c_char {
    const F_OK: c_int = 0;
    if path.is_null() {
        errno::set_errno(EINVAL);
        return core::ptr::null_mut();
    }
    // Reject PAGEZERO / unrebased guest pointers.
    if path.addr() < crate::dylib::libsystem_c::stdio::PAGEZERO_END {
        errno::set_errno(EINVAL);
        return core::ptr::null_mut();
    }
    // Darwin: path must exist. Use freestanding `access(F_OK)`.
    let exists = unsafe { crate::dylib::libsystem_c::posix::access(path, F_OK) } == 0;
    if !exists {
        errno::set_errno(2); // ENOENT
        return core::ptr::null_mut();
    }
    let n = unsafe { strlen(path) };
    // PATH_MAX-ish cap for stack resolved buffers callers pass in.
    if n >= 1024 {
        errno::set_errno(63); // ENAMETOOLONG-ish
        return core::ptr::null_mut();
    }
    let out = if resolved.is_null() {
        let p = unsafe { malloc(n.saturating_add(1)) };
        if p.is_null() {
            return core::ptr::null_mut();
        }
        p.cast::<c_char>()
    } else {
        resolved
    };
    unsafe {
        strcpy(out, path);
    }
    out
}

/// Darwin `realpath$DARWIN_EXTSN`.
#[unsafe(export_name = "realpath$DARWIN_EXTSN")]
pub(crate) unsafe extern "C" fn realpath_darwin_extsn(
    path: *const c_char,
    resolved: *mut c_char,
) -> *mut c_char {
    unsafe { realpath(path, resolved) }
}

// `sscanf` / `vsscanf` live in `printf_fmt.c` (true C `va_list` ABI).
// The old Rust fixed-arg soft sscanf broke Apple arm64 variadic calls
// (observed: `ld -flto` version parse → malformed '15.0.…').

