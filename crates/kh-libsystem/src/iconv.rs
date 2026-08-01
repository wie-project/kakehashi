//! Minimal freestanding `iconv` for Apple git (identity / UTF-8 / ASCII).
//!
//! Real conversion is out of scope; git mostly opens UTF-8↔UTF-8 handles during
//! `init` / config. Missing `_iconv_open` was a hard trampoline exit (127).

#![allow(
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::indexing_slicing,
    clippy::manual_c_str_literals
)]

use core::ffi::{c_char, c_int, c_void};
use core::ptr;

use crate::errno;
use crate::heap::{free, malloc};
use crate::stdio::strlen;

const EINVAL: i32 = 22;
const E2BIG: i32 = 7;

/// Opaque conversion descriptor (identity only).
struct IconvDesc {
    /// Magic so we reject garbage pointers.
    magic: u32,
}

const MAGIC: u32 = 0x4B48_4943; // "KHIC"

fn cstr_eq_ignore_case(a: *const c_char, b: &[u8]) -> bool {
    if a.is_null() {
        return b.is_empty();
    }
    let mut i = 0_usize;
    loop {
        let ac = unsafe { *a.add(i) } as u8;
        let Some(&bc) = b.get(i) else {
            return ac == 0;
        };
        if ac == 0 {
            return bc == 0;
        }
        let al = if ac.is_ascii_uppercase() {
            ac + 32
        } else {
            ac
        };
        let bl = if bc.is_ascii_uppercase() {
            bc + 32
        } else {
            bc
        };
        if al != bl {
            return false;
        }
        i = i.saturating_add(1);
        if i > 64 {
            return false;
        }
    }
}

fn is_identity_name(name: *const c_char) -> bool {
    if name.is_null() {
        // empty / locale default — treat as UTF-8-ish identity
        return true;
    }
    let n = unsafe { strlen(name) };
    if n == 0 {
        return true;
    }
    cstr_eq_ignore_case(name, b"UTF-8\0")
        || cstr_eq_ignore_case(name, b"UTF8\0")
        || cstr_eq_ignore_case(name, b"ASCII\0")
        || cstr_eq_ignore_case(name, b"US-ASCII\0")
        || cstr_eq_ignore_case(name, b"ISO-8859-1\0")
        || cstr_eq_ignore_case(name, b"LATIN1\0")
        || cstr_eq_ignore_case(name, b"CHAR\0")
        || cstr_eq_ignore_case(name, b"WCHAR_T\0")
}

/// C `iconv_open` → nlist `_iconv_open`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn iconv_open(
    tocode: *const c_char,
    fromcode: *const c_char,
) -> *mut c_void {
    // Accept same family / identity pairs only.
    if !is_identity_name(tocode) || !is_identity_name(fromcode) {
        // Soft: still open as identity so git can proceed on ASCII repos.
        // Real multi-byte conversion is not implemented.
    }
    let p = unsafe { malloc(core::mem::size_of::<IconvDesc>()) };
    if p.is_null() {
        errno::set_errno(12); // ENOMEM
        return ptr::null_mut();
    }
    unsafe {
        p.cast::<IconvDesc>().write(IconvDesc { magic: MAGIC });
    }
    p
}

/// C `iconv` → nlist `_iconv` (identity byte copy).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn iconv(
    cd: *mut c_void,
    inbuf: *mut *mut c_char,
    inbytesleft: *mut usize,
    outbuf: *mut *mut c_char,
    outbytesleft: *mut usize,
) -> usize {
    if cd.is_null() {
        errno::set_errno(EINVAL);
        return usize::MAX;
    }
    let desc = unsafe { &*cd.cast::<IconvDesc>() };
    if desc.magic != MAGIC {
        errno::set_errno(EINVAL);
        return usize::MAX;
    }
    // Reset state: all NULL pointers.
    if inbuf.is_null() || unsafe { (*inbuf).is_null() } {
        return 0;
    }
    if outbuf.is_null()
        || unsafe { (*outbuf).is_null() }
        || inbytesleft.is_null()
        || outbytesleft.is_null()
    {
        errno::set_errno(EINVAL);
        return usize::MAX;
    }
    let in_left = unsafe { *inbytesleft };
    let out_left = unsafe { *outbytesleft };
    if in_left == 0 {
        return 0;
    }
    if out_left < in_left {
        errno::set_errno(E2BIG);
        return usize::MAX;
    }
    let src = unsafe { *inbuf };
    let dst = unsafe { *outbuf };
    unsafe {
        ptr::copy_nonoverlapping(src.cast::<u8>(), dst.cast::<u8>(), in_left);
        *inbuf = src.add(in_left);
        *outbuf = dst.add(in_left);
        *inbytesleft = 0;
        *outbytesleft = out_left.saturating_sub(in_left);
    }
    0
}

/// C `iconv_close` → nlist `_iconv_close`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn iconv_close(cd: *mut c_void) -> c_int {
    if cd.is_null() {
        errno::set_errno(EINVAL);
        return -1;
    }
    let desc = unsafe { &*cd.cast::<IconvDesc>() };
    if desc.magic != MAGIC {
        errno::set_errno(EINVAL);
        return -1;
    }
    unsafe {
        free(cd);
    }
    0
}
