//! Freestanding POSIX `regex.h` for Apple `git` / `libLTO` (`regcomp` / …).
//!
//! Compile/match run on the **host** via `KH_HELPER_REG*` (no `regex-automata`
//! in freestanding — workspace feature-unification with `tracing-subscriber`
//! would pull `std` and clash with our `#[panic_handler]`).
//!
//! Darwin layout (arm64, `sizeof == 32`, public `_regex.h`):
//! ```c
//! typedef struct {
//!     int re_magic;
//!     size_t re_nsub;           /* offsetof 8 */
//!     const char *re_endp;      /* offsetof 16 — REG_PEND */
//!     struct re_guts *re_g;     /* offsetof 24 — we store host handle */
//! } regex_t;
//! typedef struct { regoff_t rm_so; regoff_t rm_eo; } regmatch_t;
//! ```
//!
//! A wrong 16-byte `{nsub, opaque}` layout made `re_nsub` read the host handle
//! (often `1`) — libLTO then fails `APPLE_1_*` bitcode version parse with
//! `Invalid bitcode version (Producer: 'APPLE_1_…' Reader: '…')`.
#![allow(
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::indexing_slicing,
    clippy::manual_c_str_literals,
    clippy::used_underscore_binding
)]

use core::ffi::{c_char, c_int};
use core::ptr;

use crate::sys;
use crate::{KH_HELPER_REGCOMP, KH_HELPER_REGEXEC, KH_HELPER_REGFREE};

// ── Darwin error codes ──────────────────────────────────────────────────────

const REG_NOMATCH: c_int = 1;
const REG_BADPAT: c_int = 2;
const REG_ECOLLATE: c_int = 3;
const REG_ECTYPE: c_int = 4;
const REG_EESCAPE: c_int = 5;
const REG_ESUBREG: c_int = 6;
const REG_EBRACK: c_int = 7;
const REG_EPAREN: c_int = 8;
const REG_EBRACE: c_int = 9;
const REG_BADBR: c_int = 10;
const REG_ERANGE: c_int = 11;
const REG_ESPACE: c_int = 12;
const REG_BADRPT: c_int = 13;
const REG_EMPTY: c_int = 14;
const REG_ASSERT: c_int = 15;
const REG_INVARG: c_int = 16;

/// Guest addresses in the low 4 GiB are invalid (Darwin PAGEZERO).
const PAGEZERO_END: u64 = 1 << 32;

/// Apple libregex `MAGIC1` = `(('r'^0200)<<8)|'e'` = `0xF265` (native regcomp).
const RE_MAGIC: c_int = 0xF265;

// ── Types ───────────────────────────────────────────────────────────────────

/// Darwin `regex_t` — must match public SDK `_regex.h` (32 bytes on arm64).
/// Field names mirror Darwin ABI (`re_*`); do not rename for clippy.
#[repr(C)]
#[allow(clippy::struct_field_names)]
pub(crate) struct RegexT {
    re_magic: c_int,
    /// Host handle (slot id + 1), stored in `re_g` (guts pointer slot).
    re_nsub: usize,
    re_endp: usize,
    re_g: usize,
}

/// Darwin `regmatch_t`.
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct RegmatchT {
    rm_so: i64,
    rm_eo: i64,
}

/// Packed request for `KH_HELPER_REGEXEC` (host reads from guest VA).
#[repr(C)]
struct RegexecReq {
    handle: u64,
    string: u64,
    nmatch: u64,
    pmatch: u64,
    eflags: u64,
}

fn guest_ptr_ok(p: u64) -> bool {
    p != 0 && p >= PAGEZERO_END
}

// ── C ABI ───────────────────────────────────────────────────────────────────

/// C `regcomp` → nlist `_regcomp`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn regcomp(
    preg: *mut RegexT,
    pattern: *const c_char,
    cflags: c_int,
) -> c_int {
    if preg.is_null() || !guest_ptr_ok(preg as u64) {
        return REG_INVARG;
    }
    if pattern.is_null() || !guest_ptr_ok(pattern as u64) {
        return REG_INVARG;
    }
    // out: [handle_u64, nsub_u64]
    let mut out = [0_u64; 2];
    let rc = unsafe {
        sys::helper3(
            KH_HELPER_REGCOMP,
            pattern as u64,
            u64::from(cflags.cast_unsigned()),
            out.as_mut_ptr() as u64,
        )
    };
    // helper returns 0 on success, positive Darwin REG_* on soft error,
    // negative on host fault (map to REG_ESPACE / INVARG).
    if rc < 0 {
        return REG_ESPACE;
    }
    let code = c_int::try_from(rc).unwrap_or(REG_BADPAT);
    if code != 0 {
        return code;
    }
    unsafe {
        (*preg).re_magic = RE_MAGIC;
        (*preg).re_g = usize::try_from(out[0]).unwrap_or(0);
        (*preg).re_nsub = usize::try_from(out[1]).unwrap_or(0);
        (*preg).re_endp = 0;
    }
    0
}

/// C `regexec` → nlist `_regexec`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn regexec(
    preg: *const RegexT,
    string: *const c_char,
    nmatch: usize,
    pmatch: *mut RegmatchT,
    eflags: c_int,
) -> c_int {
    if preg.is_null() || !guest_ptr_ok(preg as u64) {
        return REG_INVARG;
    }
    let (magic, handle) = unsafe { ((*preg).re_magic, (*preg).re_g) };
    if magic != RE_MAGIC || handle == 0 {
        return REG_INVARG;
    }
    if string.is_null() || !guest_ptr_ok(string as u64) {
        return REG_INVARG;
    }
    let req = RegexecReq {
        handle: u64::try_from(handle).unwrap_or(0),
        string: string as u64,
        nmatch: u64::try_from(nmatch).unwrap_or(0),
        pmatch: if pmatch.is_null() { 0 } else { pmatch as u64 },
        eflags: u64::from(eflags.cast_unsigned()),
    };
    let rc = unsafe { sys::helper1(KH_HELPER_REGEXEC, core::ptr::addr_of!(req) as u64) };
    if rc < 0 {
        return REG_ESPACE;
    }
    c_int::try_from(rc).unwrap_or(REG_NOMATCH)
}

/// C `regfree` → nlist `_regfree`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn regfree(preg: *mut RegexT) {
    if preg.is_null() || !guest_ptr_ok(preg as u64) {
        return;
    }
    let handle = unsafe { (*preg).re_g };
    if handle != 0 {
        let _ = unsafe { sys::helper1(KH_HELPER_REGFREE, u64::try_from(handle).unwrap_or(0)) };
    }
    unsafe {
        (*preg).re_magic = 0;
        (*preg).re_g = 0;
        (*preg).re_nsub = 0;
        (*preg).re_endp = 0;
    }
}

/// C `regerror` → nlist `_regerror`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn regerror(
    errcode: c_int,
    _preg: *const RegexT,
    errbuf: *mut c_char,
    errbuf_size: usize,
) -> usize {
    let msg: &[u8] = match errcode {
        0 => b"success",
        REG_NOMATCH => b"regexec() failed to match",
        REG_BADPAT => b"invalid regular expression",
        REG_ECOLLATE => b"invalid collating element",
        REG_ECTYPE => b"invalid character class",
        REG_EESCAPE => b"trailing backslash",
        REG_ESUBREG => b"invalid backreference",
        REG_EBRACK => b"brackets [] not balanced",
        REG_EPAREN => b"parentheses () not balanced",
        REG_EBRACE => b"braces {} not balanced",
        REG_BADBR => b"invalid repetition count(s)",
        REG_ERANGE => b"invalid character range",
        REG_ESPACE => b"out of memory",
        REG_BADRPT => b"repetition-operator operand invalid",
        REG_EMPTY => b"empty (sub)expression",
        REG_ASSERT => b"cannot compile regular expression",
        REG_INVARG => b"invalid argument",
        _ => b"unknown regex error",
    };
    let need = msg.len().saturating_add(1);
    if errbuf.is_null() || errbuf_size == 0 || !guest_ptr_ok(errbuf as u64) {
        return need;
    }
    let ncopy = msg.len().min(errbuf_size.saturating_sub(1));
    unsafe {
        if ncopy > 0 {
            ptr::copy_nonoverlapping(msg.as_ptr(), errbuf.cast::<u8>(), ncopy);
        }
        *errbuf.add(ncopy) = 0;
    }
    need
}
