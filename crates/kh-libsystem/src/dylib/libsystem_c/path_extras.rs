//! Extra path/string surface used by Apple `ld` / tapi.

#![allow(unused_imports, dead_code)]

#![allow(
    static_mut_refs,
    non_snake_case,
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    clippy::cast_lossless,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_ptr_alignment,
    clippy::cast_sign_loss,
    clippy::indexing_slicing,
    clippy::items_after_statements,
    clippy::manual_c_str_literals,
    clippy::many_single_char_names,
    clippy::missing_safety_doc,
    clippy::not_unsafe_ptr_arg_deref,
    clippy::too_many_arguments,
    clippy::used_underscore_binding
)]

use core::ffi::{c_char, c_int, c_void};

use crate::kh_core::errno;
use crate::kh_core::heap::malloc;
use crate::dylib::libsystem_c::stdio::{memcpy, strlen};

const EINVAL: i32 = 22;

/// C `strlcat`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn strlcat(
    dst: *mut c_char,
    src: *const c_char,
    size: usize,
) -> usize {
    if dst.is_null() || src.is_null() {
        return 0;
    }
    let dlen = if size == 0 {
        0
    } else {
        // Find current length limited by size-1.
        let mut n = 0_usize;
        unsafe {
            while n + 1 < size && dst.add(n).read() != 0 {
                n = n.saturating_add(1);
            }
        }
        n
    };
    let slen = unsafe { strlen(src) };
    if size == 0 {
        return slen.saturating_add(dlen);
    }
    let room = size.saturating_sub(dlen).saturating_sub(1);
    let mut i = 0_usize;
    unsafe {
        while i < room && src.add(i).read() != 0 {
            dst.add(dlen + i).write(src.add(i).read());
            i = i.saturating_add(1);
        }
        if dlen < size {
            dst.add(dlen + i).write(0);
        }
    }
    dlen.saturating_add(slen)
}

/// C `strndup`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn strndup(s: *const c_char, n: usize) -> *mut c_char {
    if s.is_null() {
        return core::ptr::null_mut();
    }
    let len = unsafe { strlen(s) }.min(n);
    let p = unsafe { malloc(len.saturating_add(1)).cast::<c_char>() };
    if p.is_null() {
        return core::ptr::null_mut();
    }
    unsafe {
        let _ = memcpy(p.cast(), s.cast(), len);
        p.add(len).write(0);
    }
    p
}

/// C `strtok` — classic static delimiter walk (not thread-safe).
///
/// # Safety (caller)
/// Same contract as libc: `s` (or the prior continuation) is a live mutable
/// NUL-terminated C string for the whole tokenize sequence; `delim` is a live
/// NUL-terminated delimiter set. This implementation never forms Rust `&T` /
/// `&mut T` over that buffer — only raw `read`/`write` after address checks.
///
/// Defensive guest guards (beyond libc): reject null and Darwin PAGEZERO
/// addresses, and hard-cap the walk so a missing terminator cannot run forever.
static mut STRTOK_SAVE: *mut c_char = core::ptr::null_mut();

/// Max bytes walked in one `strtok` call (same order as freestanding `strlen`).
const STRTOK_WALK_MAX: usize = 1 << 20;

/// Live guest C-string pointer: non-null and outside Darwin PAGEZERO.
///
/// Same barrier shape as `curl::easy_from` (explicit `is_null` + PAGEZERO) so
/// CodeQL `rust/access-invalid-pointer` sees a NotNullCheckBarrier at each use.
#[inline]
fn strtok_addr_ok(p: *const c_char) -> bool {
    !p.is_null() && p.addr() >= crate::dylib::libsystem_c::stdio::PAGEZERO_END
}

/// Load one byte from a guest C-string address without forming a Rust reference.
///
/// Uses `copy_nonoverlapping` into a stack local (not `as_ref` / `*p`) so we never
/// create `&T` over an untrusted C buffer, and the null/PAGEZERO checks sit in
/// the same function as the access (CodeQL barrier).
///
/// # Safety
/// After the address checks pass, `p` must point into a live allocation for at
/// least one `c_char` (libc `strtok` NUL-terminated buffer contract).
#[inline]
unsafe fn strtok_load(p: *const c_char) -> Option<c_char> {
    // NotNullCheckBarrier: keep both checks inline (do not fold through a helper
    // alone at the deref site — CodeQL does not always track that).
    if p.is_null() || p.addr() < crate::dylib::libsystem_c::stdio::PAGEZERO_END {
        return None;
    }
    let mut b: c_char = 0;
    // SAFETY: null + PAGEZERO rejected; one-byte copy from caller's live C string.
    unsafe {
        core::ptr::copy_nonoverlapping(p, core::ptr::addr_of_mut!(b), 1);
    }
    Some(b)
}

/// Store one byte at a guest C-string address without forming a Rust reference.
///
/// # Safety
/// Same as [`strtok_load`], plus the location must be mutable.
#[inline]
unsafe fn strtok_store(p: *mut c_char, v: c_char) -> bool {
    if p.is_null() || p.addr() < crate::dylib::libsystem_c::stdio::PAGEZERO_END {
        return false;
    }
    let b = v;
    // SAFETY: null + PAGEZERO rejected; one-byte copy into caller's live buffer.
    unsafe {
        core::ptr::copy_nonoverlapping(core::ptr::addr_of!(b), p, 1);
    }
    true
}

#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn strtok(s: *mut c_char, delim: *const c_char) -> *mut c_char {
    if !strtok_addr_ok(delim) {
        return core::ptr::null_mut();
    }

    let mut p = if s.is_null() {
        // SAFETY: prior continuation; re-validated before any load/store.
        unsafe { STRTOK_SAVE }
    } else {
        s
    };
    if !strtok_addr_ok(p) {
        unsafe {
            STRTOK_SAVE = core::ptr::null_mut();
        }
        return core::ptr::null_mut();
    }

    // SAFETY: `p`/`delim` address-ok; each step re-validates before load/store.
    // Advances only after a successful non-NUL load so `STRTOK_SAVE` never
    // steps from an unobserved address (no OOB continuation invent).
    unsafe {
        let mut walked = 0_usize;

        // Skip leading delimiters.
        loop {
            if walked > STRTOK_WALK_MAX {
                STRTOK_SAVE = core::ptr::null_mut();
                return core::ptr::null_mut();
            }
            let Some(c) = strtok_load(p) else {
                STRTOK_SAVE = core::ptr::null_mut();
                return core::ptr::null_mut();
            };
            if c == 0 {
                STRTOK_SAVE = core::ptr::null_mut();
                return core::ptr::null_mut();
            }
            if !is_delim(c, delim) {
                break;
            }
            // Observed a live non-NUL byte at `p` → one-byte step stays on the
            // object while the string remains NUL-terminated (libc contract).
            p = p.add(1);
            walked = walked.saturating_add(1);
        }

        let start = p;
        loop {
            if walked > STRTOK_WALK_MAX {
                // Missing terminator: return what we have; do not invent a save.
                STRTOK_SAVE = core::ptr::null_mut();
                return start;
            }
            let Some(c) = strtok_load(p) else {
                STRTOK_SAVE = core::ptr::null_mut();
                return start;
            };
            if c == 0 {
                STRTOK_SAVE = core::ptr::null_mut();
                return start;
            }
            if is_delim(c, delim) {
                // Classic strtok: splice token with in-place NUL at delimiter.
                if !strtok_store(p, 0) {
                    STRTOK_SAVE = core::ptr::null_mut();
                    return start;
                }
                // Continuation is the byte after the delimiter we just wrote.
                // That address is only retained if it itself passes addr checks
                // (rejects PAGEZERO/null); next call loads it or clears.
                let next = p.add(1);
                STRTOK_SAVE = if strtok_addr_ok(next) {
                    next
                } else {
                    core::ptr::null_mut()
                };
                return start;
            }
            p = p.add(1);
            walked = walked.saturating_add(1);
        }
    }
}

unsafe fn is_delim(c: c_char, delim: *const c_char) -> bool {
    if !strtok_addr_ok(delim) {
        return false;
    }
    let mut d = delim;
    let mut n = 0_usize;
    // SAFETY: `delim` address-ok; each byte re-checked; hard cap on set length.
    unsafe {
        loop {
            if n > 256 {
                return false;
            }
            let Some(x) = strtok_load(d) else {
                return false;
            };
            if x == 0 {
                return false;
            }
            if x == c {
                return true;
            }
            d = d.add(1);
            n = n.saturating_add(1);
        }
    }
}

/// C `strtoull`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn strtoull(
    nptr: *const c_char,
    endptr: *mut *mut c_char,
    base: c_int,
) -> u64 {
    if nptr.is_null() {
        return 0;
    }
    let mut p = nptr;
    let mut acc = 0_u64;
    let mut base_u = base;
    unsafe {
        // skip spaces
        while matches!(p.read().cast_unsigned(), b' ' | b'\t' | b'\n' | b'\r') {
            p = p.add(1);
        }
        let mut neg = false;
        let c0 = p.read().cast_unsigned();
        if c0 == b'+' || c0 == b'-' {
            neg = c0 == b'-';
            p = p.add(1);
        }
        if base_u == 0 {
            if p.read().cast_unsigned() == b'0' {
                let n = p.add(1).read().cast_unsigned();
                if n == b'x' || n == b'X' {
                    base_u = 16;
                    p = p.add(2);
                } else {
                    base_u = 8;
                }
            } else {
                base_u = 10;
            }
        } else if base_u == 16
            && p.read().cast_unsigned() == b'0'
            && matches!(p.add(1).read().cast_unsigned(), b'x' | b'X')
        {
            p = p.add(2);
        }
        if !(2..=36).contains(&base_u) {
            if !endptr.is_null() {
                endptr.write(nptr.cast_mut());
            }
            return 0;
        }
        let b = base_u as u64;
        loop {
            let c = p.read().cast_unsigned();
            let digit = match c {
                b'0'..=b'9' => c - b'0',
                b'a'..=b'z' => c - b'a' + 10,
                b'A'..=b'Z' => c - b'A' + 10,
                _ => break,
            };
            if c_int::from(digit) >= base_u {
                break;
            }
            acc = acc.saturating_mul(b).saturating_add(u64::from(digit));
            p = p.add(1);
        }
        if !endptr.is_null() {
            endptr.write(p.cast_mut());
        }
        if neg {
            acc = 0u64.wrapping_sub(acc);
        }
    }
    acc
}

/// C `dirname` — mutates path (POSIX).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn dirname(path: *mut c_char) -> *mut c_char {
    static mut DOT: [c_char; 2] = [b'.'.cast_signed(), 0];
    if path.is_null() {
        return core::ptr::addr_of_mut!(DOT).cast();
    }
    unsafe {
        let len = strlen(path);
        if len == 0 {
            return core::ptr::addr_of_mut!(DOT).cast();
        }
        // strip trailing slashes
        let mut end = len;
        while end > 1 && path.add(end - 1).read().cast_unsigned() == b'/' {
            end = end.saturating_sub(1);
        }
        // find last slash
        let mut slash_at = end;
        while slash_at > 0 {
            if path.add(slash_at - 1).read().cast_unsigned() == b'/' {
                break;
            }
            slash_at = slash_at.saturating_sub(1);
        }
        if slash_at == 0 {
            // no slash
            DOT[0] = b'.'.cast_signed();
            DOT[1] = 0;
            return core::ptr::addr_of_mut!(DOT).cast();
        }
        // keep root "/"
        let mut keep = slash_at;
        while keep > 1 && path.add(keep - 1).read().cast_unsigned() == b'/' {
            keep = keep.saturating_sub(1);
        }
        path.add(keep).write(0);
        path
    }
}

/// Darwin `dirname_r` → nlist `_dirname_r` (thread-safe; writes into `result`).
///
/// Soft: same rules as `dirname` but non-destructive; `result` must hold ≥ `PATH_MAX`.
/// Observed: CLT `libtool` undefined import.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn dirname_r(
    path: *const c_char,
    result: *mut c_char,
    size: usize,
) -> *mut c_char {
    if result.is_null() || size == 0 {
        return core::ptr::null_mut();
    }
    // Default "."
    if path.is_null() {
        if size >= 2 {
            unsafe {
                result.write(b'.'.cast_signed());
                result.add(1).write(0);
            }
            return result;
        }
        return core::ptr::null_mut();
    }
    unsafe {
        // Copy path into result then dirname in place (bounded).
        let len = strlen(path);
        if len + 1 > size {
            return core::ptr::null_mut();
        }
        core::ptr::copy_nonoverlapping(path, result, len + 1);
        let _ = dirname(result);
        result
    }
}

