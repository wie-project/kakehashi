//! Apple `_simple_*` soft string helpers (modern `ld`).

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

use crate::kh_core::heap::{free, malloc};


/// Ensure `need` bytes of capacity (including trailing NUL room). Soft resize.
unsafe fn simple_ensure(h: *mut c_void, need: usize) -> bool {
    if h.is_null() {
        return false;
    }
    let need = need.max(1);
    unsafe {
        let old = h.cast::<usize>().read() as *mut u8;
        let old_cap = h.cast::<usize>().add(1).read();
        if need <= old_cap {
            return true;
        }
        let mut cap = old_cap.max(64);
        while cap < need {
            cap = cap.saturating_mul(2).max(need);
        }
        let nbuf = malloc(cap).cast::<u8>();
        if nbuf.is_null() {
            return false;
        }
        let len = h.cast::<usize>().add(2).read().min(old_cap);
        if !old.is_null() && len > 0 {
            core::ptr::copy_nonoverlapping(old, nbuf, len);
            free(old.cast());
        } else if !old.is_null() {
            free(old.cast());
        }
        // Keep existing length; caller may extend.
        if old_cap == 0 {
            nbuf.write(0);
        }
        h.cast::<usize>().write(nbuf as usize);
        h.cast::<usize>().add(1).write(cap);
    }
    true
}

/// `_simple_salloc` — allocate a growable soft string (returns opaque handle).
#[unsafe(export_name = "_simple_salloc")]
pub(crate) unsafe extern "C" fn simple_salloc() -> *mut c_void {
    // Soft handle: heap block holding { buf*, cap, len }.
    let p = unsafe { malloc(24) };
    if p.is_null() {
        return core::ptr::null_mut();
    }
    // Seed a tiny empty buffer so `_simple_string` is never null for a live handle.
    let buf = unsafe { malloc(1) }.cast::<u8>();
    if buf.is_null() {
        unsafe {
            free(p);
        }
        return core::ptr::null_mut();
    }
    unsafe {
        buf.write(0);
        p.cast::<usize>().write(buf as usize);
        p.cast::<usize>().add(1).write(1); // cap
        p.cast::<usize>().add(2).write(0); // len
    }
    p
}

/// `_simple_sfree` — free soft string handle.
#[unsafe(export_name = "_simple_sfree")]
pub(crate) unsafe extern "C" fn simple_sfree(h: *mut c_void) {
    if h.is_null() {
        return;
    }
    unsafe {
        let buf = h.cast::<usize>().read() as *mut c_void;
        if !buf.is_null() {
            free(buf);
        }
        free(h);
    }
}

/// `_simple_sresize` — ensure capacity (soft).
#[unsafe(export_name = "_simple_sresize")]
pub(crate) unsafe extern "C" fn simple_sresize(h: *mut c_void, new_cap: usize) -> c_int {
    if unsafe { simple_ensure(h, new_cap.saturating_add(1)) } {
        0
    } else {
        -1
    }
}

/// `_simple_string` — C string view of soft buffer (NUL-terminated).
#[unsafe(export_name = "_simple_string")]
pub(crate) unsafe extern "C" fn simple_string(h: *mut c_void) -> *const c_char {
    if h.is_null() {
        return c"".as_ptr();
    }
    unsafe {
        let buf = h.cast::<usize>().read() as *const c_char;
        if buf.is_null() {
            c"".as_ptr()
        } else {
            buf
        }
    }
}

// `_simple_vsprintf` is implemented in `printf_fmt.c` so `va_list` matches
// Apple arm64 ABI (same TU as `vsnprintf`). It calls back into
// `kh_simple_append` below to grow the soft handle.

