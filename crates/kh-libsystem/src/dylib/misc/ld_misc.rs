//! Misc ld-classic soft symbols.

#![allow(unused_imports)]
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

use crate::dylib::libsystem_c::stdio::{memcpy, strlen};
use crate::kh_core::errno;
use crate::kh_core::heap::malloc;

const EINVAL: i32 = 22;

/// C `sleep` → nlist `_sleep` (seconds).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn sleep(seconds: u32) -> u32 {
    // nanosleep soft via usleep loop if available.
    let mut left = seconds;
    while left > 0 {
        // usleep max ~1s chunks
        let _ = unsafe { crate::dylib::libsystem_c::posix::usleep(1_000_000) };
        left = left.saturating_sub(1);
    }
    0
}

/// C `truncate`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn truncate(path: *const c_char, length: i64) -> c_int {
    // open + ftruncate soft path: use open then ftruncate if we have them.
    if path.is_null() {
        errno::set_errno(EINVAL);
        return -1;
    }
    let _ = length;
    // Soft success for linker temp-file sizing; real truncate not required for G4.
    0
}

/// `mkdtemp` — fill trailing `XXXXXX`, create the directory (0700), return path.
///
/// Observed: modern `ld` `-lto_library` uses `/tmp/ld-support-XXXXXX` then
/// joins `libLTO.dylib`. The old soft path only rewrote X's and **never
/// mkdir'd**, so later path joins saw a non-directory and wedged on
/// access/stat of glued names like `/tmpld-support-…libLTO.dylib`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn mkdtemp(template: *mut c_char) -> *mut c_char {
    if template.is_null() {
        return core::ptr::null_mut();
    }
    let len = unsafe { strlen(template) };
    if len < 6 {
        errno::set_errno(EINVAL);
        return core::ptr::null_mut();
    }
    let xs = unsafe { template.add(len.saturating_sub(6)) };
    for i in 0..6 {
        if unsafe { xs.add(i).read() }.cast_unsigned() != b'X' {
            errno::set_errno(EINVAL);
            return core::ptr::null_mut();
        }
    }
    // Same alphabet / LCG shape as freestanding `mkstemp`.
    const ALPH: &[u8] = b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    let mut state = template.addr().wrapping_mul(0x9E37_79B9).wrapping_add(len);
    for _attempt in 0..256 {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1);
        let mut s = state;
        for i in 0..6 {
            let idx = s % 62;
            let ch = ALPH.get(idx).copied().unwrap_or(b'0');
            unsafe {
                xs.add(i).write(ch.cast_signed());
            }
            s >>= 6;
        }
        // Darwin mkdir mode is often 0700 for mkdtemp.
        let rc = unsafe { crate::dylib::libsystem_c::posix::mkdir(template, 0o700) };
        if rc == 0 {
            return template;
        }
        // Retry only on EEXIST.
        if errno::get_errno() != 17 {
            return core::ptr::null_mut();
        }
    }
    errno::set_errno(17); // EEXIST
    core::ptr::null_mut()
}

/// Darwin `mkpath_np` — create every path component (`mkdir -p` style).
///
/// Observed: modern `ld` `-lto_library` builds `/tmp/ld-support-<pid>/libLTO.dylib`
/// via `mkpath_np` then waits for the tree. Soft always-0 never created the
/// dir → infinite access/stat loop on a missing temp path.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn mkpath_np(path: *const c_char, mode: u16) -> c_int {
    if path.is_null() {
        errno::set_errno(EINVAL);
        return -1;
    }
    let len = unsafe { strlen(path) };
    if len == 0 || len >= 1024 {
        errno::set_errno(EINVAL);
        return -1;
    }
    // Copy to mutable buffer so we can insert NULs at each `/`.
    let mut buf = [0_u8; 1024];
    unsafe {
        core::ptr::copy_nonoverlapping(path.cast::<u8>(), buf.as_mut_ptr(), len);
    }
    buf[len] = 0;
    let mode_i = c_int::from(mode);
    // Walk components: for `/a/b/c` create `/a`, `/a/b`, `/a/b/c`.
    let mut i = 0_usize;
    // Skip leading slashes but keep absolute root.
    while i < len && buf[i] == b'/' {
        i = i.saturating_add(1);
    }
    while i < len {
        // Find next slash.
        let mut j = i;
        while j < len && buf[j] != b'/' {
            j = j.saturating_add(1);
        }
        // Temporarily terminate at j (or end).
        let saved = buf[j];
        buf[j] = 0;
        let cpath = buf.as_ptr().cast::<c_char>();
        let rc = unsafe { crate::dylib::libsystem_c::posix::mkdir(cpath, mode_i) };
        let err = if rc != 0 { errno::get_errno() } else { 0 };
        buf[j] = saved;
        if rc != 0 && err != 17 {
            // EEXIST is fine; anything else fails the whole path.
            return -1;
        }
        // Skip slash run.
        i = j;
        while i < len && buf[i] == b'/' {
            i = i.saturating_add(1);
        }
    }
    0
}

/// `___tolower` (ASCII).
#[unsafe(export_name = "__tolower")]
pub(crate) unsafe extern "C" fn __tolower(c: c_int) -> c_int {
    let upper_a = c_int::from(b'A');
    let upper_z = c_int::from(b'Z');
    let lower_a = c_int::from(b'a');
    if (upper_a..=upper_z).contains(&c) {
        c.wrapping_sub(upper_a).wrapping_add(lower_a)
    } else {
        c
    }
}

/// `pthread_attr_setstacksize` soft success.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn pthread_attr_setstacksize(
    _attr: *mut c_void,
    _size: usize,
) -> c_int {
    0
}

/// Darwin `qsort_b` — Block comparator (CLT `libtool`/`ranlib` TOC sort).
///
/// ```c
/// void qsort_b(void *base, size_t nel, size_t width,
///              int (^compar)(const void *, const void *));
/// ```
///
/// Soft: treat `compar` as a Block with invoke at +16 (same as GCD soft path).
/// `invoke(block, a, b) → int`. Trace-first from `libtool -static` missing
/// `_qsort_b`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn qsort_b(
    base: *mut c_void,
    nel: usize,
    width: usize,
    compar: *mut c_void,
) {
    if base.is_null() || nel < 2 || width == 0 || compar.is_null() {
        return;
    }
    // Block_layout.invoke @ +16 on Darwin arm64.
    let invoke = unsafe { compar.cast::<usize>().add(2).read() };
    if invoke == 0 {
        return;
    }
    let invoke: unsafe extern "C" fn(*mut c_void, *const c_void, *const c_void) -> c_int =
        unsafe { core::mem::transmute(invoke) };
    // Reuse BSD qsort_r with block as thunk.
    unsafe {
        qsort_r(base, nel, width, compar, Some(invoke));
    }
}

/// Darwin BSD `qsort_r` (thunk **before** compar — not GNU order).
///
/// ```c
/// void qsort_r(void *base, size_t nel, size_t width, void *thunk,
///              int (*compar)(void *, const void *, const void *));
/// ```
///
/// Observed: Apple `ld-classic` `Parser<arm64>::sectionIndexSorter` (G4).
/// Wrong arg order called the thunk as a function → SEGV with PC on stack.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn qsort_r(
    base: *mut c_void,
    nel: usize,
    width: usize,
    thunk: *mut c_void,
    compar: Option<unsafe extern "C" fn(*mut c_void, *const c_void, *const c_void) -> c_int>,
) {
    if base.is_null() || nel < 2 || width == 0 {
        return;
    }
    let Some(cmp) = compar else {
        return;
    };
    let cmp: unsafe extern "C" fn(*mut c_void, *const c_void, *const c_void) -> c_int = {
        let raw = crate::kh_core::sys::strip_ptrauth_ia(cmp as usize);
        unsafe { core::mem::transmute(raw) }
    };
    // Simple insertion sort with thunk.
    unsafe {
        let bytes = base.cast::<u8>();
        let mut outer = 1_usize;
        while outer < nel {
            let mut inner = outer;
            while inner > 0 {
                let left = bytes.add(inner.saturating_sub(1).saturating_mul(width));
                let right = bytes.add(inner.saturating_mul(width));
                if cmp(thunk, left.cast(), right.cast()) <= 0 {
                    break;
                }
                // swap width bytes
                let mut off = 0_usize;
                while off < width {
                    let tmp = left.add(off).read();
                    left.add(off).write(right.add(off).read());
                    right.add(off).write(tmp);
                    off = off.saturating_add(1);
                }
                inner = inner.saturating_sub(1);
            }
            outer = outer.saturating_add(1);
        }
    }
}

/// `vm_page_size` global.
#[unsafe(no_mangle)]
#[used]
pub(crate) static mut vm_page_size: usize = 16384;

/// `mach_host_self` → soft port 1.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn mach_host_self() -> u32 {
    1
}

/// `host_statistics` — soft zero fill / success.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn host_statistics(
    _host: u32,
    _flavor: c_int,
    host_info_out: *mut c_int,
    host_info_out_cnt: *mut u32,
) -> c_int {
    if !host_info_out.is_null() && !host_info_out_cnt.is_null() {
        let n = unsafe { (*host_info_out_cnt) as usize };
        let mut i = 0_usize;
        while i < n {
            unsafe {
                host_info_out.add(i).write(0);
            }
            i = i.saturating_add(1);
        }
    }
    0
}
