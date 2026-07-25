//! Pure C string / memory / wide-char surface (no syscalls).

use core::ffi::{c_char, c_int, c_void};

use crate::stdio::memcpy;

/// Darwin `wchar_t` is 32-bit on arm64.
type Wchar = i32;

/// `___toupper` (ASCII) → nlist `___toupper`.
#[unsafe(export_name = "__toupper")]
pub(crate) unsafe extern "C" fn __toupper(c: c_int) -> c_int {
    let lower_a = c_int::from(b'a');
    let lower_z = c_int::from(b'z');
    let upper_a = c_int::from(b'A');
    if (lower_a..=lower_z).contains(&c) {
        c.wrapping_sub(lower_a).wrapping_add(upper_a)
    } else {
        c
    }
}

/// C `memcmp` → nlist `_memcmp`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn memcmp(
    s1: *const c_void,
    s2: *const c_void,
    nbytes: usize,
) -> c_int {
    if nbytes == 0 || s1.is_null() || s2.is_null() {
        return 0;
    }
    // SAFETY: caller guarantees `nbytes` readable bytes on both sides.
    unsafe {
        let left = s1.cast::<u8>();
        let right = s2.cast::<u8>();
        let mut idx = 0_usize;
        while idx < nbytes {
            let left_b = left.add(idx).read();
            let right_b = right.add(idx).read();
            if left_b != right_b {
                return c_int::from(left_b).wrapping_sub(c_int::from(right_b));
            }
            idx = idx.saturating_add(1);
        }
    }
    0
}

/// C `strchr` → nlist `_strchr`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn strchr(s: *const c_char, c: c_int) -> *mut c_char {
    if s.is_null() {
        return core::ptr::null_mut();
    }
    let needle = u8::try_from(c.cast_unsigned() & 0xff).unwrap_or(0);
    // SAFETY: walk until NUL.
    unsafe {
        let mut p = s;
        loop {
            let byte = p.read().cast_unsigned();
            if byte == needle {
                return p.cast_mut();
            }
            if byte == 0 {
                return core::ptr::null_mut();
            }
            p = p.add(1);
        }
    }
}

/// C `strcmp` → nlist `_strcmp`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn strcmp(s1: *const c_char, s2: *const c_char) -> c_int {
    if s1.is_null() || s2.is_null() {
        return 0;
    }
    // SAFETY: NUL-terminated C strings.
    unsafe {
        let mut left = s1;
        let mut right = s2;
        loop {
            let left_b = left.read().cast_unsigned();
            let right_b = right.read().cast_unsigned();
            if left_b != right_b {
                return c_int::from(left_b).wrapping_sub(c_int::from(right_b));
            }
            if left_b == 0 {
                return 0;
            }
            left = left.add(1);
            right = right.add(1);
        }
    }
}

/// C `strstr` → nlist `_strstr`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn strstr(haystack: *const c_char, needle: *const c_char) -> *mut c_char {
    if haystack.is_null() || needle.is_null() {
        return core::ptr::null_mut();
    }
    // SAFETY: NUL-terminated.
    unsafe {
        if needle.read() == 0 {
            return haystack.cast_mut();
        }
        let mut h = haystack;
        while h.read() != 0 {
            let mut a = h;
            let mut b = needle;
            loop {
                let nb = b.read();
                if nb == 0 {
                    return h.cast_mut();
                }
                if a.read() != nb {
                    break;
                }
                a = a.add(1);
                b = b.add(1);
            }
            h = h.add(1);
        }
    }
    core::ptr::null_mut()
}

/// C `strerror` → nlist `_strerror` (static English stubs).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn strerror(errnum: c_int) -> *mut c_char {
    // Minimal static messages; not thread-safe by design of classic strerror.
    static mut BUF: [u8; 32] = *b"Unknown error                  \0";
    let msg: &[u8] = match errnum {
        0 => b"Undefined error: 0\0",
        1 => b"Operation not permitted\0",
        2 => b"No such file or directory\0",
        9 => b"Bad file descriptor\0",
        12 => b"Cannot allocate memory\0",
        13 => b"Permission denied\0",
        14 => b"Bad address\0",
        22 => b"Invalid argument\0",
        78 => b"Function not implemented\0",
        _ => b"Unknown error\0",
    };
    // SAFETY: single static buffer for scaffold guests.
    unsafe {
        let dst = core::ptr::addr_of_mut!(BUF).cast::<u8>();
        let mut i = 0_usize;
        while i < 31 {
            let b = msg.get(i).copied().unwrap_or(0);
            dst.add(i).write(b);
            if b == 0 {
                break;
            }
            i = i.saturating_add(1);
        }
        dst.add(31).write(0);
        dst.cast()
    }
}

/// Darwin `memset_pattern16` → nlist `_memset_pattern16`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn memset_pattern16(b: *mut c_void, pattern16: *const c_void, len: usize) {
    if b.is_null() || pattern16.is_null() || len == 0 {
        return;
    }
    // SAFETY: pattern is 16 bytes; fill `len` bytes of `b`.
    unsafe {
        let dst = b.cast::<u8>();
        let pat = pattern16.cast::<u8>();
        let mut i = 0_usize;
        while i < len {
            let pi = i % 16;
            dst.add(i).write(pat.add(pi).read());
            i = i.saturating_add(1);
        }
    }
}

/// C `mbstowcs` → nlist `_mbstowcs` (ASCII-only).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn mbstowcs(pwcs: *mut Wchar, s: *const c_char, n: usize) -> usize {
    if s.is_null() {
        return usize::MAX;
    }
    // SAFETY: walk multi-byte (treated as single-byte ASCII).
    unsafe {
        let mut i = 0_usize;
        loop {
            let byte = s.add(i).read().cast_unsigned();
            if byte == 0 {
                if !pwcs.is_null() && i < n {
                    pwcs.add(i).write(0);
                }
                return i;
            }
            if !pwcs.is_null() {
                if i >= n {
                    return i;
                }
                pwcs.add(i).write(Wchar::from(byte));
            }
            i = i.saturating_add(1);
        }
    }
}

/// C `wcstombs` → nlist `_wcstombs` (ASCII-only).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn wcstombs(
    out: *mut c_char,
    pwcs: *const Wchar,
    max: usize,
) -> usize {
    if pwcs.is_null() {
        return usize::MAX;
    }
    unsafe {
        let mut idx = 0_usize;
        loop {
            let wide = pwcs.add(idx).read();
            if wide == 0 {
                if !out.is_null() && idx < max {
                    out.add(idx).write(0);
                }
                return idx;
            }
            if !out.is_null() {
                if idx >= max {
                    return idx;
                }
                let byte = u8::try_from(wide.cast_unsigned() & 0xff).unwrap_or(b'?');
                out.add(idx).write(byte.cast_signed());
            }
            idx = idx.saturating_add(1);
        }
    }
}

/// C `wcslen` → nlist `_wcslen`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn wcslen(s: *const Wchar) -> usize {
    if s.is_null() {
        return 0;
    }
    let mut n = 0_usize;
    unsafe {
        while s.add(n).read() != 0 {
            n = n.saturating_add(1);
            if n > (1 << 20) {
                break;
            }
        }
    }
    n
}

/// C `wcscmp` → nlist `_wcscmp`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn wcscmp(s1: *const Wchar, s2: *const Wchar) -> c_int {
    if s1.is_null() || s2.is_null() {
        return 0;
    }
    unsafe {
        let mut left = s1;
        let mut right = s2;
        loop {
            let left_w = left.read();
            let right_w = right.read();
            if left_w != right_w {
                return left_w.wrapping_sub(right_w);
            }
            if left_w == 0 {
                return 0;
            }
            left = left.add(1);
            right = right.add(1);
        }
    }
}

/// C `wcsstr` → nlist `_wcsstr`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn wcsstr(haystack: *const Wchar, needle: *const Wchar) -> *mut Wchar {
    if haystack.is_null() || needle.is_null() {
        return core::ptr::null_mut();
    }
    unsafe {
        if needle.read() == 0 {
            return haystack.cast_mut();
        }
        let mut h = haystack;
        while h.read() != 0 {
            let mut a = h;
            let mut b = needle;
            loop {
                let nb = b.read();
                if nb == 0 {
                    return h.cast_mut();
                }
                if a.read() != nb {
                    break;
                }
                a = a.add(1);
                b = b.add(1);
            }
            h = h.add(1);
        }
    }
    core::ptr::null_mut()
}

/// C `wmemcpy` → nlist `_wmemcpy`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn wmemcpy(dst: *mut Wchar, src: *const Wchar, n: usize) -> *mut Wchar {
    if n > 0 && !dst.is_null() && !src.is_null() {
        let bytes = n.saturating_mul(core::mem::size_of::<Wchar>());
        // SAFETY: non-overlapping wide regions.
        unsafe {
            let _ = memcpy(dst.cast(), src.cast(), bytes);
        }
    }
    dst
}
