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
pub(crate) unsafe extern "C" fn strstr(
    haystack: *const c_char,
    needle: *const c_char,
) -> *mut c_char {
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

/// Static English errno messages (shared by `strerror` / `strerror_r`).
fn strerror_msg(errnum: c_int) -> &'static [u8] {
    match errnum {
        0 => b"Undefined error: 0\0",
        1 => b"Operation not permitted\0",
        2 => b"No such file or directory\0",
        3 => b"No such process\0",
        4 => b"Interrupted system call\0",
        5 => b"Input/output error\0",
        6 => b"Device not configured\0",
        7 => b"Argument list too long\0",
        8 => b"Exec format error\0",
        9 => b"Bad file descriptor\0",
        10 => b"No child processes\0",
        // Darwin: EDEADLK=11; Linux EAGAIN=11 — either is fine as text.
        11 => b"Resource deadlock avoided\0",
        12 => b"Cannot allocate memory\0",
        13 => b"Permission denied\0",
        14 => b"Bad address\0",
        17 => b"File exists\0",
        20 => b"Not a directory\0",
        21 => b"Is a directory\0",
        22 => b"Invalid argument\0",
        24 => b"Too many open files\0",
        28 => b"No space left on device\0",
        32 => b"Broken pipe\0",
        // Darwin EAGAIN / EWOULDBLOCK
        35 => b"Resource temporarily unavailable\0",
        36 => b"Operation now in progress\0",
        37 => b"Operation already in progress\0",
        38 => b"Socket operation on non-socket\0",
        39 => b"Destination address required\0",
        40 => b"Message too long\0",
        41 => b"Protocol wrong type for socket\0",
        42 => b"Protocol not available\0",
        43 => b"Protocol not supported\0",
        44 => b"Socket type not supported\0",
        45 => b"Operation not supported\0",
        46 => b"Protocol family not supported\0",
        47 => b"Address family not supported by protocol family\0",
        48 => b"Address already in use\0",
        49 => b"Can't assign requested address\0",
        50 => b"Network is down\0",
        51 => b"Network is unreachable\0",
        52 => b"Network dropped connection on reset\0",
        53 => b"Software caused connection abort\0",
        54 => b"Connection reset by peer\0",
        55 => b"No buffer space available\0",
        56 => b"Socket is already connected\0",
        57 => b"Socket is not connected\0",
        58 => b"Can't send after socket shutdown\0",
        60 => b"Operation timed out\0",
        61 => b"Connection refused\0",
        64 => b"Host is down\0",
        65 => b"No route to host\0",
        78 => b"Function not implemented\0",
        _ => b"Unknown error\0",
    }
}

/// C `strerror` → nlist `_strerror` (static English stubs).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn strerror(errnum: c_int) -> *mut c_char {
    // Minimal static messages; not thread-safe by design of classic strerror.
    static mut BUF: [u8; 64] = [0; 64];
    let msg = strerror_msg(errnum);
    // SAFETY: single static buffer for scaffold guests.
    unsafe {
        let dst = core::ptr::addr_of_mut!(BUF).cast::<u8>();
        let mut i = 0_usize;
        while i < 63 {
            let b = msg.get(i).copied().unwrap_or(0);
            dst.add(i).write(b);
            if b == 0 {
                break;
            }
            i = i.saturating_add(1);
        }
        dst.add(63).write(0);
        dst.cast()
    }
}

/// POSIX/XSI `strerror_r` → nlist `_strerror_r` (Darwin; returns 0 / ERANGE).
///
/// curl calls this after a completed transfer when formatting diagnostics.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn strerror_r(
    errnum: c_int,
    buf: *mut c_char,
    buflen: usize,
) -> c_int {
    if buf.is_null() || buflen == 0 {
        return 22; // EINVAL
    }
    let msg = strerror_msg(errnum);
    // Message length excluding trailing NUL.
    let mut msg_len = 0_usize;
    while msg.get(msg_len).copied().unwrap_or(0) != 0 {
        msg_len = msg_len.saturating_add(1);
    }
    if buflen <= msg_len {
        // Truncate and NUL-terminate; report ERANGE (34 on Darwin).
        unsafe {
            let n = buflen.saturating_sub(1);
            let mut i = 0_usize;
            while i < n {
                buf.add(i)
                    .write(msg.get(i).copied().unwrap_or(0).cast_signed());
                i = i.saturating_add(1);
            }
            buf.add(n).write(0);
        }
        return 34; // ERANGE
    }
    unsafe {
        let mut i = 0_usize;
        while i < msg_len {
            buf.add(i)
                .write(msg.get(i).copied().unwrap_or(0).cast_signed());
            i = i.saturating_add(1);
        }
        buf.add(msg_len).write(0);
    }
    0
}

/// Darwin `memset_pattern16` → nlist `_memset_pattern16`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn memset_pattern16(
    b: *mut c_void,
    pattern16: *const c_void,
    len: usize,
) {
    // Reject PAGEZERO / null (low 4 GiB is never a live guest buffer under kh).
    if len == 0
        || b.is_null()
        || b.addr() < crate::stdio::PAGEZERO_END
        || pattern16.is_null()
        || pattern16.addr() < crate::stdio::PAGEZERO_END
    {
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
pub(crate) unsafe extern "C" fn wmemcpy(
    dst: *mut Wchar,
    src: *const Wchar,
    n: usize,
) -> *mut Wchar {
    if n > 0 && !dst.is_null() && !src.is_null() {
        let bytes = n.saturating_mul(core::mem::size_of::<Wchar>());
        // SAFETY: non-overlapping wide regions.
        unsafe {
            let _ = memcpy(dst.cast(), src.cast(), bytes);
        }
    }
    dst
}

// ── curl G1 string surface (from Docker unresolved list) ────────────────────

/// C `strdup` → nlist `_strdup`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn strdup(s: *const c_char) -> *mut c_char {
    if s.is_null() {
        return core::ptr::null_mut();
    }
    let n = unsafe { crate::stdio::strlen(s) };
    let total = n.saturating_add(1);
    let p = unsafe { crate::malloc(total).cast::<c_char>() };
    if p.is_null() {
        return core::ptr::null_mut();
    }
    unsafe {
        let _ = memcpy(p.cast(), s.cast(), total);
    }
    p
}

/// C `strcpy` → nlist `_strcpy`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn strcpy(dst: *mut c_char, src: *const c_char) -> *mut c_char {
    if dst.is_null() || src.is_null() {
        return dst;
    }
    unsafe {
        let n = crate::stdio::strlen(src).saturating_add(1);
        let _ = memcpy(dst.cast(), src.cast(), n);
    }
    dst
}

/// C `strncpy` → nlist `_strncpy`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn strncpy(
    dst: *mut c_char,
    src: *const c_char,
    n: usize,
) -> *mut c_char {
    if dst.is_null() || n == 0 {
        return dst;
    }
    if src.is_null() {
        unsafe {
            let _ = crate::stdio::memset(dst.cast(), 0, n);
        }
        return dst;
    }
    unsafe {
        let mut i = 0_usize;
        while i < n {
            let b = src.add(i).read();
            dst.add(i).write(b);
            if b == 0 {
                i = i.saturating_add(1);
                while i < n {
                    dst.add(i).write(0);
                    i = i.saturating_add(1);
                }
                break;
            }
            i = i.saturating_add(1);
        }
    }
    dst
}

/// C `strcat` → nlist `_strcat`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn strcat(dst: *mut c_char, src: *const c_char) -> *mut c_char {
    if dst.is_null() || src.is_null() {
        return dst;
    }
    unsafe {
        let end = dst.add(crate::stdio::strlen(dst));
        let _ = strcpy(end, src);
    }
    dst
}

/// C `strncmp` → nlist `_strncmp`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn strncmp(s1: *const c_char, s2: *const c_char, n: usize) -> c_int {
    if n == 0 || s1.is_null() || s2.is_null() {
        return 0;
    }
    unsafe {
        let mut i = 0_usize;
        while i < n {
            let a = s1.add(i).read().cast_unsigned();
            let b = s2.add(i).read().cast_unsigned();
            if a != b {
                return c_int::from(a).wrapping_sub(c_int::from(b));
            }
            if a == 0 {
                return 0;
            }
            i = i.saturating_add(1);
        }
    }
    0
}

/// C `memchr` → nlist `_memchr`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn memchr(
    haystack: *const c_void,
    ch: c_int,
    nbytes: usize,
) -> *mut c_void {
    if haystack.is_null() || nbytes == 0 {
        return core::ptr::null_mut();
    }
    let needle = u8::try_from(ch.cast_unsigned() & 0xff).unwrap_or(0);
    unsafe {
        let base = haystack.cast::<u8>();
        let mut idx = 0_usize;
        while idx < nbytes {
            if base.add(idx).read() == needle {
                return base.add(idx).cast_mut().cast();
            }
            idx = idx.saturating_add(1);
        }
    }
    core::ptr::null_mut()
}

/// C `atoi` → nlist `_atoi` (ASCII decimal, no errno).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn atoi(s: *const c_char) -> c_int {
    if s.is_null() {
        return 0;
    }
    unsafe {
        let mut p = s;
        // skip leading space
        loop {
            let b = p.read().cast_unsigned();
            if b == 0 {
                return 0;
            }
            if b == b' ' || b == b'\t' || b == b'\n' || b == b'\r' || b == b'\x0b' || b == b'\x0c' {
                p = p.add(1);
                continue;
            }
            break;
        }
        let mut sign = 1_i32;
        let b0 = p.read().cast_unsigned();
        if b0 == b'+' {
            p = p.add(1);
        } else if b0 == b'-' {
            sign = -1;
            p = p.add(1);
        }
        let mut acc = 0_i32;
        loop {
            let b = p.read().cast_unsigned();
            if !b.is_ascii_digit() {
                break;
            }
            let digit = i32::from(b.wrapping_sub(b'0'));
            acc = acc.saturating_mul(10).saturating_add(digit);
            p = p.add(1);
        }
        acc.saturating_mul(sign)
    }
}

/// C `isdigit` → nlist `_isdigit`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn isdigit(c: c_int) -> c_int {
    let u = c.cast_unsigned();
    c_int::from((u >= u32::from(b'0')) && (u <= u32::from(b'9')))
}

/// C `isspace` → nlist `_isspace`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn isspace(c: c_int) -> c_int {
    if c < 0 {
        return 0;
    }
    let u = c.cast_unsigned();
    c_int::from(
        u == u32::from(b' ')
            || u == u32::from(b'\t')
            || u == u32::from(b'\n')
            || u == u32::from(b'\r')
            || u == u32::from(b'\x0b')
            || u == u32::from(b'\x0c'),
    )
}

/// C `isupper` → nlist `_isupper`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn isupper(c: c_int) -> c_int {
    let u = c.cast_unsigned();
    c_int::from((u >= u32::from(b'A')) && (u <= u32::from(b'Z')))
}

/// C `tolower` → nlist `_tolower`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn tolower(c: c_int) -> c_int {
    let upper_a = c_int::from(b'A');
    let upper_z = c_int::from(b'Z');
    if (upper_a..=upper_z).contains(&c) {
        c.wrapping_sub(upper_a).wrapping_add(c_int::from(b'a'))
    } else {
        c
    }
}

/// C `strcasecmp` → nlist `_strcasecmp`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn strcasecmp(s1: *const c_char, s2: *const c_char) -> c_int {
    if s1.is_null() || s2.is_null() {
        return 0;
    }
    unsafe {
        let mut left = s1;
        let mut right = s2;
        loop {
            let a = tolower(c_int::from(left.read().cast_unsigned()));
            let b = tolower(c_int::from(right.read().cast_unsigned()));
            if a != b {
                return a.wrapping_sub(b);
            }
            if a == 0 {
                return 0;
            }
            left = left.add(1);
            right = right.add(1);
        }
    }
}

/// C `strncasecmp` → nlist `_strncasecmp`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn strncasecmp(
    s1: *const c_char,
    s2: *const c_char,
    n: usize,
) -> c_int {
    if n == 0 || s1.is_null() || s2.is_null() {
        return 0;
    }
    unsafe {
        let mut i = 0_usize;
        while i < n {
            let a = tolower(c_int::from(s1.add(i).read().cast_unsigned()));
            let b = tolower(c_int::from(s2.add(i).read().cast_unsigned()));
            if a != b {
                return a.wrapping_sub(b);
            }
            if a == 0 {
                return 0;
            }
            i = i.saturating_add(1);
        }
    }
    0
}

/// C `strrchr` → nlist `_strrchr`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn strrchr(s: *const c_char, c: c_int) -> *mut c_char {
    if s.is_null() {
        return core::ptr::null_mut();
    }
    let needle = u8::try_from(c.cast_unsigned() & 0xff).unwrap_or(0);
    let mut last: *mut c_char = core::ptr::null_mut();
    unsafe {
        let mut p = s;
        loop {
            let byte = p.read().cast_unsigned();
            if byte == needle {
                last = p.cast_mut();
            }
            if byte == 0 {
                return last;
            }
            p = p.add(1);
        }
    }
}

/// C `strnlen` → nlist `_strnlen`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn strnlen(s: *const c_char, maxlen: usize) -> usize {
    if s.is_null() || maxlen == 0 {
        return 0;
    }
    let mut n = 0_usize;
    unsafe {
        while n < maxlen {
            if s.add(n).read() == 0 {
                break;
            }
            n = n.saturating_add(1);
        }
    }
    n
}

/// C `strtol` → nlist `_strtol`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn strtol(
    s: *const c_char,
    endp: *mut *mut c_char,
    base: c_int,
) -> i64 {
    unsafe { strto_i64(s, endp, base) }
}

/// C `strtoll` → nlist `_strtoll`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn strtoll(
    s: *const c_char,
    endp: *mut *mut c_char,
    base: c_int,
) -> i64 {
    unsafe { strto_i64(s, endp, base) }
}

/// C `strtoul` → nlist `_strtoul`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn strtoul(
    s: *const c_char,
    endp: *mut *mut c_char,
    base: c_int,
) -> u64 {
    let v = unsafe { strto_i64(s, endp, base) };
    v.cast_unsigned()
}

/// C `strtoimax` → nlist `_strtoimax`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn strtoimax(
    s: *const c_char,
    endp: *mut *mut c_char,
    base: c_int,
) -> i64 {
    unsafe { strto_i64(s, endp, base) }
}

/// C `strtoumax` → nlist `_strtoumax`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn strtoumax(
    s: *const c_char,
    endp: *mut *mut c_char,
    base: c_int,
) -> u64 {
    let v = unsafe { strto_i64(s, endp, base) };
    v.cast_unsigned()
}

unsafe fn strto_i64(s: *const c_char, endp: *mut *mut c_char, base: c_int) -> i64 {
    if s.is_null() {
        return 0;
    }
    let mut p = s;
    unsafe {
        // skip spaces
        loop {
            let b = p.read().cast_unsigned();
            if b == 0 {
                if !endp.is_null() {
                    endp.write(p.cast_mut());
                }
                return 0;
            }
            if isspace(c_int::from(b)) != 0 {
                p = p.add(1);
                continue;
            }
            break;
        }
        let mut sign = 1_i64;
        let b0 = p.read().cast_unsigned();
        if b0 == b'+' {
            p = p.add(1);
        } else if b0 == b'-' {
            sign = -1;
            p = p.add(1);
        }
        let mut radix = base;
        if radix == 0 {
            if p.read().cast_unsigned() == b'0' {
                let n = p.add(1).read().cast_unsigned();
                if n == b'x' || n == b'X' {
                    radix = 16;
                    p = p.add(2);
                } else {
                    radix = 8;
                }
            } else {
                radix = 10;
            }
        } else if radix == 16 && p.read().cast_unsigned() == b'0' && {
            let n = p.add(1).read().cast_unsigned();
            n == b'x' || n == b'X'
        } {
            p = p.add(2);
        }
        if !(2..=36).contains(&radix) {
            if !endp.is_null() {
                endp.write(s.cast_mut());
            }
            return 0;
        }
        let radix_u = u32::try_from(radix).unwrap_or(10);
        let mut acc = 0_i64;
        let start = p;
        loop {
            let b = p.read().cast_unsigned();
            let digit = if b.is_ascii_digit() {
                u32::from(b.wrapping_sub(b'0'))
            } else if b.is_ascii_lowercase() {
                u32::from(b.wrapping_sub(b'a')).saturating_add(10)
            } else if b.is_ascii_uppercase() {
                u32::from(b.wrapping_sub(b'A')).saturating_add(10)
            } else {
                break;
            };
            if digit >= radix_u {
                break;
            }
            acc = acc
                .saturating_mul(i64::from(radix_u))
                .saturating_add(i64::from(digit));
            p = p.add(1);
        }
        if p == start {
            if !endp.is_null() {
                endp.write(s.cast_mut());
            }
            return 0;
        }
        if !endp.is_null() {
            endp.write(p.cast_mut());
        }
        acc.saturating_mul(sign)
    }
}

/// C `strcspn` → nlist `_strcspn`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn strcspn(s: *const c_char, reject: *const c_char) -> usize {
    if s.is_null() {
        return 0;
    }
    unsafe {
        let mut n = 0_usize;
        loop {
            let b = s.add(n).read();
            if b == 0 {
                return n;
            }
            if !reject.is_null() && !strchr(reject, c_int::from(b.cast_unsigned())).is_null() {
                return n;
            }
            n = n.saturating_add(1);
        }
    }
}

/// C `strspn` → nlist `_strspn`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn strspn(s: *const c_char, accept: *const c_char) -> usize {
    if s.is_null() {
        return 0;
    }
    unsafe {
        let mut n = 0_usize;
        loop {
            let b = s.add(n).read();
            if b == 0 {
                return n;
            }
            if accept.is_null() || strchr(accept, c_int::from(b.cast_unsigned())).is_null() {
                return n;
            }
            n = n.saturating_add(1);
        }
    }
}

/// C `strpbrk` → nlist `_strpbrk`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn strpbrk(s: *const c_char, accept: *const c_char) -> *mut c_char {
    if s.is_null() || accept.is_null() {
        return core::ptr::null_mut();
    }
    unsafe {
        let mut p = s;
        loop {
            let b = p.read();
            if b == 0 {
                return core::ptr::null_mut();
            }
            if !strchr(accept, c_int::from(b.cast_unsigned())).is_null() {
                return p.cast_mut();
            }
            p = p.add(1);
        }
    }
}

/// C `memmem` → nlist `_memmem`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn memmem(
    haystack: *const c_void,
    haystacklen: usize,
    needle: *const c_void,
    needlelen: usize,
) -> *mut c_void {
    if needlelen == 0 {
        return haystack.cast_mut();
    }
    if haystack.is_null() || needle.is_null() || haystacklen < needlelen {
        return core::ptr::null_mut();
    }
    unsafe {
        let h = haystack.cast::<u8>();
        let n = needle.cast::<u8>();
        let last = haystacklen.saturating_sub(needlelen);
        let mut i = 0_usize;
        while i <= last {
            if memcmp(h.add(i).cast(), n.cast(), needlelen) == 0 {
                return h.add(i).cast::<c_void>().cast_mut();
            }
            i = i.saturating_add(1);
        }
    }
    core::ptr::null_mut()
}

/// C11 `memset_s` → nlist `_memset_s` (returns 0 / EINVAL).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn memset_s(s: *mut c_void, smax: usize, c: c_int, n: usize) -> c_int {
    if s.is_null() && (smax > 0 || n > 0) {
        return 22; // EINVAL
    }
    if n > smax {
        if !s.is_null() && smax > 0 {
            let _ = unsafe { crate::stdio::memset(s, c, smax) };
        }
        return 22;
    }
    if n > 0 && !s.is_null() {
        let _ = unsafe { crate::stdio::memset(s, c, n) };
    }
    0
}

/// C `basename` → nlist `_basename` (may mutate path; POSIX/GNU-ish).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn basename(path: *mut c_char) -> *mut c_char {
    static mut DOT: [u8; 2] = *b".\0";
    if path.is_null() {
        return core::ptr::addr_of_mut!(DOT).cast();
    }
    unsafe {
        // Empty → "."
        if path.read() == 0 {
            return core::ptr::addr_of_mut!(DOT).cast();
        }
        // Walk to end.
        let mut end = path;
        while end.read() != 0 {
            end = end.add(1);
        }
        // Strip trailing slashes (but keep a single "/" root).
        while end > path {
            let prev = end.sub(1);
            if prev.read() != b'/'.cast_signed() {
                break;
            }
            end = prev;
            end.write(0);
        }
        if path.read() == 0 {
            // Was all slashes.
            path.write(b'/'.cast_signed());
            path.add(1).write(0);
            return path;
        }
        // Find last slash.
        let mut p = end;
        while p > path {
            let prev = p.sub(1);
            if prev.read() == b'/'.cast_signed() {
                return p;
            }
            p = prev;
        }
        path
    }
}

// Darwin fortify wrappers (curl imports these; bounds not enforced yet).

/// `___strlcpy_chk` → nlist `___strlcpy_chk` (git init HEAD / path copy).
#[unsafe(export_name = "__strlcpy_chk")]
pub(crate) unsafe extern "C" fn __strlcpy_chk(
    dst: *mut c_char,
    src: *const c_char,
    size: usize,
    _dstlen: usize,
) -> usize {
    unsafe { crate::posix::strlcpy(dst, src, size) }
}

/// `___strcpy_chk` → nlist `___strcpy_chk`.
#[unsafe(export_name = "__strcpy_chk")]
pub(crate) unsafe extern "C" fn __strcpy_chk(
    dst: *mut c_char,
    src: *const c_char,
    _dstlen: usize,
) -> *mut c_char {
    unsafe { strcpy(dst, src) }
}

/// `___strncpy_chk` → nlist `___strncpy_chk`.
#[unsafe(export_name = "__strncpy_chk")]
pub(crate) unsafe extern "C" fn __strncpy_chk(
    dst: *mut c_char,
    src: *const c_char,
    len: usize,
    _dstlen: usize,
) -> *mut c_char {
    unsafe { strncpy(dst, src, len) }
}

/// `___strcat_chk` → nlist `___strcat_chk`.
#[unsafe(export_name = "__strcat_chk")]
pub(crate) unsafe extern "C" fn __strcat_chk(
    dst: *mut c_char,
    src: *const c_char,
    _dstlen: usize,
) -> *mut c_char {
    unsafe { strcat(dst, src) }
}

/// `___memcpy_chk` → nlist `___memcpy_chk`.
#[unsafe(export_name = "__memcpy_chk")]
pub(crate) unsafe extern "C" fn __memcpy_chk(
    dst: *mut c_void,
    src: *const c_void,
    len: usize,
    _dstlen: usize,
) -> *mut c_void {
    unsafe { memcpy(dst, src, len) }
}

/// `___memmove_chk` → nlist `___memmove_chk`.
#[unsafe(export_name = "__memmove_chk")]
pub(crate) unsafe extern "C" fn __memmove_chk(
    dst: *mut c_void,
    src: *const c_void,
    len: usize,
    _dstlen: usize,
) -> *mut c_void {
    unsafe { crate::stdio::memmove(dst, src, len) }
}

/// `___memset_chk` → nlist `___memset_chk`.
#[unsafe(export_name = "__memset_chk")]
pub(crate) unsafe extern "C" fn __memset_chk(
    dst: *mut c_void,
    c: c_int,
    len: usize,
    _dstlen: usize,
) -> *mut c_void {
    unsafe { crate::stdio::memset(dst, c, len) }
}
