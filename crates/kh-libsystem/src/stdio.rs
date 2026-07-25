//! C stdio / string surface (Darwin `write` + host helpers + pure memory ops).

use core::ffi::{c_char, c_int, c_void};

use crate::errno;
use crate::sys::{self, SYS_WRITE};
use crate::trace;
use crate::{KH_HELPER_PRINTF, KH_HELPER_PUTS};

/// C `write` → nlist `_write`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn write(fd: c_int, buf: *const c_void, nbyte: usize) -> isize {
    trace::note_size(b"write", nbyte);
    if buf.is_null() && nbyte > 0 {
        errno::set_errno(14);
        return -1;
    }
    let fd_u = u64::from(fd.cast_unsigned());
    let ptr = ptr_to_u64(buf);
    let len = usize_to_u64(nbyte);
    // SAFETY: caller buffer; Darwin write via trap/host.
    let ret = unsafe { sys::syscall3(SYS_WRITE, fd_u, ptr, len) };
    if ret < 0 {
        errno::set_errno(i32::try_from(ret.saturating_neg()).unwrap_or(1));
    }
    ret
}

/// C `puts` → nlist `_puts`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn puts(s: *const c_char) -> c_int {
    trace::note(b"[kh-libsystem] puts()\n");
    if s.is_null() {
        errno::set_errno(14);
        return -1;
    }
    // SAFETY: helper reads C string.
    let ret = unsafe { sys::helper1(KH_HELPER_PUTS, ptr_to_u64(s.cast())) };
    if ret < 0 {
        errno::set_errno(i32::try_from(ret.saturating_neg()).unwrap_or(1));
        return -1;
    }
    c_int::try_from(ret).unwrap_or(0)
}

/// C `printf` → nlist `_printf` (literal format only for now).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn printf(fmt: *const c_char) -> c_int {
    trace::note(b"[kh-libsystem] printf()\n");
    if fmt.is_null() {
        errno::set_errno(14);
        return -1;
    }
    // SAFETY: helper reads format; no `%` yet.
    let ret = unsafe { sys::helper1(KH_HELPER_PRINTF, ptr_to_u64(fmt.cast())) };
    if ret < 0 {
        errno::set_errno(i32::try_from(ret.saturating_neg()).unwrap_or(1));
        return -1;
    }
    c_int::try_from(ret).unwrap_or(0)
}

/// C `strlen` → nlist `_strlen`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn strlen(s: *const c_char) -> usize {
    if s.is_null() {
        return 0;
    }
    let mut n = 0_usize;
    // SAFETY: walk until NUL.
    unsafe {
        loop {
            let b = s.add(n).read();
            if b == 0 {
                break;
            }
            n = n.saturating_add(1);
            if n > (1 << 20) {
                break;
            }
        }
    }
    n
}

/// C `memcpy` → nlist `_memcpy`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn memcpy(dst: *mut c_void, src: *const c_void, n: usize) -> *mut c_void {
    if n > 0 && !dst.is_null() && !src.is_null() {
        // SAFETY: non-overlapping regions; manual loop (no host memcpy).
        unsafe {
            byte_copy_forward(dst.cast(), src.cast(), n);
        }
    }
    dst
}

/// C `memmove` → nlist `_memmove`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn memmove(dst: *mut c_void, src: *const c_void, n: usize) -> *mut c_void {
    if n > 0 && !dst.is_null() && !src.is_null() {
        // SAFETY: may overlap.
        unsafe {
            let d = dst.cast::<u8>();
            let s = src.cast::<u8>();
            if d.addr() <= s.addr() {
                byte_copy_forward(d, s, n);
            } else {
                byte_copy_backward(d, s, n);
            }
        }
    }
    dst
}

/// C `memset` → nlist `_memset`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn memset(dst: *mut c_void, c: c_int, n: usize) -> *mut c_void {
    if n > 0 && !dst.is_null() {
        let byte = u8::try_from(c.cast_unsigned() & 0xff).unwrap_or(0);
        // SAFETY: valid for n bytes.
        unsafe {
            byte_set(dst.cast(), byte, n);
        }
    }
    dst
}

/// `bzero` → nlist `_bzero`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bzero(dst: *mut c_void, n: usize) {
    if n > 0 && !dst.is_null() {
        // SAFETY: valid for n bytes.
        unsafe {
            byte_set(dst.cast(), 0, n);
        }
    }
}

#[inline]
unsafe fn byte_copy_forward(dst: *mut u8, src: *const u8, n: usize) {
    let mut i = 0_usize;
    while i < n {
        // SAFETY: i < n.
        unsafe {
            dst.add(i).write(src.add(i).read());
        }
        i = i.saturating_add(1);
    }
}

#[inline]
unsafe fn byte_copy_backward(dst: *mut u8, src: *const u8, n: usize) {
    let mut i = n;
    while i > 0 {
        i = i.saturating_sub(1);
        // SAFETY: i < n.
        unsafe {
            dst.add(i).write(src.add(i).read());
        }
    }
}

#[inline]
unsafe fn byte_set(dst: *mut u8, byte: u8, n: usize) {
    let mut i = 0_usize;
    while i < n {
        // SAFETY: i < n.
        unsafe {
            dst.add(i).write(byte);
        }
        i = i.saturating_add(1);
    }
}

#[inline]
fn ptr_to_u64(p: *const c_void) -> u64 {
    u64::try_from(p.addr()).unwrap_or(0)
}

#[inline]
fn usize_to_u64(n: usize) -> u64 {
    u64::try_from(n).unwrap_or(0)
}
