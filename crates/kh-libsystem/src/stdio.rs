//! C stdio / string surface (Darwin `write` + host helpers + pure memory ops).

use core::ffi::{c_char, c_int, c_void};

use crate::errno;
use crate::sys::{self, SYS_READ, SYS_WRITE};
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
///
/// Must not be implemented as `memset(dst, 0, n)` or a plain zeroing loop:
/// freestanding LLVM rewrites those to a call to `bzero` itself, which became
/// `b _bzero` (infinite loop) and hung `7zz a` inside `VariantCopy`.
/// Volatile stores prevent that recognition.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bzero(dst: *mut c_void, n: usize) {
    if dst.is_null() || n == 0 {
        return;
    }
    let p = dst.cast::<u8>();
    let mut i = 0_usize;
    while i < n {
        // SAFETY: `i < n` bytes at `dst`.
        unsafe {
            core::ptr::write_volatile(p.add(i), 0);
        }
        i = i.saturating_add(1);
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

// ── stdio FILE* globals (opaque stubs for libc++ / C guests) ────────────────

/// Opaque stand-in for Darwin `FILE` (layout not exposed to guests).
#[repr(C)]
struct FileStub {
    fd: c_int,
    flags: u32,
    err: c_int,
    _pad: [u8; 52],
}

const FILE_EOF: u32 = 1;
const FILE_ERR: u32 = 2;

static mut STDIN_FILE: FileStub = FileStub {
    fd: 0,
    flags: 0,
    err: 0,
    _pad: [0; 52],
};
static mut STDOUT_FILE: FileStub = FileStub {
    fd: 1,
    flags: 0,
    err: 0,
    _pad: [0; 52],
};
static mut STDERR_FILE: FileStub = FileStub {
    fd: 2,
    flags: 0,
    err: 0,
    _pad: [0; 52],
};

/// `FILE *__stdinp` → nlist `___stdinp`.
#[unsafe(export_name = "__stdinp")]
#[used]
static mut STDINP: *mut FileStub = core::ptr::addr_of_mut!(STDIN_FILE);

/// `FILE *__stdoutp` → nlist `___stdoutp`.
#[unsafe(export_name = "__stdoutp")]
#[used]
static mut STDOUTP: *mut FileStub = core::ptr::addr_of_mut!(STDOUT_FILE);

/// `FILE *__stderrp` → nlist `___stderrp`.
#[unsafe(export_name = "__stderrp")]
#[used]
static mut STDERRP: *mut FileStub = core::ptr::addr_of_mut!(STDERR_FILE);

#[inline]
unsafe fn as_file(stream: *mut c_void) -> *mut FileStub {
    stream.cast()
}

/// C `fileno` → nlist `_fileno`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn fileno(stream: *mut c_void) -> c_int {
    if stream.is_null() {
        errno::set_errno(9);
        return -1;
    }
    unsafe { (*as_file(stream)).fd }
}

/// C `feof` → nlist `_feof`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn feof(stream: *mut c_void) -> c_int {
    if stream.is_null() {
        return 0;
    }
    unsafe { i32::from(((*as_file(stream)).flags & FILE_EOF) != 0) }
}

/// C `ferror` → nlist `_ferror`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn ferror(stream: *mut c_void) -> c_int {
    if stream.is_null() {
        return 0;
    }
    unsafe { i32::from(((*as_file(stream)).flags & FILE_ERR) != 0) }
}

/// C `fflush` → nlist `_fflush` (no buffering).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn fflush(_stream: *mut c_void) -> c_int {
    0
}

/// C `fputc` → nlist `_fputc`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn fputc(c: c_int, stream: *mut c_void) -> c_int {
    if stream.is_null() {
        errno::set_errno(9);
        return -1;
    }
    let f = unsafe { as_file(stream) };
    let byte = [u8::try_from(c.cast_unsigned() & 0xff).unwrap_or(0)];
    let fd = unsafe { (*f).fd };
    let ret = unsafe { write(fd, byte.as_ptr().cast(), 1) };
    if ret < 0 {
        unsafe {
            (*f).flags |= FILE_ERR;
            (*f).err = 1;
        }
        return -1;
    }
    c & 0xff
}

/// C `fputs` → nlist `_fputs`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn fputs(s: *const c_char, stream: *mut c_void) -> c_int {
    if stream.is_null() || s.is_null() {
        errno::set_errno(9);
        return -1;
    }
    let f = unsafe { as_file(stream) };
    let n = unsafe { strlen(s) };
    let fd = unsafe { (*f).fd };
    let ret = unsafe { write(fd, s.cast(), n) };
    if ret < 0 {
        unsafe {
            (*f).flags |= FILE_ERR;
        }
        return -1;
    }
    0
}

/// C `fgetc` → nlist `_fgetc`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn fgetc(stream: *mut c_void) -> c_int {
    if stream.is_null() {
        errno::set_errno(9);
        return -1; // EOF
    }
    let f = unsafe { as_file(stream) };
    let mut byte = [0_u8; 1];
    let fd = unsafe { (*f).fd };
    let fd_u = u64::from(fd.cast_unsigned());
    let n = unsafe { sys::syscall3(SYS_READ, fd_u, ptr_to_u64(byte.as_mut_ptr().cast()), 1) };
    if n <= 0 {
        unsafe {
            (*f).flags |= FILE_EOF;
        }
        return -1; // EOF
    }
    c_int::from(byte[0])
}

#[inline]
fn usize_to_u64(n: usize) -> u64 {
    u64::try_from(n).unwrap_or(0)
}
