//! C stdio / string surface (Darwin `write` + host helpers + pure memory ops).

use core::ffi::{c_char, c_int, c_void};

use crate::errno;
use crate::sys::{self, SYS_READ, SYS_WRITE};
use crate::trace;
use crate::KH_HELPER_PUTS;

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
        // POSIX `ssize_t` error: always -1 + errno (not -errno).
        return -1;
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

// Variadic *printf lives in `printf_fmt.c` (stable Rust has no c_variadic):
// `printf`, `fprintf`, `vprintf`, `vfprintf`, `snprintf`, …

/// Darwin MH_EXECUTE `__PAGEZERO` is 4 GiB — low canonical addresses are never
/// valid guest data. MH_DYLIB freestanding images use low preferred VAs but are
/// always **slid** at load, so live pointers are `preferred + slide` (>> 32-bit).
pub(crate) const PAGEZERO_END: usize = 0x1_0000_0000;

/// True when `p` is outside the unmapped low 4 GiB (Darwin PAGEZERO).
#[inline]
pub(crate) fn ptr_usable(p: *const c_void) -> bool {
    p.addr() >= PAGEZERO_END
}

/// C `strlen` → nlist `_strlen`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn strlen(s: *const c_char) -> usize {
    // Reject PAGEZERO / null — unrebased pointers SEGV here otherwise (G4).
    if s.is_null() || s.addr() < PAGEZERO_END {
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
    if n > 0 && ptr_usable(dst) && ptr_usable(src) {
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
    if n > 0 && ptr_usable(dst) && ptr_usable(src) {
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
    if n > 0 && ptr_usable(dst) {
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

/// C `flockfile` → nlist `_flockfile` (stdio per-FILE lock).
///
/// Freestanding single-guest-thread model: no-op. Real Darwin locks the
/// `FILE*`; git only needs the symbol present for `--version` / early boot.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn flockfile(_stream: *mut c_void) {}

/// C `funlockfile` → nlist `_funlockfile`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn funlockfile(_stream: *mut c_void) {}

/// C `ftrylockfile` → nlist `_ftrylockfile` (0 = locked).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn ftrylockfile(_stream: *mut c_void) -> c_int {
    0
}

/// Darwin `___srget` — refill/`getc` helper used by stdio macros.
///
/// Soft path: one-byte `read` from the stub fd. Returns the byte or `EOF` (−1).
// Darwin prepends `_` to `export_name`, so `__srget` → Mach-O `___srget`.
#[unsafe(export_name = "__srget")]
pub(crate) unsafe extern "C" fn srget(stream: *mut c_void) -> c_int {
    if stream.is_null() {
        return -1;
    }
    // SAFETY: guest FILE* is our FileStub.
    let f = unsafe { as_file(stream) };
    if f.is_null() {
        return -1;
    }
    let fd = unsafe { (*f).fd };
    let mut b = 0_u8;
    let ptr = ptr_to_u64(core::ptr::from_mut(&mut b).cast::<c_void>());
    let ret = unsafe {
        sys::syscall3(SYS_READ, u64::from(fd.cast_unsigned()), ptr, 1)
    };
    if ret <= 0 {
        unsafe {
            (*f).flags |= FILE_EOF;
        }
        return -1;
    }
    c_int::from(b)
}

/// Darwin `___swbuf` — putc/flush helper used by stdio macros.
///
/// Soft path: one-byte `write` to the stub fd. Returns `c` or `EOF`.
#[unsafe(export_name = "__swbuf")]
pub(crate) unsafe extern "C" fn swbuf(c: c_int, stream: *mut c_void) -> c_int {
    if stream.is_null() {
        return -1;
    }
    let f = unsafe { as_file(stream) };
    if f.is_null() {
        return -1;
    }
    let fd = unsafe { (*f).fd };
    let b = u8::try_from(c & 0xff).unwrap_or(0);
    let ptr = ptr_to_u64(core::ptr::from_ref(&b).cast::<c_void>());
    let ret = unsafe {
        sys::syscall3(SYS_WRITE, u64::from(fd.cast_unsigned()), ptr, 1)
    };
    if ret <= 0 {
        unsafe {
            (*f).flags |= FILE_ERR;
        }
        return -1;
    }
    c & 0xff
}

#[inline]
unsafe fn as_file(stream: *mut c_void) -> *mut FileStub {
    stream.cast()
}

/// Darwin open flags (subset; matches runtime translation).
const O_RDONLY: c_int = 0;
const O_WRONLY: c_int = 1;
const O_RDWR: c_int = 2;
const O_APPEND: c_int = 0x0008;
const O_CREAT: c_int = 0x0200;
const O_TRUNC: c_int = 0x0400;

/// Parse a simple fopen mode string into Darwin open flags + default mode bits.
fn open_flags_from_mode(mode: *const c_char) -> Option<(c_int, c_int)> {
    if mode.is_null() {
        return None;
    }
    // SAFETY: NUL-terminated mode from guest ("r", "rb", "w+", …).
    let m0 = unsafe { *mode };
    if m0 == 0 {
        return None;
    }
    // Scan for '+' / 'a' / 'w' / 'r' as unsigned bytes.
    let mut has_plus = false;
    let mut kind = m0.cast_unsigned();
    let mut i = 0_usize;
    while i < 8 {
        // SAFETY: stop at NUL within short mode strings.
        let c = unsafe { (*mode.add(i)).cast_unsigned() };
        if c == 0 {
            break;
        }
        if c == b'+' {
            has_plus = true;
        } else if c == b'a' || c == b'w' || c == b'r' {
            kind = c;
        }
        i = i.saturating_add(1);
    }
    let (flags, creat_mode) = if kind == b'w' {
        if has_plus {
            (O_RDWR | O_CREAT | O_TRUNC, 0o666)
        } else {
            (O_WRONLY | O_CREAT | O_TRUNC, 0o666)
        }
    } else if kind == b'a' {
        if has_plus {
            (O_RDWR | O_CREAT | O_APPEND, 0o666)
        } else {
            (O_WRONLY | O_CREAT | O_APPEND, 0o666)
        }
    } else if has_plus {
        (O_RDWR, 0)
    } else {
        (O_RDONLY, 0)
    };
    Some((flags, creat_mode))
}

fn file_from_fd(fd: c_int) -> *mut FileStub {
    if fd < 0 {
        return core::ptr::null_mut();
    }
    let raw = unsafe { crate::heap::malloc(core::mem::size_of::<FileStub>()) };
    if raw.is_null() {
        errno::set_errno(12);
        return core::ptr::null_mut();
    }
    let f = raw.cast::<FileStub>();
    // Zero the whole stub then set fd (pad field is intentionally anonymous).
    unsafe {
        core::ptr::write_bytes(f.cast::<u8>(), 0, core::mem::size_of::<FileStub>());
        (*f).fd = fd;
    }
    f
}

/// C `fopen` → nlist `_fopen`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn fopen(path: *const c_char, mode: *const c_char) -> *mut c_void {
    let Some((flags, creat_mode)) = open_flags_from_mode(mode) else {
        errno::set_errno(22);
        return core::ptr::null_mut();
    };
    if path.is_null() {
        errno::set_errno(14);
        return core::ptr::null_mut();
    }
    // SAFETY: path/mode from guest; open is our BSD wrapper.
    let fd = unsafe { crate::posix::open(path, flags, creat_mode) };
    file_from_fd(fd).cast()
}

/// Darwin `$DARWIN_EXTSN` symbol variant of `fopen`.
#[unsafe(export_name = "fopen$DARWIN_EXTSN")]
pub(crate) unsafe extern "C" fn fopen_darwin_extsn(
    path: *const c_char,
    mode: *const c_char,
) -> *mut c_void {
    // SAFETY: same as fopen.
    unsafe { fopen(path, mode) }
}

/// C `fdopen` → nlist `_fdopen`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn fdopen(fd: c_int, mode: *const c_char) -> *mut c_void {
    let _ = mode;
    if fd < 0 {
        errno::set_errno(9);
        return core::ptr::null_mut();
    }
    file_from_fd(fd).cast()
}

/// C `fclose` → nlist `_fclose`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn fclose(stream: *mut c_void) -> c_int {
    if stream.is_null() {
        errno::set_errno(9);
        return -1;
    }
    // Do not free/close std streams.
    let p = stream.cast::<FileStub>();
    if core::ptr::eq(p, core::ptr::addr_of_mut!(STDIN_FILE))
        || core::ptr::eq(p, core::ptr::addr_of_mut!(STDOUT_FILE))
        || core::ptr::eq(p, core::ptr::addr_of_mut!(STDERR_FILE))
    {
        return 0;
    }
    let fd = unsafe { (*p).fd };
    let rc = unsafe { crate::posix::close(fd) };
    unsafe {
        crate::heap::free(stream);
    }
    rc
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

/// C `putc` → nlist `_putc` (same as `fputc`; git log pretty-print).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn putc(c: c_int, stream: *mut c_void) -> c_int {
    unsafe { fputc(c, stream) }
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

/// C `fgets` → nlist `_fgets` (OpenSSL PEM reader for bottle CA bundle).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn fgets(
    s: *mut c_char,
    size: c_int,
    stream: *mut c_void,
) -> *mut c_char {
    if s.is_null() || stream.is_null() || size <= 0 {
        return core::ptr::null_mut();
    }
    let max = usize::try_from(size).unwrap_or(0);
    if max == 0 {
        return core::ptr::null_mut();
    }
    // Leave room for NUL; POSIX: store at most size-1 chars + NUL.
    let limit = max.saturating_sub(1);
    if limit == 0 {
        unsafe {
            s.write(0);
        }
        return s;
    }
    let mut i = 0_usize;
    while i < limit {
        let ch = unsafe { fgetc(stream) };
        if ch < 0 {
            // EOF: return NULL if nothing read, else partial line.
            if i == 0 {
                return core::ptr::null_mut();
            }
            break;
        }
        let b = u8::try_from(ch).unwrap_or(0);
        unsafe {
            s.add(i).write(b.cast_signed());
        }
        i = i.saturating_add(1);
        if b == b'\n' {
            break;
        }
    }
    unsafe {
        s.add(i).write(0);
    }
    s
}

/// C `getdelim` → nlist `_getdelim` (git pathspec / config line reader).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn getdelim(
    lineptr: *mut *mut c_char,
    n: *mut usize,
    delim: c_int,
    stream: *mut c_void,
) -> isize {
    if lineptr.is_null() || n.is_null() || stream.is_null() {
        errno::set_errno(22);
        return -1;
    }
    let delim_b = u8::try_from(delim.cast_unsigned() & 0xff).unwrap_or(b'\n');
    let mut cap = unsafe { *n };
    let mut buf = unsafe { *lineptr };
    if buf.is_null() || cap == 0 {
        cap = 128;
        buf = unsafe { crate::heap::malloc(cap).cast::<c_char>() };
        if buf.is_null() {
            errno::set_errno(12);
            return -1;
        }
        unsafe {
            *lineptr = buf;
            *n = cap;
        }
    }
    let mut len = 0_usize;
    loop {
        let ch = unsafe { fgetc(stream) };
        if ch < 0 {
            if len == 0 {
                return -1; // EOF, nothing read
            }
            break;
        }
        let b = u8::try_from(ch).unwrap_or(0);
        // Ensure room for byte + NUL.
        if len.saturating_add(2) > cap {
            let new_cap = cap.saturating_mul(2).max(len.saturating_add(2)).max(128);
            let new_buf = unsafe { crate::heap::realloc(buf.cast(), new_cap).cast::<c_char>() };
            if new_buf.is_null() {
                errno::set_errno(12);
                return -1;
            }
            buf = new_buf;
            cap = new_cap;
            unsafe {
                *lineptr = buf;
                *n = cap;
            }
        }
        unsafe {
            buf.add(len).write(b.cast_signed());
        }
        len = len.saturating_add(1);
        if b == delim_b {
            break;
        }
        if len > (1 << 20) {
            break;
        }
    }
    unsafe {
        buf.add(len).write(0);
    }
    isize::try_from(len).unwrap_or(-1)
}

/// C `getline` → nlist `_getline`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn getline(
    lineptr: *mut *mut c_char,
    n: *mut usize,
    stream: *mut c_void,
) -> isize {
    unsafe { getdelim(lineptr, n, c_int::from(b'\n'), stream) }
}

/// C `fread` → nlist `_fread` (curl G1 follow-up after `_DefaultRuneLocale`).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn fread(
    ptr: *mut c_void,
    size: usize,
    nitems: usize,
    stream: *mut c_void,
) -> usize {
    if stream.is_null() || size == 0 || nitems == 0 {
        return 0;
    }
    if ptr.is_null() {
        errno::set_errno(14);
        return 0;
    }
    let f = unsafe { as_file(stream) };
    let total = size.saturating_mul(nitems);
    let fd = unsafe { (*f).fd };
    let fd_u = u64::from(fd.cast_unsigned());
    let n = unsafe { sys::syscall3(SYS_READ, fd_u, ptr_to_u64(ptr), usize_to_u64(total)) };
    if n < 0 {
        unsafe {
            (*f).flags |= FILE_ERR;
            (*f).err = 1;
        }
        return 0;
    }
    if n == 0 {
        unsafe {
            (*f).flags |= FILE_EOF;
        }
        return 0;
    }
    let got = usize::try_from(n).unwrap_or(0);
    // Whole items only (POSIX fread).
    got.checked_div(size).unwrap_or(0)
}

/// C `fwrite` → nlist `_fwrite`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn fwrite(
    ptr: *const c_void,
    size: usize,
    nitems: usize,
    stream: *mut c_void,
) -> usize {
    if stream.is_null() || size == 0 || nitems == 0 {
        return 0;
    }
    if ptr.is_null() {
        errno::set_errno(14);
        return 0;
    }
    let f = unsafe { as_file(stream) };
    let total = size.saturating_mul(nitems);
    let fd = unsafe { (*f).fd };
    let ret = unsafe { write(fd, ptr, total) };
    if ret < 0 {
        unsafe {
            (*f).flags |= FILE_ERR;
            (*f).err = 1;
        }
        return 0;
    }
    let got = usize::try_from(ret).unwrap_or(0);
    got.checked_div(size).unwrap_or(0)
}

/// C `fseek` → nlist `_fseek`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn fseek(stream: *mut c_void, offset: i64, whence: c_int) -> c_int {
    if stream.is_null() {
        errno::set_errno(9);
        return -1;
    }
    let f = unsafe { as_file(stream) };
    let fd = unsafe { (*f).fd };
    let pos = unsafe { crate::posix::lseek(fd, offset, whence) };
    if pos < 0 {
        unsafe {
            (*f).flags |= FILE_ERR;
        }
        return -1;
    }
    unsafe {
        (*f).flags &= !FILE_EOF;
    }
    0
}

/// C `fseeko` → nlist `_fseeko` (off_t is i64 on Darwin arm64).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn fseeko(stream: *mut c_void, offset: i64, whence: c_int) -> c_int {
    unsafe { fseek(stream, offset, whence) }
}

/// C `ftell` → nlist `_ftell`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn ftell(stream: *mut c_void) -> i64 {
    if stream.is_null() {
        errno::set_errno(9);
        return -1;
    }
    let f = unsafe { as_file(stream) };
    let fd = unsafe { (*f).fd };
    // SEEK_CUR = 1
    unsafe { crate::posix::lseek(fd, 0, 1) }
}

/// C `ftello` → nlist `_ftello`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn ftello(stream: *mut c_void) -> i64 {
    unsafe { ftell(stream) }
}

/// C `rewind` → nlist `_rewind`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn rewind(stream: *mut c_void) {
    if stream.is_null() {
        return;
    }
    let _ = unsafe { fseek(stream, 0, 0) };
    unsafe {
        (*as_file(stream)).flags &= !(FILE_EOF | FILE_ERR);
        (*as_file(stream)).err = 0;
    }
}

/// C `getc` → nlist `_getc` (same as fgetc).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn getc(stream: *mut c_void) -> c_int {
    unsafe { fgetc(stream) }
}

/// C `freopen` → nlist `_freopen`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn freopen(
    path: *const c_char,
    mode: *const c_char,
    stream: *mut c_void,
) -> *mut c_void {
    if stream.is_null() {
        errno::set_errno(9);
        return core::ptr::null_mut();
    }
    let Some((flags, creat_mode)) = open_flags_from_mode(mode) else {
        errno::set_errno(22);
        return core::ptr::null_mut();
    };
    if path.is_null() {
        errno::set_errno(14);
        return core::ptr::null_mut();
    }
    let f = unsafe { as_file(stream) };
    let old_fd = unsafe { (*f).fd };
    let is_std = core::ptr::eq(f, core::ptr::addr_of_mut!(STDIN_FILE))
        || core::ptr::eq(f, core::ptr::addr_of_mut!(STDOUT_FILE))
        || core::ptr::eq(f, core::ptr::addr_of_mut!(STDERR_FILE));
    // Close previous fd except for the three std streams' original slots when
    // guests freopen stdio onto a path (still close the prior open if non-std).
    if !is_std && old_fd >= 0 {
        let _ = unsafe { crate::posix::close(old_fd) };
    }
    let new_fd = unsafe { crate::posix::open(path, flags, creat_mode) };
    if new_fd < 0 {
        return core::ptr::null_mut();
    }
    unsafe {
        (*f).fd = new_fd;
        (*f).flags = 0;
        (*f).err = 0;
    }
    stream
}

#[inline]
fn usize_to_u64(n: usize) -> u64 {
    u64::try_from(n).unwrap_or(0)
}
