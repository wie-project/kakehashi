//! Remaining freestanding stubs for curl option surface (trace-first polish).
//!
//! Covers bind-list symbols still trampolined after tiers 1–8: jmp/context,
//! sscanf/fnmatch/realpath, DNS name helpers, kqueue soft, tty, notify.

// Scaffolding: small fixed buffers + digit loops; same allowances as locale.rs.
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

use crate::errno;
use crate::heap::{free, malloc};
use crate::stdio::strlen;
use crate::string::{strcmp, strcpy};

const EINVAL: i32 = 22;
const ENOTTY: i32 = 25;
const ENOSYS: i32 = 78;
const EAI_NONAME: i32 = 8;
const EAI_FAMILY: i32 = 1;

// ── Apple `_simple_*` soft string helpers (modern `ld`) ─────────────────────
//
// Private libc helpers used by CLT tools (`mach_o::Error` in modern `ld`):
//   Error(fmt, ...) → _simple_salloc + _simple_vsprintf
//   Error::message() → _simple_string(handle) → fprintf(stderr, "ld: %s\n", …)
//
// Soft layout (opaque to callers; only our five exports must agree):
//   struct { char *buf; size_t cap; size_t len; }
//
// Root cause of sparse `ld: ` exit 1: soft `_simple_vsprintf` was a no-op, so
// `message()` always returned an empty C string.

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

// ── dyld image query soft (modern `ld` process map) ─────────────────────────
//
// Apple nlists use a leading underscore already in the C spelling (`_dyld_*`).
// Export with that exact Mach-O name (rustc adds one more `_` for normal
// no_mangle, so use export_name).

/// Soft: report 0 images (no dyld shared-cache walk under kh).
#[unsafe(export_name = "_dyld_image_count")]
pub(crate) unsafe extern "C" fn dyld_image_count() -> u32 {
    0
}

#[unsafe(export_name = "dyld_image_count")]
pub(crate) unsafe extern "C" fn dyld_image_count_plain() -> u32 {
    0
}

/// Soft: null name.
#[unsafe(export_name = "_dyld_get_image_name")]
pub(crate) unsafe extern "C" fn dyld_get_image_name(_image_index: u32) -> *const c_char {
    core::ptr::null()
}

#[unsafe(export_name = "dyld_get_image_name")]
pub(crate) unsafe extern "C" fn dyld_get_image_name_plain(_image_index: u32) -> *const c_char {
    core::ptr::null()
}

/// Soft: null header.
#[unsafe(export_name = "_dyld_get_image_header")]
pub(crate) unsafe extern "C" fn dyld_get_image_header(_image_index: u32) -> *const c_void {
    core::ptr::null()
}

// ── intmax helpers ──────────────────────────────────────────────────────────

/// C `imaxabs` → nlist `_imaxabs` (`intmax_t` = `i64` on Darwin arm64).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn imaxabs(j: i64) -> i64 {
    j.saturating_abs()
}

// ── execinfo soft (clang crash paths / llvm Support) ─────────────────────────

/// C `backtrace` → nlist `_backtrace`.
///
/// Soft: report zero frames. Real stack walk is out of scope for freestanding
/// libSystem; guests that only probe crash reporting survive.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn backtrace(_buffer: *mut *mut c_void, _size: c_int) -> c_int {
    0
}

/// C `backtrace_symbols` → nlist `_backtrace_symbols` (null = failure).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn backtrace_symbols(
    _buffer: *mut *mut c_void,
    _size: c_int,
) -> *mut *mut c_char {
    core::ptr::null_mut()
}

/// C `backtrace_symbols_fd` → nlist `_backtrace_symbols_fd` (no-op).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn backtrace_symbols_fd(
    _buffer: *mut *mut c_void,
    _size: c_int,
    _fd: c_int,
) {
}

// ── kdebug soft (Apple clang / LLVM Support tracing) ────────────────────────

/// C `kdebug_trace_string` → nlist `_kdebug_trace_string`.
///
/// Soft: accept and return 0 (no kernel trace facility under kh).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn kdebug_trace_string(
    _debugid: u32,
    _str_id: u64,
    _str: *const c_char,
) -> c_int {
    0
}

/// C `kdebug_trace` → nlist `_kdebug_trace` (soft success).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn kdebug_trace(
    _debugid: u32,
    _a: u64,
    _b: u64,
    _c: u64,
    _d: u64,
) -> c_int {
    0
}

/// C `kdebug_is_enabled` → nlist `_kdebug_is_enabled` (always off).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn kdebug_is_enabled(_debugid: u32) -> c_int {
    0
}

// `arc4random*` lives in `net.rs` (curl-era buf + clang scalar).

// ── setjmp / longjmp / ucontext soft ────────────────────────────────────────

/// C `setjmp` → always 0 (context not restored by our soft `longjmp`).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn setjmp(_env: *mut c_void) -> c_int {
    0
}

/// Darwin `_setjmp` → nlist `__setjmp`.
#[unsafe(export_name = "_setjmp")]
pub(crate) unsafe extern "C" fn _setjmp(env: *mut c_void) -> c_int {
    unsafe { setjmp(env) }
}

/// C `longjmp` → exit guest (no real context restore).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn longjmp(_env: *mut c_void, val: c_int) -> ! {
    let code = if val == 0 { 1 } else { val };
    unsafe {
        crate::process::exit_now(code);
    }
}

/// Darwin `_longjmp` → nlist `__longjmp`.
#[unsafe(export_name = "_longjmp")]
pub(crate) unsafe extern "C" fn _longjmp(env: *mut c_void, val: c_int) -> ! {
    unsafe { longjmp(env, val) }
}

/// C `getcontext` → soft ENOSYS.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn getcontext(_ucp: *mut c_void) -> c_int {
    errno::set_errno(ENOSYS);
    -1
}

/// C `setcontext` → soft ENOSYS.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn setcontext(_ucp: *const c_void) -> c_int {
    errno::set_errno(ENOSYS);
    -1
}

/// C `makecontext` → no-op.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn makecontext(
    _ucp: *mut c_void,
    _func: *mut c_void,
    _argc: c_int,
    // varargs ignored
) {
}

// ── tty ─────────────────────────────────────────────────────────────────────

/// C `tcgetattr` → ENOTTY (no guest tty).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn tcgetattr(_fd: c_int, _termios_p: *mut c_void) -> c_int {
    errno::set_errno(ENOTTY);
    -1
}

/// C `tcsetattr` → ENOTTY.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn tcsetattr(
    _fd: c_int,
    _optional_actions: c_int,
    _termios_p: *const c_void,
) -> c_int {
    errno::set_errno(ENOTTY);
    -1
}

// ── notify (soft) ───────────────────────────────────────────────────────────

/// Darwin `notify_cancel` → 0.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn notify_cancel(_token: c_int) -> u32 {
    0
}

/// Darwin `notify_register_file_descriptor` → soft success token 1.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn notify_register_file_descriptor(
    _name: *const c_char,
    _notify_fd: *mut c_int,
    _flags: c_int,
    _out_token: *mut c_int,
) -> u32 {
    if !_out_token.is_null() {
        unsafe {
            _out_token.write(1);
        }
    }
    0
}

// ── kqueue soft ─────────────────────────────────────────────────────────────

/// C `kqueue` → anonymous pipe read end (kevent will soft-return 0).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn kqueue() -> c_int {
    // pipe() returns read in low 32 / write high on Darwin via our wrapper...
    // Use open("/dev/null") style: allocate a pipe via net::pipe.
    let mut fds = [0_i32; 2];
    let rc = unsafe { crate::net::pipe(fds.as_mut_ptr()) };
    if rc != 0 {
        return -1;
    }
    // Close write end; return read end as a pollable fd.
    let _ = unsafe { crate::posix::close(fds[1]) };
    fds[0]
}

/// C `kevent` → always 0 events (timeout / idle).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn kevent(
    _kq: c_int,
    _changelist: *const c_void,
    nchanges: c_int,
    _eventlist: *mut c_void,
    _nevents: c_int,
    _timeout: *const c_void,
) -> c_int {
    let _ = nchanges;
    0
}

// ── path / string ───────────────────────────────────────────────────────────

/// C `fnmatch` → basic `*` / `?` / literal (enough for curl glob off paths).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn fnmatch(
    pattern: *const c_char,
    string: *const c_char,
    _flags: c_int,
) -> c_int {
    if pattern.is_null() || string.is_null() {
        return 1;
    }
    if unsafe { fnmatch_inner(pattern, string) } {
        0
    } else {
        1 // FNM_NOMATCH
    }
}

unsafe fn fnmatch_inner(mut pat: *const c_char, mut s: *const c_char) -> bool {
    loop {
        let p = unsafe { pat.read().cast_unsigned() };
        let c = unsafe { s.read().cast_unsigned() };
        if p == 0 {
            return c == 0;
        }
        if p == b'*' {
            // greedy *
            unsafe {
                pat = pat.add(1);
            }
            if unsafe { pat.read() } == 0 {
                return true;
            }
            loop {
                if unsafe { fnmatch_inner(pat, s) } {
                    return true;
                }
                if unsafe { s.read() } == 0 {
                    return false;
                }
                unsafe {
                    s = s.add(1);
                }
            }
        }
        if p == b'?' {
            if c == 0 {
                return false;
            }
        } else if p != c {
            return false;
        }
        if c == 0 {
            return p == 0;
        }
        unsafe {
            pat = pat.add(1);
            s = s.add(1);
        }
    }
}

/// C `realpath` → nlist `_realpath`.
///
/// Soft: copy the path, but still require the path to exist (Darwin
/// `realpath` returns `NULL` + `ENOENT` when the target is missing). Modern
/// `ld` uses this when processing `-syslibroot` before adding default
/// `$root/usr/lib` library search paths.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn realpath(
    path: *const c_char,
    resolved: *mut c_char,
) -> *mut c_char {
    const F_OK: c_int = 0;
    if path.is_null() {
        errno::set_errno(EINVAL);
        return core::ptr::null_mut();
    }
    // Reject PAGEZERO / unrebased guest pointers.
    if path.addr() < crate::stdio::PAGEZERO_END {
        errno::set_errno(EINVAL);
        return core::ptr::null_mut();
    }
    // Darwin: path must exist. Use freestanding `access(F_OK)`.
    let exists = unsafe { crate::posix::access(path, F_OK) } == 0;
    if !exists {
        errno::set_errno(2); // ENOENT
        return core::ptr::null_mut();
    }
    let n = unsafe { strlen(path) };
    // PATH_MAX-ish cap for stack resolved buffers callers pass in.
    if n >= 1024 {
        errno::set_errno(63); // ENAMETOOLONG-ish
        return core::ptr::null_mut();
    }
    let out = if resolved.is_null() {
        let p = unsafe { malloc(n.saturating_add(1)) };
        if p.is_null() {
            return core::ptr::null_mut();
        }
        p.cast::<c_char>()
    } else {
        resolved
    };
    unsafe {
        strcpy(out, path);
    }
    out
}

/// Darwin `realpath$DARWIN_EXTSN`.
#[unsafe(export_name = "realpath$DARWIN_EXTSN")]
pub(crate) unsafe extern "C" fn realpath_darwin_extsn(
    path: *const c_char,
    resolved: *mut c_char,
) -> *mut c_char {
    unsafe { realpath(path, resolved) }
}

// `sscanf` / `vsscanf` live in `printf_fmt.c` (true C `va_list` ABI).
// The old Rust fixed-arg soft sscanf broke Apple arm64 variadic calls
// (observed: `ld -flto` version parse → malformed '15.0.…').

// ── DNS name helpers ────────────────────────────────────────────────────────

/// C `getnameinfo` → numeric host/service when possible.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn getnameinfo(
    sa: *const c_void,
    salen: u32,
    host: *mut c_char,
    hostlen: u32,
    serv: *mut c_char,
    servlen: u32,
    flags: c_int,
) -> c_int {
    let _ = flags;
    if sa.is_null() || salen < 2 {
        return EAI_FAMILY;
    }
    let family = unsafe { sa.cast::<u8>().add(1).read() }; // Darwin sa_family at byte 1
    if family == 2 && salen >= 8 {
        // AF_INET sockaddr_in: port @2, addr @4
        let base = sa.cast::<u8>();
        if !host.is_null() && hostlen > 0 {
            let a = unsafe {
                [
                    base.add(4).read(),
                    base.add(5).read(),
                    base.add(6).read(),
                    base.add(7).read(),
                ]
            };
            write_ipv4(host, hostlen, a);
        }
        if !serv.is_null() && servlen > 0 {
            let port = u16::from_be_bytes(unsafe { [base.add(2).read(), base.add(3).read()] });
            write_u16_dec(serv, servlen, port);
        }
        return 0;
    }
    EAI_NONAME
}

fn write_ipv4(dst: *mut c_char, dstlen: u32, a: [u8; 4]) {
    let mut buf = [0_u8; 16];
    let mut o = 0_usize;
    for (i, b) in a.iter().enumerate() {
        if i > 0 {
            if let Some(s) = buf.get_mut(o) {
                *s = b'.';
            }
            o = o.saturating_add(1);
        }
        let mut v = u32::from(*b);
        let mut tmp = [0_u8; 3];
        let mut t = 0_usize;
        if v == 0 {
            tmp[0] = b'0';
            t = 1;
        } else {
            while v > 0 && t < 3 {
                tmp[t] = b'0' + u8::try_from(v % 10).unwrap_or(0);
                v /= 10;
                t = t.saturating_add(1);
            }
        }
        while t > 0 {
            t = t.saturating_sub(1);
            if let Some(s) = buf.get_mut(o) {
                *s = tmp[t];
            }
            o = o.saturating_add(1);
        }
    }
    let max = usize::try_from(dstlen).unwrap_or(0);
    if max == 0 {
        return;
    }
    let n = o.min(max.saturating_sub(1));
    unsafe {
        let mut i = 0_usize;
        while i < n {
            dst.add(i)
                .write(buf.get(i).copied().unwrap_or(0).cast_signed());
            i = i.saturating_add(1);
        }
        dst.add(n).write(0);
    }
}

fn write_u16_dec(dst: *mut c_char, dstlen: u32, mut v: u16) {
    let mut tmp = [0_u8; 5];
    let mut t = 0_usize;
    if v == 0 {
        tmp[0] = b'0';
        t = 1;
    } else {
        while v > 0 && t < 5 {
            tmp[t] = b'0' + u8::try_from(v % 10).unwrap_or(0);
            v /= 10;
            t = t.saturating_add(1);
        }
    }
    let max = usize::try_from(dstlen).unwrap_or(0);
    if max == 0 {
        return;
    }
    let mut o = 0_usize;
    while t > 0 && o + 1 < max {
        t = t.saturating_sub(1);
        unsafe {
            dst.add(o).write(tmp[t].cast_signed());
        }
        o = o.saturating_add(1);
    }
    unsafe {
        dst.add(o).write(0);
    }
}

/// C `gethostbyname` → null (prefer getaddrinfo).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn gethostbyname(_name: *const c_char) -> *mut c_void {
    core::ptr::null_mut()
}

/// Static servent for common services.
#[repr(C)]
struct Servent {
    name: *const c_char,
    aliases: *mut *mut c_char,
    port: c_int, // network byte order
    proto: *const c_char,
}

static mut NULL_ALIAS: *mut c_char = core::ptr::null_mut();
static mut SERVENT: Servent = Servent {
    name: core::ptr::null(),
    aliases: core::ptr::null_mut(),
    port: 0,
    proto: core::ptr::null(),
};
static mut SERV_NAME: [u8; 16] = [0; 16];
static mut SERV_PROTO: [u8; 8] = [0; 8];

unsafe fn fill_servent(name: &[u8], port_host: u16, proto: &[u8]) -> *mut Servent {
    unsafe {
        SERVENT.aliases = core::ptr::addr_of_mut!(NULL_ALIAS);
        SERVENT.port = c_int::from(port_host.to_be());
        let mut i = 0_usize;
        while i < 15 {
            let b = name.get(i).copied().unwrap_or(0);
            SERV_NAME[i] = b;
            if b == 0 {
                break;
            }
            i = i.saturating_add(1);
        }
        SERV_NAME[15] = 0;
        i = 0;
        while i < 7 {
            let b = proto.get(i).copied().unwrap_or(0);
            SERV_PROTO[i] = b;
            if b == 0 {
                break;
            }
            i = i.saturating_add(1);
        }
        SERV_PROTO[7] = 0;
        SERVENT.name = core::ptr::addr_of!(SERV_NAME).cast();
        SERVENT.proto = core::ptr::addr_of!(SERV_PROTO).cast();
        core::ptr::addr_of_mut!(SERVENT)
    }
}

/// C `getservbyname`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn getservbyname(
    name: *const c_char,
    proto: *const c_char,
) -> *mut c_void {
    if name.is_null() {
        return core::ptr::null_mut();
    }
    let p = if proto.is_null() {
        b"tcp\0".as_ptr()
    } else {
        proto.cast()
    };
    let n = unsafe {
        if strcmp(name, c"http".as_ptr()) == 0 {
            Some((b"http\0".as_slice(), 80_u16))
        } else if strcmp(name, c"https".as_ptr()) == 0 {
            Some((b"https\0".as_slice(), 443))
        } else if strcmp(name, c"ftp".as_ptr()) == 0 {
            Some((b"ftp\0".as_slice(), 21))
        } else if strcmp(name, c"ssh".as_ptr()) == 0 {
            Some((b"ssh\0".as_slice(), 22))
        } else if strcmp(name, c"smtp".as_ptr()) == 0 {
            Some((b"smtp\0".as_slice(), 25))
        } else {
            None
        }
    };
    let Some((nm, port)) = n else {
        return core::ptr::null_mut();
    };
    let _ = p;
    unsafe { fill_servent(nm, port, b"tcp\0").cast() }
}

/// C `getservbyport` (port in network order).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn getservbyport(port: c_int, _proto: *const c_char) -> *mut c_void {
    let host = u16::from_be(u16::try_from(port.cast_unsigned() & 0xffff).unwrap_or(0));
    let (nm, p) = match host {
        80 => (b"http\0".as_slice(), 80_u16),
        443 => (b"https\0".as_slice(), 443),
        21 => (b"ftp\0".as_slice(), 21),
        22 => (b"ssh\0".as_slice(), 22),
        25 => (b"smtp\0".as_slice(), 25),
        _ => return core::ptr::null_mut(),
    };
    unsafe { fill_servent(nm, p, b"tcp\0").cast() }
}

// ── CoreServices FSEvents (Apple git file watch / maintenance) ──────────────
//
// `git` LC_LOAD_DYLIB CoreServices and two-level-binds these. Bottle has no
// CoreServices.framework; soft no-ops here so flat resolve binds to libSystem
// instead of failing load (`unresolved symbol _FSEventStreamCreate`) or
// aborting via missing trampoline when watch paths run after commit.

/// `FSEventStreamCreate` → null stream (watcher unavailable).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn FSEventStreamCreate(
    _allocator: *mut c_void,
    _callback: *mut c_void,
    _context: *mut c_void,
    _paths: *mut c_void,
    _since: u64,
    _latency: f64,
    _flags: u32,
) -> *mut c_void {
    core::ptr::null_mut()
}

/// `FSEventStreamStart` → false (Boolean).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn FSEventStreamStart(_stream: *mut c_void) -> u8 {
    0
}

/// `FSEventStreamStop`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn FSEventStreamStop(_stream: *mut c_void) {}

/// `FSEventStreamInvalidate`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn FSEventStreamInvalidate(_stream: *mut c_void) {}

/// `FSEventStreamRelease`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn FSEventStreamRelease(_stream: *mut c_void) {}

/// `FSEventStreamSetDispatchQueue`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn FSEventStreamSetDispatchQueue(
    _stream: *mut c_void,
    _queue: *mut c_void,
) {
}

// ── timers (git progress / clone) ───────────────────────────────────────────

/// C `setitimer` → soft success (no real interval timers).
///
/// Apple `git` clone uses this for the progress ticker; missing export was a
/// hard trampoline exit mid-checkout (`index.lock` left behind).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn setitimer(
    _which: c_int,
    _value: *const c_void,
    _ovalue: *mut c_void,
) -> c_int {
    0
}

/// C `getitimer` → zeroed soft success.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn getitimer(_which: c_int, value: *mut c_void) -> c_int {
    if !value.is_null() {
        // struct itimerval { timeval it_interval; timeval it_value; } — 32 bytes on arm64.
        unsafe {
            core::ptr::write_bytes(value.cast::<u8>(), 0, 32);
        }
    }
    0
}

// ── std::random_device (Apple arm64: sizeof = 4) ─────────────────────────────
//
// libLTO imports ctor(string), dtor, operator(). Host sizeof is 4 — soft as a
// single u32 LCG state (no /dev/urandom). Enough for unique temp path digits.

/// Soft LCG state when the 4-byte object is treated as seed storage.
#[inline]
unsafe fn rd_state(this: *mut c_void) -> *mut u32 {
    this.cast::<u32>()
}

/// `random_device::random_device(string const&)` C1.
///
/// nlist `_ZNSt3__113random_deviceC1ERKNS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEE`
#[unsafe(export_name = "_ZNSt3__113random_deviceC1ERKNS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEE")]
pub(crate) unsafe extern "C" fn random_device_ctor_string(
    this: *mut c_void,
    _token: *const c_void,
) {
    if this.is_null() {
        return;
    }
    // Seed from a mix of address + fixed constant (deterministic-ish, non-zero).
    let seed = (this.addr() as u32)
        .wrapping_mul(0x9E37_79B9)
        .wrapping_add(0xA5A5_5A5A)
        .max(1);
    unsafe {
        rd_state(this).write(seed);
    }
}

/// `random_device::~random_device()` D1.
#[unsafe(export_name = "_ZNSt3__113random_deviceD1Ev")]
pub(crate) unsafe extern "C" fn random_device_dtor(this: *mut c_void) {
    if this.is_null() {
        return;
    }
    unsafe {
        rd_state(this).write(0);
    }
}

/// `random_device::operator()()` → `unsigned int`.
#[unsafe(export_name = "_ZNSt3__113random_deviceclEv")]
pub(crate) unsafe extern "C" fn random_device_call(this: *mut c_void) -> u32 {
    if this.is_null() {
        return 0xC0FF_EE00;
    }
    // xorshift32-ish LCG (Numerical Recipes constants).
    let p = unsafe { rd_state(this) };
    let mut x = unsafe { p.read() };
    if x == 0 {
        x = 0xDEAD_BEEF;
    }
    x = x
        .wrapping_mul(1_664_525)
        .wrapping_add(1_013_904_223);
    unsafe {
        p.write(x);
    }
    x
}
