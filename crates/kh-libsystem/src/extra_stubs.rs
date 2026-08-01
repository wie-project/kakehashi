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
use crate::heap::malloc;
use crate::stdio::strlen;
use crate::string::{strcmp, strcpy};

const EINVAL: i32 = 22;
const ENOTTY: i32 = 25;
const ENOSYS: i32 = 78;
const EAI_NONAME: i32 = 8;
const EAI_FAMILY: i32 = 1;

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

/// C `realpath` → nlist `_realpath` (copy path; no full canonicalize).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn realpath(
    path: *const c_char,
    resolved: *mut c_char,
) -> *mut c_char {
    if path.is_null() {
        errno::set_errno(EINVAL);
        return core::ptr::null_mut();
    }
    let n = unsafe { strlen(path) };
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

/// Minimal `sscanf` for `%d` `%u` `%s` `%c` `%x` and literals (curl/openssl).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn sscanf(
    s: *const c_char,
    fmt: *const c_char,
    // AAPCS: remaining args in x2.. — we only support up to 4 pointer outs via
    // the first four after fmt by reading from a fixed va layout is not possible
    // in pure Rust without va_list. Use a limited approach: only parse into
    // stack via known register convention is unsafe.
    //
    // Darwin arm64: a0=s, a1=fmt, a2=arg0, a3=arg1, a4=arg2, a5=arg3, a6=arg4, a7=arg5
    a0: *mut c_void,
    a1: *mut c_void,
    a2: *mut c_void,
    a3: *mut c_void,
) -> c_int {
    if s.is_null() || fmt.is_null() {
        return -1;
    }
    let args = [a0, a1, a2, a3];
    let mut ai = 0_usize;
    let mut si = 0_usize;
    let mut fi = 0_usize;
    let mut assigned = 0_i32;
    unsafe {
        loop {
            let f = fmt.add(fi).read().cast_unsigned();
            if f == 0 {
                break;
            }
            if f == b'%' {
                fi = fi.saturating_add(1);
                let mut spec = fmt.add(fi).read().cast_unsigned();
                // skip width digits
                while (b'0'..=b'9').contains(&spec) {
                    fi = fi.saturating_add(1);
                    spec = fmt.add(fi).read().cast_unsigned();
                }
                if spec == 0 {
                    break;
                }
                fi = fi.saturating_add(1);
                // skip whitespace in input
                while {
                    let c = s.add(si).read().cast_unsigned();
                    c == b' ' || c == b'\t' || c == b'\n' || c == b'\r'
                } {
                    si = si.saturating_add(1);
                }
                let Some(out) = args.get(ai).copied() else {
                    break;
                };
                if out.is_null() && spec != b'%' {
                    break;
                }
                match spec {
                    b'd' | b'i' | b'u' | b'x' | b'X' => {
                        let (val, n) = parse_int(s.add(si), spec == b'x' || spec == b'X');
                        if n == 0 {
                            break;
                        }
                        si = si.saturating_add(n);
                        if spec == b'u' || spec == b'x' || spec == b'X' {
                            out.cast::<u32>().write(val as u32);
                        } else {
                            out.cast::<i32>().write(val);
                        }
                        assigned = assigned.saturating_add(1);
                        ai = ai.saturating_add(1);
                    }
                    b's' => {
                        let mut n = 0_usize;
                        let dst = out.cast::<c_char>();
                        loop {
                            let c = s.add(si.saturating_add(n)).read();
                            let u = c.cast_unsigned();
                            if u == 0 || u == b' ' || u == b'\t' || u == b'\n' {
                                break;
                            }
                            dst.add(n).write(c);
                            n = n.saturating_add(1);
                            if n >= 255 {
                                break;
                            }
                        }
                        if n == 0 {
                            break;
                        }
                        dst.add(n).write(0);
                        si = si.saturating_add(n);
                        assigned = assigned.saturating_add(1);
                        ai = ai.saturating_add(1);
                    }
                    b'c' => {
                        let c = s.add(si).read();
                        if c == 0 {
                            break;
                        }
                        out.cast::<c_char>().write(c);
                        si = si.saturating_add(1);
                        assigned = assigned.saturating_add(1);
                        ai = ai.saturating_add(1);
                    }
                    b'%' => {
                        if s.add(si).read().cast_unsigned() != b'%' {
                            break;
                        }
                        si = si.saturating_add(1);
                    }
                    _ => break,
                }
                continue;
            }
            // whitespace in format matches any whitespace
            if f == b' ' || f == b'\t' || f == b'\n' {
                while {
                    let c = s.add(si).read().cast_unsigned();
                    c == b' ' || c == b'\t' || c == b'\n' || c == b'\r'
                } {
                    si = si.saturating_add(1);
                }
                fi = fi.saturating_add(1);
                continue;
            }
            if s.add(si).read().cast_unsigned() != f {
                break;
            }
            si = si.saturating_add(1);
            fi = fi.saturating_add(1);
        }
    }
    assigned
}

fn parse_int(s: *const c_char, hex: bool) -> (i32, usize) {
    unsafe {
        let mut i = 0_usize;
        let mut sign = 1_i32;
        let c0 = s.add(i).read().cast_unsigned();
        if c0 == b'+' || c0 == b'-' {
            if c0 == b'-' {
                sign = -1;
            }
            i = i.saturating_add(1);
        }
        let mut val = 0_i32;
        let mut n = 0_usize;
        loop {
            let c = s.add(i).read().cast_unsigned();
            let digit = if hex {
                if (b'0'..=b'9').contains(&c) {
                    c - b'0'
                } else if (b'a'..=b'f').contains(&c) {
                    c - b'a' + 10
                } else if (b'A'..=b'F').contains(&c) {
                    c - b'A' + 10
                } else {
                    break;
                }
            } else if (b'0'..=b'9').contains(&c) {
                c - b'0'
            } else {
                break;
            };
            val = val
                .saturating_mul(if hex { 16 } else { 10 })
                .saturating_add(i32::from(digit));
            i = i.saturating_add(1);
            n = n.saturating_add(1);
            if n > 10 {
                break;
            }
        }
        if n == 0 {
            (0, 0)
        } else {
            (val.saturating_mul(sign), i)
        }
    }
}

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
