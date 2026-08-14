//! Soft leftovers that do not map cleanly to a single Darwin dylib name.

#![allow(unused_imports, dead_code)]

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

use crate::kh_core::errno;
use crate::kh_core::heap::{free, malloc};
use crate::dylib::libsystem_c::stdio::strlen;
use crate::dylib::libsystem_c::string::{strcmp, strcpy};
use crate::kh_core::process;
use crate::kh_core::sys::{self, SYS_IOCTL};

const EINVAL: i32 = 22;
const ENOTTY: i32 = 25;
const ENOSYS: i32 = 78;

pub(crate) mod coreanalytics_xar;
pub(crate) mod os_lock_ld;
pub(crate) mod ld_misc;
pub(crate) use ld_misc::mkpath_np;

/// C `imaxabs` → nlist `_imaxabs` (`intmax_t` = `i64` on Darwin arm64).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn imaxabs(j: i64) -> i64 {
    j.saturating_abs()
}


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

/// C `csops` → nlist `_csops` (codesign query; soft allow).
///
/// Darwin `sh` / launchd-adjacent tools call this at start. `0` + zeroed
/// status is "unsigned / no flags" and is enough to continue.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn csops(
    _pid: i32,
    _ops: u32,
    useraddr: *mut c_void,
    usersize: usize,
) -> c_int {
    if !useraddr.is_null() && usersize > 0 {
        unsafe {
            core::ptr::write_bytes(useraddr.cast::<u8>(), 0, usersize.min(64));
        }
    }
    0
}

/// C `csops_audittoken` → nlist `_csops_audittoken`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn csops_audittoken(
    pid: i32,
    ops: u32,
    useraddr: *mut c_void,
    usersize: usize,
    _token: *mut c_void,
) -> c_int {
    unsafe { csops(pid, ops, useraddr, usersize) }
}

/// C `compat_mode` → nlist `_compat_mode`.
///
/// Apple shells query this to pick legacy vs modern behavior. `0` = current
/// Darwin semantics (not a named compatibility mode).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn compat_mode(
    _function: *const c_char,
    _mode: *const c_char,
) -> c_int {
    0
}

// `arc4random*` lives in `net.rs` (curl-era buf + clang scalar).

// ── setjmp / longjmp (AAPCS64; layout is ours — callers treat jmp_buf as opaque)
//
// Darwin arm64 `jmp_buf` is 48 ints (192 bytes). Soft stubs used to return 0 /
// `_exit`, so Apple bash 3.2 (function `return`, error unwind) either exited
// or kept running with a dead jmp_buf. rustup.sh dies at `main "$@"` without
// a real restore.
//
// Slots (uint64): x19–x28, x29, x30, sp, x18, d8–d15, sigmask, savemask.

const JMP_SIGMASK: usize = 22;
const JMP_SAVEMASK: usize = 23;
const SIG_SETMASK: c_int = 3;

macro_rules! setjmp_asm {
    () => {
        core::arch::naked_asm!(
            "stp x19, x20, [x0, #0]",
            "stp x21, x22, [x0, #16]",
            "stp x23, x24, [x0, #32]",
            "stp x25, x26, [x0, #48]",
            "stp x27, x28, [x0, #64]",
            "stp x29, x30, [x0, #80]",
            "mov x2, sp",
            "stp x2, x18, [x0, #96]",
            "stp d8, d9, [x0, #112]",
            "stp d10, d11, [x0, #128]",
            "stp d12, d13, [x0, #144]",
            "stp d14, d15, [x0, #160]",
            "mov w0, #0",
            "ret",
        )
    };
}

macro_rules! longjmp_asm {
    () => {
        core::arch::naked_asm!(
            "ldp x19, x20, [x0, #0]",
            "ldp x21, x22, [x0, #16]",
            "ldp x23, x24, [x0, #32]",
            "ldp x25, x26, [x0, #48]",
            "ldp x27, x28, [x0, #64]",
            "ldp x29, x30, [x0, #80]",
            "ldp x2, x18, [x0, #96]",
            "mov sp, x2",
            "ldp d8, d9, [x0, #112]",
            "ldp d10, d11, [x0, #128]",
            "ldp d12, d13, [x0, #144]",
            "ldp d14, d15, [x0, #160]",
            "cmp w1, #0",
            "csinc w0, w1, wzr, ne",
            "ret",
        )
    };
}

/// C `setjmp` → nlist `_setjmp`.
#[unsafe(no_mangle)]
#[unsafe(naked)]
pub(crate) unsafe extern "C" fn setjmp(_env: *mut u64) -> c_int {
    setjmp_asm!()
}

/// Darwin `_setjmp` → nlist `__setjmp` (same save as `setjmp`).
///
/// On Darwin, `export_name` is decorated with a leading `_`, so `"_setjmp"`
/// is the C `_setjmp` nlist.
#[unsafe(export_name = "_setjmp")]
#[unsafe(naked)]
pub(crate) unsafe extern "C" fn darwin_under_setjmp(_env: *mut u64) -> c_int {
    setjmp_asm!()
}

/// C `longjmp` → nlist `_longjmp`. Restores the `setjmp` frame; never `ret`s here.
#[unsafe(no_mangle)]
#[unsafe(naked)]
pub(crate) unsafe extern "C" fn longjmp(_env: *mut u64, _val: c_int) -> ! {
    longjmp_asm!()
}

/// Darwin `_longjmp` → nlist `__longjmp`.
#[unsafe(export_name = "_longjmp")]
#[unsafe(naked)]
pub(crate) unsafe extern "C" fn darwin_under_longjmp(_env: *mut u64, _val: c_int) -> ! {
    longjmp_asm!()
}

/// C `sigsetjmp` → nlist `_sigsetjmp`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn sigsetjmp(env: *mut u64, savemask: c_int) -> c_int {
    if env.is_null() {
        return 0;
    }
    unsafe {
        env.add(JMP_SAVEMASK).write(u64::from(savemask != 0));
        if savemask != 0 {
            let mask_slot = env.add(JMP_SIGMASK).cast::<c_void>();
            let _ = crate::dylib::libsystem_c::posix::sigprocmask(
                SIG_SETMASK,
                core::ptr::null(),
                mask_slot,
            );
        }
        setjmp(env)
    }
}

/// C `siglongjmp` → nlist `_siglongjmp`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn siglongjmp(env: *mut u64, val: c_int) -> ! {
    if !env.is_null() {
        unsafe {
            if env.add(JMP_SAVEMASK).read() != 0 {
                let mask_slot = env.add(JMP_SIGMASK).cast::<c_void>();
                let _ = crate::dylib::libsystem_c::posix::sigprocmask(
                    SIG_SETMASK,
                    mask_slot,
                    core::ptr::null_mut(),
                );
            }
            longjmp(env, val);
        }
    }
    unsafe {
        crate::kh_core::process::exit_now(if val == 0 { 1 } else { val });
    }
}

/// Darwin `SS_DISABLE` (`<signal.h>` / `<sys/signal.h>`).
const SS_DISABLE: i32 = 0x0004;

/// C `sigaltstack` → nlist `_sigaltstack`.
///
/// Soft success: Rust std installs an alternate signal stack after the main
/// guard page. We accept the request so init continues; overflow still faults
/// on the thread stack.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn sigaltstack(ss: *const c_void, oss: *mut c_void) -> c_int {
    if !oss.is_null() {
        // Darwin `stack_t` on arm64: ss_sp, ss_size, ss_flags (+ pad).
        let mut buf = [0_u8; 24];
        buf[16..20].copy_from_slice(&SS_DISABLE.to_ne_bytes());
        unsafe {
            core::ptr::copy_nonoverlapping(buf.as_ptr(), oss.cast::<u8>(), buf.len());
        }
    }
    let _ = ss;
    0
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


/// Darwin `TIOCGETA` (`_IOR('t', 19, struct termios)`, arm64 size 72).
const TIOCGETA: u64 = 0x4048_7413;
/// Darwin `TIOCSETA`.
const TIOCSETA: u64 = 0x8048_7414;
/// Darwin `TIOCSETAW`.
const TIOCSETAW: u64 = 0x8048_7415;
/// Darwin `TIOCSETAF`.
const TIOCSETAF: u64 = 0x8048_7416;
/// Darwin `TIOCDRAIN`.
const TIOCDRAIN: u64 = 0x2000_745e;
/// Darwin `TIOCFLUSH`.
const TIOCFLUSH: u64 = 0x8004_7410;

const TCSADRAIN: c_int = 1;
const TCSAFLUSH: c_int = 2;

const DARWIN_IGNBRK: u64 = 0x0000_0001;
const DARWIN_BRKINT: u64 = 0x0000_0002;
const DARWIN_PARMRK: u64 = 0x0000_0008;
const DARWIN_ISTRIP: u64 = 0x0000_0020;
const DARWIN_INLCR: u64 = 0x0000_0040;
const DARWIN_IGNCR: u64 = 0x0000_0080;
const DARWIN_ICRNL: u64 = 0x0000_0100;
const DARWIN_IXON: u64 = 0x0000_0200;
const DARWIN_OPOST: u64 = 0x0000_0001;
const DARWIN_ECHO: u64 = 0x0000_0008;
const DARWIN_ECHONL: u64 = 0x0000_0010;
const DARWIN_ICANON: u64 = 0x0000_0100;
const DARWIN_ISIG: u64 = 0x0000_0080;
const DARWIN_IEXTEN: u64 = 0x0000_0400;
const DARWIN_CSIZE: u64 = 0x0000_0300;
const DARWIN_PARENB: u64 = 0x0000_1000;
const DARWIN_CS8: u64 = 0x0000_0300;

#[repr(C)]
struct DarwinTermios {
    c_iflag: u64,
    c_oflag: u64,
    c_cflag: u64,
    c_lflag: u64,
    c_cc: [u8; 20],
    _pad: [u8; 4],
    c_ispeed: u64,
    c_ospeed: u64,
}

#[inline]
fn ioctl_ret(ret: isize) -> c_int {
    if ret < 0 {
        errno::set_errno(i32::try_from(ret.saturating_neg()).unwrap_or(ENOTTY));
        -1
    } else {
        0
    }
}

/// C `tcgetattr` → `ioctl(TIOCGETA)`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn tcgetattr(fd: c_int, termios_p: *mut c_void) -> c_int {
    if termios_p.is_null() {
        errno::set_errno(EINVAL);
        return -1;
    }
    ioctl_ret(unsafe {
        sys::syscall3(
            SYS_IOCTL,
            u64::from(fd.cast_unsigned()),
            TIOCGETA,
            u64::try_from(termios_p.addr()).unwrap_or(0),
        )
    })
}

/// C `tcsetattr` → `ioctl(TIOCSETA/W/F)`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn tcsetattr(
    fd: c_int,
    optional_actions: c_int,
    termios_p: *const c_void,
) -> c_int {
    if termios_p.is_null() {
        errno::set_errno(EINVAL);
        return -1;
    }
    let req = match optional_actions & 0x0f {
        TCSADRAIN => TIOCSETAW,
        TCSAFLUSH => TIOCSETAF,
        _ => TIOCSETA,
    };
    ioctl_ret(unsafe {
        sys::syscall3(
            SYS_IOCTL,
            u64::from(fd.cast_unsigned()),
            req,
            u64::try_from(termios_p.addr()).unwrap_or(0),
        )
    })
}

/// C `tcdrain` → `ioctl(TIOCDRAIN)`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn tcdrain(fd: c_int) -> c_int {
    ioctl_ret(unsafe {
        sys::syscall3(SYS_IOCTL, u64::from(fd.cast_unsigned()), TIOCDRAIN, 0)
    })
}

/// C `tcflush` → `ioctl(TIOCFLUSH)` (`TCIFLUSH`/`TCOFLUSH`/`TCIOFLUSH`).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn tcflush(fd: c_int, queue_selector: c_int) -> c_int {
    let mut which = queue_selector;
    ioctl_ret(unsafe {
        sys::syscall3(
            SYS_IOCTL,
            u64::from(fd.cast_unsigned()),
            TIOCFLUSH,
            u64::try_from(core::ptr::from_mut(&mut which).addr()).unwrap_or(0),
        )
    })
}

/// C `cfgetispeed`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn cfgetispeed(termios_p: *const c_void) -> u64 {
    let Some(t) = (unsafe { termios_ref(termios_p.cast_mut()) }) else {
        return 0;
    };
    t.c_ispeed
}

/// C `cfgetospeed`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn cfgetospeed(termios_p: *const c_void) -> u64 {
    let Some(t) = (unsafe { termios_ref(termios_p.cast_mut()) }) else {
        return 0;
    };
    t.c_ospeed
}

/// C `cfsetispeed`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn cfsetispeed(termios_p: *mut c_void, speed: u64) -> c_int {
    let Some(t) = (unsafe { termios_ref(termios_p) }) else {
        errno::set_errno(EINVAL);
        return -1;
    };
    t.c_ispeed = speed;
    0
}

/// C `cfsetospeed`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn cfsetospeed(termios_p: *mut c_void, speed: u64) -> c_int {
    let Some(t) = (unsafe { termios_ref(termios_p) }) else {
        errno::set_errno(EINVAL);
        return -1;
    };
    t.c_ospeed = speed;
    0
}

/// C `cfsetspeed` — set both input and output speed.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn cfsetspeed(termios_p: *mut c_void, speed: u64) -> c_int {
    let Some(t) = (unsafe { termios_ref(termios_p) }) else {
        errno::set_errno(EINVAL);
        return -1;
    };
    t.c_ispeed = speed;
    t.c_ospeed = speed;
    0
}

/// C `cfmakeraw` — documented POSIX/BSD raw-mode flag mask.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn cfmakeraw(termios_p: *mut c_void) {
    let Some(t) = (unsafe { termios_ref(termios_p) }) else {
        return;
    };
    t.c_iflag &= !(DARWIN_IGNBRK
        | DARWIN_BRKINT
        | DARWIN_PARMRK
        | DARWIN_ISTRIP
        | DARWIN_INLCR
        | DARWIN_IGNCR
        | DARWIN_ICRNL
        | DARWIN_IXON);
    t.c_oflag &= !DARWIN_OPOST;
    t.c_lflag &= !(DARWIN_ECHO | DARWIN_ECHONL | DARWIN_ICANON | DARWIN_ISIG | DARWIN_IEXTEN);
    t.c_cflag &= !(DARWIN_CSIZE | DARWIN_PARENB);
    t.c_cflag |= DARWIN_CS8;
}

unsafe fn termios_ref<'a>(p: *mut c_void) -> Option<&'a mut DarwinTermios> {
    if p.is_null() {
        return None;
    }
    Some(unsafe { &mut *p.cast::<DarwinTermios>() })
}

/// C `ttyname` — static `/dev/tty` when `fd` is a host tty.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn ttyname(fd: c_int) -> *mut c_char {
    if unsafe { crate::dylib::libsystem_c::posix::isatty(fd) } == 0 {
        return core::ptr::null_mut();
    }
    TTYNAME.as_ptr().cast_mut().cast()
}

static TTYNAME: [u8; 9] = *b"/dev/tty\0";

/// C `ttyname_r`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn ttyname_r(fd: c_int, buf: *mut c_char, buflen: usize) -> c_int {
    if buf.is_null() || buflen == 0 {
        errno::set_errno(EINVAL);
        return EINVAL;
    }
    if unsafe { crate::dylib::libsystem_c::posix::isatty(fd) } == 0 {
        errno::set_errno(ENOTTY);
        return ENOTTY;
    }
    let name = b"/dev/tty\0";
    if buflen < name.len() {
        errno::set_errno(ERANGE_TTY);
        return ERANGE_TTY;
    }
    unsafe {
        core::ptr::copy_nonoverlapping(name.as_ptr(), buf.cast::<u8>(), name.len());
    }
    0
}

const ERANGE_TTY: i32 = 34;


/// C `kqueue` → anonymous pipe read end (kevent will soft-return 0).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn kqueue() -> c_int {
    // pipe() returns read in low 32 / write high on Darwin via our wrapper...
    // Use open("/dev/null") style: allocate a pipe via net::pipe.
    let mut fds = [0_i32; 2];
    let rc = unsafe { crate::dylib::libsystem_c::net::pipe(fds.as_mut_ptr()) };
    if rc != 0 {
        return -1;
    }
    // Close write end; return read end as a pollable fd.
    let _ = unsafe { crate::dylib::libsystem_c::posix::close(fds[1]) };
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


