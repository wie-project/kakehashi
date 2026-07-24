//! Guest file-descriptor table and FD-related BSD syscalls.

use std::collections::HashMap;
use std::fs::OpenOptions;
use std::os::fd::{FromRawFd, IntoRawFd, RawFd};
use std::sync::Mutex;

use crate::bottle::{self, translate_path};
use crate::mem::registry_check_range;

use super::common::{
    EBADF, EFAULT, EINVAL, ENOENT, EPERM, SyscallArgs, SyscallResult, reg_as_i32, reg_as_i64,
};

/// Darwin `AT_FDCWD` for `openat`.
pub(crate) const AT_FDCWD: i32 = -2;

/// Darwin `fcntl` commands (subset).
const F_DUPFD: i32 = 0;
const F_GETFD: i32 = 1;
const F_SETFD: i32 = 2;
const F_GETFL: i32 = 3;
const F_SETFL: i32 = 4;

/// Darwin open(2) flag bits (subset).
const DARWIN_O_RDONLY: u64 = 0x0000;
const DARWIN_O_WRONLY: u64 = 0x0001;
const DARWIN_O_RDWR: u64 = 0x0002;
const DARWIN_O_CREAT: u64 = 0x0200;
const DARWIN_O_TRUNC: u64 = 0x0400;
const DARWIN_O_APPEND: u64 = 0x0008;
const DARWIN_O_EXCL: u64 = 0x0800;
/// Approximate `O_NONBLOCK` for GETFL reporting.
const DARWIN_O_NONBLOCK: u64 = 0x0004;

/// Darwin `lseek` whence.
const SEEK_SET: i32 = 0;
const SEEK_CUR: i32 = 1;
const SEEK_END: i32 = 2;

// Guest FD → host FD. 0/1/2 are identity (stdin/out/err).
static FD_TABLE: Mutex<Option<HashMap<i32, RawFd>>> = Mutex::new(None);
static NEXT_FD: Mutex<i32> = Mutex::new(32);

/// Resets the guest FD table (called from [`super::reset_syscall_state`]).
pub(crate) fn reset_fd_table() {
    if let Ok(mut t) = FD_TABLE.lock() {
        // Close owned host fds so we do not leak across runs in tests.
        if let Some(map) = t.take() {
            for (gfd, hfd) in map {
                if gfd > 2 {
                    // SAFETY: host fd was owned by the table.
                    unsafe {
                        let _ = libc::close(hfd);
                    }
                }
            }
        }
        *t = Some(HashMap::new());
    }
    if let Ok(mut n) = NEXT_FD.lock() {
        *n = 32;
    }
}

/// Resolves a guest FD register value to a host `RawFd`.
#[must_use]
pub(crate) fn guest_to_host_fd(x0: u64) -> Option<RawFd> {
    guest_to_host_fd_i32(reg_as_i32(x0))
}

fn guest_to_host_fd_i32(gfd: i32) -> Option<RawFd> {
    if gfd == 0 || gfd == 1 || gfd == 2 {
        return Some(gfd);
    }
    FD_TABLE
        .lock()
        .ok()
        .and_then(|t| t.as_ref().and_then(|m| m.get(&gfd).copied()))
}

/// Allocates a new guest FD bound to `host`.
pub(crate) fn alloc_guest_fd(host: RawFd) -> Option<i32> {
    let mut table = FD_TABLE.lock().ok()?;
    let map = table.get_or_insert_with(HashMap::new);
    let mut next = NEXT_FD.lock().ok()?;
    // Skip collisions (unlikely with monotonic counter).
    for _ in 0..1024 {
        let gfd = *next;
        *next = next.saturating_add(1);
        if gfd > 2 && !map.contains_key(&gfd) {
            map.insert(gfd, host);
            return Some(gfd);
        }
    }
    None
}

fn take_guest_fd(gfd: i32) -> Option<RawFd> {
    let mut table = FD_TABLE.lock().ok()?;
    table.as_mut()?.remove(&gfd)
}

fn peek_guest_fd(gfd: i32) -> Option<RawFd> {
    guest_to_host_fd_i32(gfd)
}

/// `open` — path in `x0`, flags in `x1`, mode in `x2` (ignored unless create).
pub(crate) fn handle_open(args: SyscallArgs) -> SyscallResult {
    open_path(args.x0, args.x1, "open")
}

/// `openat` — dirfd `x0`, path `x1`, flags `x2`, mode `x3`.
pub(crate) fn handle_openat(args: SyscallArgs) -> SyscallResult {
    let name = "openat";
    let dirfd = reg_as_i32(args.x0);
    if !registry_check_range(args.x1, 1, false) {
        return SyscallResult::err(name, EFAULT);
    }
    let Some(path) = bottle::read_c_string(args.x1, 4096) else {
        return SyscallResult::err(name, EFAULT);
    };

    if dirfd == AT_FDCWD || path.starts_with('/') {
        return open_translated(&path, args.x2, name);
    }

    let Some(host_dir) = peek_guest_fd(dirfd) else {
        return SyscallResult::err(name, EBADF);
    };

    // Relative openat against a directory FD (no bottle rewrite of relative).
    let flags = darwin_to_host_open_flags(args.x2);
    let mode = u32::try_from(args.x3 & 0xFFFF).unwrap_or(0o666);
    // SAFETY: host_dir is a live table fd; path is a temporary CString.
    let Ok(c_path) = std::ffi::CString::new(path) else {
        return SyscallResult::err(name, EFAULT);
    };
    let rc = unsafe { libc::openat(host_dir, c_path.as_ptr(), flags, mode) };
    if rc < 0 {
        return SyscallResult::err(name, ENOENT);
    }
    if let Some(gfd) = alloc_guest_fd(rc) {
        SyscallResult::ok(name, u64::try_from(gfd).unwrap_or(0))
    } else {
        unsafe {
            let _ = libc::close(rc);
        }
        SyscallResult::err(name, EPERM)
    }
}

fn open_path(path_ptr: u64, flags: u64, name: &'static str) -> SyscallResult {
    if !registry_check_range(path_ptr, 1, false) {
        return SyscallResult::err(name, EFAULT);
    }
    let Some(path) = bottle::read_c_string(path_ptr, 4096) else {
        return SyscallResult::err(name, EFAULT);
    };
    open_translated(&path, flags, name)
}

fn open_translated(path: &str, flags: u64, name: &'static str) -> SyscallResult {
    let Ok(host_path) = translate_path(path) else {
        return SyscallResult::err(name, ENOENT);
    };
    let of = darwin_open_flags(flags);
    let mut opts = OpenOptions::new();
    apply_open_flags(&mut opts, of);
    let Ok(file) = opts.open(&host_path) else {
        return SyscallResult::err(name, ENOENT);
    };
    let host_fd = file.into_raw_fd();
    if let Some(gfd) = alloc_guest_fd(host_fd) {
        SyscallResult::ok(name, u64::try_from(gfd).unwrap_or(0))
    } else {
        unsafe {
            let _ = libc::close(host_fd);
        }
        SyscallResult::err(name, EPERM)
    }
}

/// `close`.
pub(crate) fn handle_close(args: SyscallArgs) -> SyscallResult {
    let name = "close";
    let gfd = reg_as_i32(args.x0);
    if gfd == 0 || gfd == 1 || gfd == 2 {
        return SyscallResult::ok(name, 0);
    }
    match take_guest_fd(gfd) {
        Some(hfd) => {
            let rc = unsafe { libc::close(hfd) };
            if rc == 0 {
                SyscallResult::ok(name, 0)
            } else {
                SyscallResult::err(name, EBADF)
            }
        }
        None => SyscallResult::err(name, EBADF),
    }
}

/// `dup`.
pub(crate) fn handle_dup(args: SyscallArgs) -> SyscallResult {
    let name = "dup";
    let Some(host) = guest_to_host_fd(args.x0) else {
        return SyscallResult::err(name, EBADF);
    };
    // SAFETY: host is a valid open fd.
    let new_host = unsafe { libc::dup(host) };
    if new_host < 0 {
        return SyscallResult::err(name, EBADF);
    }
    if let Some(gfd) = alloc_guest_fd(new_host) {
        SyscallResult::ok(name, u64::try_from(gfd).unwrap_or(0))
    } else {
        unsafe {
            let _ = libc::close(new_host);
        }
        SyscallResult::err(name, EPERM)
    }
}

/// `lseek` — fd `x0`, offset `x1`, whence `x2`.
pub(crate) fn handle_lseek(args: SyscallArgs) -> SyscallResult {
    let name = "lseek";
    let Some(host) = guest_to_host_fd(args.x0) else {
        return SyscallResult::err(name, EBADF);
    };
    let offset = reg_as_i64(args.x1);
    let whence = reg_as_i32(args.x2);
    let host_whence = match whence {
        SEEK_SET => libc::SEEK_SET,
        SEEK_CUR => libc::SEEK_CUR,
        SEEK_END => libc::SEEK_END,
        _ => return SyscallResult::err(name, EINVAL),
    };
    // SAFETY: host fd live.
    let rc = unsafe { libc::lseek(host, offset, host_whence) };
    if rc < 0 {
        return SyscallResult::err(name, EBADF);
    }
    SyscallResult::ok(name, u64::from_ne_bytes(rc.to_ne_bytes()))
}

/// `fcntl` — fd `x0`, cmd `x1`, arg `x2`.
pub(crate) fn handle_fcntl(args: SyscallArgs) -> SyscallResult {
    let name = "fcntl";
    let Some(host) = guest_to_host_fd(args.x0) else {
        return SyscallResult::err(name, EBADF);
    };
    let cmd = reg_as_i32(args.x1);
    let arg = reg_as_i32(args.x2);
    match cmd {
        F_GETFD => {
            let rc = unsafe { libc::fcntl(host, libc::F_GETFD) };
            if rc < 0 {
                SyscallResult::err(name, EBADF)
            } else {
                SyscallResult::ok(name, u64::try_from(rc).unwrap_or(0))
            }
        }
        F_SETFD => {
            let rc = unsafe { libc::fcntl(host, libc::F_SETFD, arg) };
            if rc < 0 {
                SyscallResult::err(name, EBADF)
            } else {
                SyscallResult::ok(name, 0)
            }
        }
        F_GETFL => {
            let rc = unsafe { libc::fcntl(host, libc::F_GETFL) };
            if rc < 0 {
                return SyscallResult::err(name, EBADF);
            }
            // Best-effort map common host bits → Darwin O_* for libc probes.
            let fl = u32::try_from(rc).unwrap_or(0);
            let accmode = u32::try_from(libc::O_ACCMODE).unwrap_or(3);
            let o_wronly = u32::try_from(libc::O_WRONLY).unwrap_or(1);
            let o_rdwr = u32::try_from(libc::O_RDWR).unwrap_or(2);
            let o_append = u32::try_from(libc::O_APPEND).unwrap_or(0);
            let o_nonblock = u32::try_from(libc::O_NONBLOCK).unwrap_or(0);
            let mut d = DARWIN_O_RDONLY;
            let acc = fl & accmode;
            if acc == o_wronly {
                d = DARWIN_O_WRONLY;
            } else if acc == o_rdwr {
                d = DARWIN_O_RDWR;
            }
            if o_append != 0 && fl & o_append != 0 {
                d |= DARWIN_O_APPEND;
            }
            if o_nonblock != 0 && fl & o_nonblock != 0 {
                d |= DARWIN_O_NONBLOCK;
            }
            SyscallResult::ok(name, d)
        }
        F_SETFL => {
            // Map a few Darwin bits to host; ignore unknown.
            let mut host_fl = 0_i32;
            let f = u64::try_from(arg).unwrap_or(0);
            if f & DARWIN_O_APPEND != 0 {
                host_fl |= libc::O_APPEND;
            }
            if f & DARWIN_O_NONBLOCK != 0 {
                host_fl |= libc::O_NONBLOCK;
            }
            let rc = unsafe { libc::fcntl(host, libc::F_SETFL, host_fl) };
            if rc < 0 {
                SyscallResult::err(name, EBADF)
            } else {
                SyscallResult::ok(name, 0)
            }
        }
        F_DUPFD => {
            let rc = unsafe { libc::fcntl(host, libc::F_DUPFD, arg.max(0)) };
            if rc < 0 {
                return SyscallResult::err(name, EBADF);
            }
            if let Some(gfd) = alloc_guest_fd(rc) {
                SyscallResult::ok(name, u64::try_from(gfd).unwrap_or(0))
            } else {
                unsafe {
                    let _ = libc::close(rc);
                }
                SyscallResult::err(name, EPERM)
            }
        }
        _ => SyscallResult::err(name, EINVAL),
    }
}

/// Writes data to a host fd (stdio special-cased for tests).
pub(crate) fn write_host_fd(fd: RawFd, data: &[u8]) -> std::io::Result<usize> {
    use std::io::Write;
    if fd == 1 {
        let mut out = std::io::stdout().lock();
        out.write_all(data)?;
        out.flush()?;
        return Ok(data.len());
    }
    if fd == 2 {
        let mut out = std::io::stderr().lock();
        out.write_all(data)?;
        out.flush()?;
        return Ok(data.len());
    }
    // SAFETY: fd from table / stdio.
    let mut file = unsafe { std::fs::File::from_raw_fd(fd) };
    let n = file.write(data)?;
    let _ = file.into_raw_fd();
    Ok(n)
}

/// Reads from a host fd.
pub(crate) fn read_host_fd(fd: RawFd, buf: &mut [u8]) -> std::io::Result<usize> {
    use std::io::Read;
    if fd == 0 {
        return std::io::stdin().lock().read(buf);
    }
    let mut file = unsafe { std::fs::File::from_raw_fd(fd) };
    let n = file.read(buf)?;
    let _ = file.into_raw_fd();
    Ok(n)
}

// --- open flags --------------------------------------------------------------

#[derive(Debug, Clone, Copy)]
#[allow(clippy::struct_excessive_bools)]
struct OpenFlags {
    read: bool,
    write: bool,
    create: bool,
    truncate: bool,
    append: bool,
    exclusive: bool,
}

fn darwin_open_flags(raw: u64) -> OpenFlags {
    let acc = raw & 0x3;
    OpenFlags {
        read: acc == DARWIN_O_RDONLY || acc == DARWIN_O_RDWR,
        write: acc == DARWIN_O_WRONLY || acc == DARWIN_O_RDWR,
        create: raw & DARWIN_O_CREAT != 0,
        truncate: raw & DARWIN_O_TRUNC != 0,
        append: raw & DARWIN_O_APPEND != 0,
        exclusive: raw & DARWIN_O_EXCL != 0,
    }
}

fn apply_open_flags(opts: &mut OpenOptions, flags: OpenFlags) {
    if flags.read {
        opts.read(true);
    }
    if flags.write {
        opts.write(true);
    }
    if !flags.read && !flags.write {
        opts.read(true);
    }
    if flags.create {
        opts.create(true);
    }
    if flags.truncate {
        opts.truncate(true);
    }
    if flags.append {
        opts.append(true);
    }
    if flags.create && flags.exclusive {
        opts.create_new(true);
    }
}

fn darwin_to_host_open_flags(raw: u64) -> libc::c_int {
    let of = darwin_open_flags(raw);
    let mut f = 0;
    if of.read && of.write {
        f |= libc::O_RDWR;
    } else if of.write {
        f |= libc::O_WRONLY;
    } else {
        f |= libc::O_RDONLY;
    }
    if of.create {
        f |= libc::O_CREAT;
    }
    if of.truncate {
        f |= libc::O_TRUNC;
    }
    if of.append {
        f |= libc::O_APPEND;
    }
    if of.exclusive {
        f |= libc::O_EXCL;
    }
    f
}
