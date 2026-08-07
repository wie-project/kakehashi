//! Guest file-descriptor table accessors and FD-related BSD syscalls.

use std::io::{Read, Write};
use std::os::fd::RawFd;

use crate::bottle::{self, translate_path};
use crate::host;
use crate::mem::registry_check_range;
use crate::process;

use super::common::{
    EBADF, EEXIST, EFAULT, EINVAL, ENOENT, EPERM, SyscallArgs, SyscallResult, guest_write,
    reg_as_i32, reg_as_i64,
};

/// Darwin `AT_FDCWD` for `openat`.
pub(crate) const AT_FDCWD: i32 = -2;

/// Darwin `fcntl` commands (subset).
const F_DUPFD: i32 = 0;
const F_GETFD: i32 = 1;
const F_SETFD: i32 = 2;
const F_GETFL: i32 = 3;
const F_SETFL: i32 = 4;
/// Darwin `F_GETPATH` — write path of `fd` into `arg` buffer (`MAXPATHLEN`).
const F_GETPATH: i32 = 50;
/// Darwin `MAXPATHLEN` / `PATH_MAX` for `F_GETPATH` buffer.
const DARWIN_MAXPATHLEN: usize = 1024;

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

/// Resolves a guest FD register value to a host `RawFd`.
#[must_use]
pub(crate) fn guest_to_host_fd(x0: u64) -> Option<RawFd> {
    guest_to_host_fd_i32(reg_as_i32(x0))
}

fn guest_to_host_fd_i32(gfd: i32) -> Option<RawFd> {
    // Lock-free atomic map — do not take ProcessState on every read/write.
    process::fd_get(gfd)
}

/// Allocates a new guest FD bound to `host_fd` (lock-free).
pub(crate) fn alloc_guest_fd(host_fd: RawFd) -> Option<i32> {
    process::fd_alloc(host_fd)
}

fn take_guest_fd(gfd: i32) -> Option<RawFd> {
    process::fd_take(gfd)
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
    let Some(bytes) = bottle::read_c_bytes(args.x1, 4096) else {
        return SyscallResult::err(name, EFAULT);
    };
    let path = String::from_utf8_lossy(&bytes).into_owned();

    if dirfd == AT_FDCWD || path.starts_with('/') {
        return open_translated(&path, args.x2, name);
    }

    let Some(host_dir) = guest_to_host_fd_i32(dirfd) else {
        return SyscallResult::err(name, EBADF);
    };

    let flags = darwin_to_host_open_flags(args.x2);
    let mode = u32::try_from(args.x3 & 0xFFFF).unwrap_or(0o666);
    // CString rejects interior NUL; our bytes already stop at first NUL.
    let Ok(c_path) = std::ffi::CString::new(bytes) else {
        return SyscallResult::err(name, EFAULT);
    };
    let Some(rc) = host::openat(host_dir, &c_path, flags, mode) else {
        return SyscallResult::err(name, ENOENT);
    };
    finish_open(name, rc)
}

fn open_path(path_ptr: u64, flags: u64, name: &'static str) -> SyscallResult {
    if !registry_check_range(path_ptr, 1, false) {
        return SyscallResult::err(name, EFAULT);
    }
    let Some(bytes) = bottle::read_c_bytes(path_ptr, 4096) else {
        return SyscallResult::err(name, EFAULT);
    };
    // Darwin paths are bytes; lossy only for logging / bottle PathBuf.
    let path = String::from_utf8_lossy(&bytes).into_owned();
    open_translated(&path, flags, name)
}

/// Map host `errno` after a failed `open`/`openat` to Darwin errno.
///
/// Important for curl `--no-clobber` (`O_CREAT|O_EXCL`): must surface `EEXIST`,
/// not a blanket `ENOENT` (that made curl report write error 23).
fn map_open_errno(host_err: i32) -> i64 {
    if host_err == libc::ENOENT {
        ENOENT
    } else if host_err == libc::EEXIST {
        EEXIST
    } else if host_err == libc::EACCES || host_err == libc::EPERM {
        EPERM
    } else if host_err == libc::EINVAL || host_err == libc::EISDIR || host_err == libc::ENOTDIR {
        EINVAL
    } else {
        // Preserve positive host errno when it overlaps Darwin; else ENOENT.
        i64::from(host_err).abs().max(1)
    }
}

fn open_fail(name: &'static str, path: &str, why: &str) -> SyscallResult {
    let host_err = std::io::Error::last_os_error()
        .raw_os_error()
        .unwrap_or(libc::ENOENT);
    let darwin = map_open_errno(host_err);
    log_open_fail(
        path,
        host_err,
        &format!("{why} host_errno={host_err} darwin={darwin}"),
    );
    SyscallResult::err(name, darwin)
}

fn open_translated(path: &str, flags: u64, name: &'static str) -> SyscallResult {
    let r = open_translated_once(path, flags, name);
    if !r.error {
        return r;
    }
    // G5: modern ld may open paths with a dropped `/` (liblib, .sdkusr, …).
    let enoent = r.error && r.retval == Some(ENOENT.unsigned_abs());
    if enoent && let Some(fixed) = bottle::repair_ld_guest_path(path) {
        let r2 = open_translated_once(&fixed, flags, name);
        if !r2.error {
            tracing::debug!(guest = %path, fixed = %fixed, "open ok (ld path repair)");
            return r2;
        }
    }
    r
}

fn open_translated_once(path: &str, flags: u64, name: &'static str) -> SyscallResult {
    let host_flags = darwin_to_host_open_flags(flags);
    let mode = 0o666_u32;
    let creat = host_flags & libc::O_CREAT != 0;
    // O_EXCL alone is not useful; mkdir-retry only when create is requested and
    // failure looks like missing parent (not EEXIST from --no-clobber).
    let excl = host_flags & libc::O_EXCL != 0;
    // B1: bottle dirfd + relative path — no PathBuf join, shorter kernel walk.
    if let Some((dirfd, rel)) = bottle::bottle_openat_rel(path) {
        let Ok(c_rel) = std::ffi::CString::new(rel) else {
            return SyscallResult::err(name, EFAULT);
        };
        if let Some(rc) = host::openat(dirfd, &c_rel, host_flags, mode) {
            return finish_open(name, rc);
        }
        let first_err = std::io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::ENOENT);
        // curl `-o nested/file`: parent may not exist yet. With O_CREAT (and not
        // a pure exclusivity race), make parents under the bottle and retry once.
        if creat
            && first_err == libc::ENOENT
            && let Some(parent) = std::path::Path::new(rel).parent()
            && !parent.as_os_str().is_empty()
            && parent != std::path::Path::new(".")
        {
            drop(mkdirat_p(dirfd, parent));
            if let Some(rc) = host::openat(dirfd, &c_rel, host_flags, mode) {
                return finish_open(name, rc);
            }
        }
        // Prefer the first errno (EEXIST from O_EXCL must not become ENOENT).
        if first_err == libc::EEXIST || excl {
            log_open_fail(
                path,
                first_err,
                &format!(
                    "openat host_errno={first_err} darwin={}",
                    map_open_errno(first_err)
                ),
            );
            return SyscallResult::err(name, map_open_errno(first_err));
        }
        return open_fail(name, path, "openat");
    }

    let Ok(host_path) = translate_path(path) else {
        log_open_fail(path, libc::ENOENT, "ENOENT(translate)");
        return SyscallResult::err(name, ENOENT);
    };
    let Ok(c_path) = std::ffi::CString::new(host_path.as_os_str().as_encoded_bytes()) else {
        return SyscallResult::err(name, EFAULT);
    };
    // libc open: works for directories (opendir path) and files alike.
    if let Some(rc) = host::open_path(&c_path, host_flags, mode) {
        return finish_open(name, rc);
    }
    let first_err = std::io::Error::last_os_error()
        .raw_os_error()
        .unwrap_or(libc::ENOENT);
    // Relative `-o .tmp/out/body` (host CWD) or absolute under bottle: create
    // missing parents when the guest asked for O_CREAT (fopen "w" / curl -o).
    if creat
        && first_err == libc::ENOENT
        && let Some(parent) = host_path.parent()
        && !parent.as_os_str().is_empty()
    {
        drop(std::fs::create_dir_all(parent));
        if let Some(rc) = host::open_path(&c_path, host_flags, mode) {
            return finish_open(name, rc);
        }
    }
    if first_err == libc::EEXIST || excl {
        log_open_fail(
            path,
            first_err,
            &format!(
                "open host_errno={first_err} darwin={}",
                map_open_errno(first_err)
            ),
        );
        return SyscallResult::err(name, map_open_errno(first_err));
    }
    open_fail(name, path, "open")
}

/// Log open failures. **ENOENT / EEXIST are expected** (git probes missing
/// objects, templates, attrs) — at default `warn` they flooded Docker logs
/// (~thousands/sec on monorepo clone) and crushed throughput via virtiofs.
fn log_open_fail(path: &str, host_err: i32, why: &str) {
    if host_err == libc::ENOENT || host_err == libc::EEXIST {
        tracing::debug!(path, why, "open fail");
    } else {
        tracing::warn!(path, why, "open fail");
    }
}

/// Create intermediate directories for a bottle-relative path (`a/b` → `mkdirat a`).
fn mkdirat_p(dirfd: RawFd, rel: &std::path::Path) -> std::io::Result<()> {
    let mut cur = std::path::PathBuf::new();
    for comp in rel.components() {
        use std::path::Component;
        if let Component::Normal(s) = comp {
            cur.push(s);
            let Ok(c) = std::ffi::CString::new(cur.as_os_str().as_encoded_bytes()) else {
                continue;
            };
            host::mkdirat(dirfd, &c, 0o755)?;
        }
    }
    Ok(())
}

fn finish_open(name: &'static str, host_fd: RawFd) -> SyscallResult {
    if let Some(gfd) = alloc_guest_fd(host_fd) {
        SyscallResult::ok(name, u64::try_from(gfd).unwrap_or(0))
    } else {
        host::close_fd(host_fd);
        SyscallResult::err(name, EPERM)
    }
}

/// `close`.
///
/// Stdio 0–2 used to soft-succeed without closing the host descriptor. That
/// broke Apple `git fetch-pack --stateless-rpc`, which `close(1)`s before
/// printing fetched refs — those lines then leaked into remote-curl → parent
/// as `https unexpectedly said: '<sha> refs/…'` (e.g. 560 lines on folly).
pub(crate) fn handle_close(args: SyscallArgs) -> SyscallResult {
    let name = "close";
    let gfd = reg_as_i32(args.x0);
    // Drop readdir stream before releasing the host FD.
    process::with_mut(|p| p.close_dir_stream(gfd));
    // Drop rustls session before closing the wire socket.
    let _ = crate::tls_fd::take_tls(gfd);
    match take_guest_fd(gfd) {
        Some(hfd) => {
            host::close_fd(hfd);
            SyscallResult::ok(name, 0)
        }
        None => SyscallResult::err(name, EBADF),
    }
}

/// `dup`.
pub(crate) fn handle_dup(args: SyscallArgs) -> SyscallResult {
    let name = "dup";
    let old = reg_as_i32(args.x0);
    let Some(h) = guest_to_host_fd(args.x0) else {
        return SyscallResult::err(name, EBADF);
    };
    let Some(new_host) = host::dup_fd(h) else {
        return SyscallResult::err(name, EBADF);
    };
    let nb = process::fd_guest_nonblock(old);
    if let Some(gfd) = alloc_guest_fd(new_host) {
        process::fd_set_guest_nonblock(gfd, nb);
        SyscallResult::ok(name, u64::try_from(gfd).unwrap_or(0))
    } else {
        host::close_fd(new_host);
        SyscallResult::err(name, EPERM)
    }
}

/// `dup2` — oldfd `x0`, newfd `x1`.
pub(crate) fn handle_dup2(args: SyscallArgs) -> SyscallResult {
    let name = "dup2";
    let old = reg_as_i32(args.x0);
    let new = reg_as_i32(args.x1);
    if new < 0 {
        return SyscallResult::err(name, EBADF);
    }
    let Some(host_old) = guest_to_host_fd_i32(old) else {
        return SyscallResult::err(name, EBADF);
    };
    if old == new {
        return SyscallResult::ok(name, u64::try_from(new).unwrap_or(0));
    }

    let nb = process::fd_guest_nonblock(old);

    // Stdio slots are identity-mapped to host 0/1/2 — must host-dup2 so the
    // next `execve` (re-exec of `kh`) inherits the redirected descriptors.
    // Also re-opens a slot previously `close`'d (see [`handle_close`]).
    if new <= 2 {
        if host::dup2_fd(host_old, new).is_none() {
            return SyscallResult::err(name, EBADF);
        }
        process::stdio_mark_open(new);
        process::fd_set_guest_nonblock(new, nb);
        return SyscallResult::ok(name, u64::try_from(new).unwrap_or(0));
    }

    let Some(host_new) = host::dup_fd(host_old) else {
        return SyscallResult::err(name, EBADF);
    };
    if !process::fd_install(new, host_new) {
        host::close_fd(host_new);
        return SyscallResult::err(name, EBADF);
    }
    process::fd_set_guest_nonblock(new, nb);
    SyscallResult::ok(name, u64::try_from(new).unwrap_or(0))
}

/// `lseek` — fd `x0`, offset `x1`, whence `x2`.
pub(crate) fn handle_lseek(args: SyscallArgs) -> SyscallResult {
    let name = "lseek";
    let Some(h) = guest_to_host_fd(args.x0) else {
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
    let Some(rc) = host::lseek_fd(h, offset, host_whence) else {
        return SyscallResult::err(name, EBADF);
    };
    SyscallResult::ok(name, u64::from_ne_bytes(rc.to_ne_bytes()))
}

/// `fcntl` — fd `x0`, cmd `x1`, arg `x2`.
pub(crate) fn handle_fcntl(args: SyscallArgs) -> SyscallResult {
    let name = "fcntl";
    let Some(h) = guest_to_host_fd(args.x0) else {
        return SyscallResult::err(name, EBADF);
    };
    let cmd = reg_as_i32(args.x1);
    let arg = reg_as_i32(args.x2);
    match cmd {
        F_GETFD => match host::fcntl_get(h, libc::F_GETFD) {
            Some(rc) => SyscallResult::ok(name, u64::try_from(rc).unwrap_or(0)),
            None => SyscallResult::err(name, EBADF),
        },
        F_SETFD => match host::fcntl_set(h, libc::F_SETFD, arg) {
            Some(_) => SyscallResult::ok(name, 0),
            None => SyscallResult::err(name, EBADF),
        },
        F_GETFL => {
            let Some(rc) = host::fcntl_get(h, libc::F_GETFL) else {
                return SyscallResult::err(name, EBADF);
            };
            // Report guest-visible O_NONBLOCK, not host (pipes are host-nonblock
            // for curl multi while guests still see Darwin blocking defaults).
            let mut d = host_fl_to_darwin(rc);
            let gfd = reg_as_i32(args.x0);
            d &= !DARWIN_O_NONBLOCK;
            if process::fd_guest_nonblock(gfd) {
                d |= DARWIN_O_NONBLOCK;
            }
            SyscallResult::ok(name, d)
        }
        F_SETFL => {
            // `arg` is the full Darwin flags word (or 0 if guest omitted it).
            // Preserve host access-mode bits; only toggle status flags we map.
            let flags = u64::try_from(arg).unwrap_or(0);
            let guest_nb = flags & DARWIN_O_NONBLOCK != 0;
            let gfd = reg_as_i32(args.x0);
            process::fd_set_guest_nonblock(gfd, guest_nb);
            let Some(cur) = host::fcntl_get(h, libc::F_GETFL) else {
                return SyscallResult::err(name, EBADF);
            };
            let mut host_fl = cur & !libc::O_NONBLOCK & !libc::O_APPEND;
            host_fl |= darwin_fl_to_host(flags);
            match host::fcntl_set(h, libc::F_SETFL, host_fl) {
                Some(_) => SyscallResult::ok(name, 0),
                None => SyscallResult::err(name, EBADF),
            }
        }
        F_DUPFD => {
            let Some(rc) = host::fcntl_set(h, libc::F_DUPFD, arg.max(0)) else {
                return SyscallResult::err(name, EBADF);
            };
            finish_open(name, rc)
        }
        F_GETPATH => {
            // G5: modern `ld` / tapi call `fcntl(fd, F_GETPATH, buf)` after open.
            // Soft-ok without filling the buffer left garbage paths (observed
            // follow-up `open("\u{2}")`) and tapi `ENOENT in '…liblib…'`.
            let buf = args.x2;
            if !registry_check_range(buf, DARWIN_MAXPATHLEN, true) {
                return SyscallResult::err(name, EFAULT);
            }
            let Some(guest_path) = guest_path_for_host_fd(h) else {
                return SyscallResult::err(name, ENOENT);
            };
            let bytes = guest_path.as_bytes();
            // Need room for path + NUL.
            if bytes.len().saturating_add(1) > DARWIN_MAXPATHLEN {
                return SyscallResult::err(name, ENOENT);
            }
            guest_write(buf, bytes);
            let nul_off = buf.saturating_add(u64::try_from(bytes.len()).unwrap_or(0));
            guest_write(nul_off, &[0]);
            tracing::debug!(%guest_path, "fcntl F_GETPATH");
            SyscallResult::ok(name, 0)
        }
        _ => {
            // Soft-success for unknown fcntl cmds (F_FULLFSYNC, F_NOCACHE, …).
            // Hard EINVAL made guests spin; macOS ignores many optional cmds.
            log_fcntl_cmd(cmd);
            SyscallResult::ok(name, 0)
        }
    }
}

/// Guest-visible path for a host FD (`/proc/self/fd/N` → bottle/guest form).
fn guest_path_for_host_fd(h: RawFd) -> Option<String> {
    let link = std::fs::read_link(format!("/proc/self/fd/{h}")).ok()?;
    bottle::host_path_to_guest(&link)
}

fn log_fcntl_cmd(cmd: i32) {
    tracing::debug!(cmd, "fcntl soft-ok (unknown cmd)");
}

fn host_fl_to_darwin(rc: i32) -> u64 {
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
    d
}

fn darwin_fl_to_host(f: u64) -> i32 {
    let mut host_fl = 0_i32;
    if f & DARWIN_O_APPEND != 0 {
        host_fl |= libc::O_APPEND;
    }
    if f & DARWIN_O_NONBLOCK != 0 {
        host_fl |= libc::O_NONBLOCK;
    }
    host_fl
}

/// Writes data to a host fd (stdio special-cased for tests).
pub(crate) fn write_host_fd(fd: RawFd, data: &[u8]) -> std::io::Result<usize> {
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
    host::write_fd(fd, data)
}

/// Reads from a host fd.
pub(crate) fn read_host_fd(fd: RawFd, buf: &mut [u8]) -> std::io::Result<usize> {
    if fd == 0 {
        return std::io::stdin().lock().read(buf);
    }
    host::read_fd(fd, buf)
}

// --- open flags --------------------------------------------------------------

/// Bit-packed open flags (avoids a bool-heavy struct for clippy).
#[derive(Debug, Clone, Copy)]
struct OpenFlags(u8);

impl OpenFlags {
    const READ: u8 = 1 << 0;
    const WRITE: u8 = 1 << 1;
    const CREATE: u8 = 1 << 2;
    const TRUNCATE: u8 = 1 << 3;
    const APPEND: u8 = 1 << 4;
    const EXCLUSIVE: u8 = 1 << 5;

    const fn has(self, bit: u8) -> bool {
        self.0 & bit != 0
    }
}

fn darwin_open_flags(raw: u64) -> OpenFlags {
    let acc = raw & 0x3;
    let mut bits = 0_u8;
    if acc == DARWIN_O_RDONLY || acc == DARWIN_O_RDWR {
        bits |= OpenFlags::READ;
    }
    if acc == DARWIN_O_WRONLY || acc == DARWIN_O_RDWR {
        bits |= OpenFlags::WRITE;
    }
    if raw & DARWIN_O_CREAT != 0 {
        bits |= OpenFlags::CREATE;
    }
    if raw & DARWIN_O_TRUNC != 0 {
        bits |= OpenFlags::TRUNCATE;
    }
    if raw & DARWIN_O_APPEND != 0 {
        bits |= OpenFlags::APPEND;
    }
    if raw & DARWIN_O_EXCL != 0 {
        bits |= OpenFlags::EXCLUSIVE;
    }
    OpenFlags(bits)
}

fn darwin_to_host_open_flags(raw: u64) -> libc::c_int {
    let of = darwin_open_flags(raw);
    let mut f = 0;
    if of.has(OpenFlags::READ) && of.has(OpenFlags::WRITE) {
        f |= libc::O_RDWR;
    } else if of.has(OpenFlags::WRITE) {
        f |= libc::O_WRONLY;
    } else {
        f |= libc::O_RDONLY;
    }
    if of.has(OpenFlags::CREATE) {
        f |= libc::O_CREAT;
    }
    if of.has(OpenFlags::TRUNCATE) {
        f |= libc::O_TRUNC;
    }
    if of.has(OpenFlags::APPEND) {
        f |= libc::O_APPEND;
    }
    if of.has(OpenFlags::EXCLUSIVE) {
        f |= libc::O_EXCL;
    }
    f
}
