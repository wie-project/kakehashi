//! BSD `read` / `write`.

use crate::mem::registry_check_range;

use super::common::{
    EBADF, EFAULT, EPERM, SyscallArgs, SyscallResult, guest_slice, guest_slice_mut,
};
use super::fd::{guest_to_host_fd, read_host_fd, write_host_fd};

/// Darwin `EAGAIN`.
const DARWIN_EAGAIN: i64 = 35;
/// Darwin `EINTR`.
const DARWIN_EINTR: i64 = 4;
/// Darwin `EPIPE`.
const DARWIN_EPIPE: i64 = 32;
/// Darwin `ENOSPC`.
const DARWIN_ENOSPC: i64 = 28;
/// Darwin `ECONNRESET`.
const DARWIN_ECONNRESET: i64 = 54;

/// Host `write`/`read` errno → Darwin (do not collapse `EPIPE` to `EPERM`).
fn host_io_errno(os: i32) -> i64 {
    if os == libc::EAGAIN || os == libc::EWOULDBLOCK {
        return DARWIN_EAGAIN;
    }
    if os == libc::EINTR {
        return DARWIN_EINTR;
    }
    if os == libc::EPIPE {
        return DARWIN_EPIPE;
    }
    if os == libc::ENOSPC {
        return DARWIN_ENOSPC;
    }
    if os == libc::ECONNRESET {
        return DARWIN_ECONNRESET;
    }
    EPERM
}

/// `write`.
pub(crate) fn handle_write(args: SyscallArgs) -> SyscallResult {
    let name = "write";
    let gfd = super::common::reg_as_i32(args.x0);
    tracing::debug!(gfd, len = args.x2, "write");
    let Some(host_fd) = guest_to_host_fd(args.x0) else {
        // Expected after guest `close` on stdio (fetch-pack prints refs post-close(1)).
        // At `warn` this floods monorepo clones (~hundreds of lines).
        tracing::debug!(gfd, x0 = format_args!("{:#x}", args.x0), "write fail EBADF");
        return SyscallResult::err(name, EBADF);
    };
    let Ok(len) = usize::try_from(args.x2) else {
        return SyscallResult::err(name, EFAULT);
    };
    if len == 0 {
        return SyscallResult::ok(name, 0);
    }
    // Cap ridiculous lengths; full registry walk is TLS-cached on sequential I/O.
    if len > (1 << 30) || !registry_check_range(args.x1, len, false) {
        tracing::warn!(gfd, len, "write fail EFAULT");
        return SyscallResult::err(name, EFAULT);
    }
    write_slice(name, gfd, host_fd, guest_slice(args.x1, len))
}

/// `writev` — rust std / tokio vectored send (TLS ClientHello, HTTP).
pub(crate) fn handle_writev(args: SyscallArgs) -> SyscallResult {
    let name = "writev";
    let gfd = super::common::reg_as_i32(args.x0);
    let iovcnt = super::common::reg_as_i32(args.x2);
    tracing::debug!(gfd, iovcnt, "writev");
    let Some(host_fd) = guest_to_host_fd(args.x0) else {
        return SyscallResult::err(name, EBADF);
    };
    if iovcnt < 0 {
        return SyscallResult::err(name, EFAULT);
    }
    if iovcnt == 0 {
        return SyscallResult::ok(name, 0);
    }
    let Ok(n_iov) = usize::try_from(iovcnt) else {
        return SyscallResult::err(name, EFAULT);
    };
    // POSIX `IOV_MAX` is 1024; rust tokio uses a handful of slices.
    if n_iov > 1024 {
        return SyscallResult::err(name, EFAULT);
    }
    let bytes = n_iov.saturating_mul(16);
    if args.x1 == 0 || !registry_check_range(args.x1, bytes, false) {
        return SyscallResult::err(name, EFAULT);
    }
    let iov = guest_slice(args.x1, bytes);
    let mut total = 0_u64;
    for i in 0..n_iov {
        let off = i.saturating_mul(16);
        let base = u64::from_le_bytes(
            iov.get(off..off.saturating_add(8))
                .and_then(|s| s.try_into().ok())
                .unwrap_or([0; 8]),
        );
        let len = u64::from_le_bytes(
            iov.get(off.saturating_add(8)..off.saturating_add(16))
                .and_then(|s| s.try_into().ok())
                .unwrap_or([0; 8]),
        );
        let Ok(n) = usize::try_from(len) else {
            return SyscallResult::err(name, EFAULT);
        };
        if n == 0 {
            continue;
        }
        if n > (1 << 30) || base == 0 || !registry_check_range(base, n, false) {
            return SyscallResult::err(name, EFAULT);
        }
        let r = write_slice(name, gfd, host_fd, guest_slice(base, n));
        if r.error {
            if total > 0 && r.retval == Some(DARWIN_EAGAIN.unsigned_abs()) {
                return SyscallResult::ok(name, total);
            }
            return r;
        }
        let wrote = r.retval.unwrap_or(0);
        total = total.saturating_add(wrote);
        if wrote < len {
            break;
        }
    }
    SyscallResult::ok(name, total)
}

fn write_slice(
    name: &'static str,
    gfd: i32,
    host_fd: std::os::fd::RawFd,
    slice: &[u8],
) -> SyscallResult {
    if slice.is_empty() {
        return SyscallResult::ok(name, 0);
    }
    // TLS-wrapped guest FD: plaintext app data via rustls (path B freestanding curl).
    if crate::tls_fd::is_tls_fd(gfd) {
        let guest_blocking = !crate::process::fd_guest_nonblock(gfd);
        return match crate::tls_fd::write(gfd, host_fd, slice, guest_blocking) {
            Ok(n) => {
                super::net::rearm_kevent_write(gfd);
                SyscallResult::ok(name, u64::try_from(n).unwrap_or(0))
            }
            Err(e) => {
                let os = e.raw_os_error().unwrap_or(0);
                if os == libc::EAGAIN
                    || os == libc::EWOULDBLOCK
                    || e.kind() == std::io::ErrorKind::WouldBlock
                {
                    return SyscallResult::err(name, DARWIN_EAGAIN);
                }
                if os == libc::EPIPE {
                    tracing::debug!(gfd, "tls write EPIPE");
                } else {
                    tracing::warn!(gfd, error = %e, "tls write fail");
                }
                SyscallResult::err(name, host_io_errno(os))
            }
        };
    }
    // Host pipes are O_NONBLOCK; emulate Darwin blocking write until the guest
    // sets O_NONBLOCK (curl multi) or the pipe drains.
    loop {
        match write_host_fd(host_fd, slice) {
            Ok(n) => {
                super::net::rearm_kevent_write(gfd);
                return SyscallResult::ok(name, u64::try_from(n).unwrap_or(0));
            }
            Err(e) => {
                let os = e.raw_os_error().unwrap_or(0);
                if os == libc::EAGAIN || os == libc::EWOULDBLOCK {
                    if !crate::process::fd_guest_nonblock(gfd)
                        && crate::host::poll_fd_writable(host_fd, -1)
                    {
                        continue;
                    }
                    return SyscallResult::err(name, DARWIN_EAGAIN);
                }
                if os == libc::EPIPE {
                    tracing::debug!(gfd, "write EPIPE");
                } else {
                    tracing::warn!(gfd, error = %e, "write fail");
                }
                return SyscallResult::err(name, host_io_errno(os));
            }
        }
    }
}

/// `pread` — fd `x0`, buf `x1`, len `x2`, offset `x3` (does not move file offset).
#[allow(unsafe_code)]
pub(crate) fn handle_pread(args: SyscallArgs) -> SyscallResult {
    let name = "pread";
    let Some(host_fd) = guest_to_host_fd(args.x0) else {
        return SyscallResult::err(name, EBADF);
    };
    let Ok(len) = usize::try_from(args.x2) else {
        return SyscallResult::err(name, EFAULT);
    };
    if len == 0 {
        return SyscallResult::ok(name, 0);
    }
    if len > (1 << 30) || !registry_check_range(args.x1, len, true) {
        return SyscallResult::err(name, EFAULT);
    }
    let offset = super::common::reg_as_i64(args.x3);
    let buf = guest_slice_mut(args.x1, len);
    // SAFETY: host pread into identity-mapped guest buffer.
    let n = unsafe { libc::pread(host_fd, buf.as_mut_ptr().cast(), len, offset) };
    if n < 0 {
        let os = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        if os == libc::EAGAIN || os == libc::EWOULDBLOCK {
            return SyscallResult::err(name, DARWIN_EAGAIN);
        }
        tracing::warn!(os, "pread fail");
        return SyscallResult::err(name, host_io_errno(os));
    }
    SyscallResult::ok(name, u64::try_from(n).unwrap_or(0))
}

/// `pwrite` — fd `x0`, buf `x1`, len `x2`, offset `x3`.
#[allow(unsafe_code)]
pub(crate) fn handle_pwrite(args: SyscallArgs) -> SyscallResult {
    let name = "pwrite";
    let Some(host_fd) = guest_to_host_fd(args.x0) else {
        return SyscallResult::err(name, EBADF);
    };
    let Ok(len) = usize::try_from(args.x2) else {
        return SyscallResult::err(name, EFAULT);
    };
    if len == 0 {
        return SyscallResult::ok(name, 0);
    }
    if len > (1 << 30) || !registry_check_range(args.x1, len, false) {
        return SyscallResult::err(name, EFAULT);
    }
    let offset = super::common::reg_as_i64(args.x3);
    let slice = guest_slice(args.x1, len);
    let n = unsafe { libc::pwrite(host_fd, slice.as_ptr().cast(), len, offset) };
    if n < 0 {
        let os = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        tracing::warn!(os, "pwrite fail");
        return SyscallResult::err(name, host_io_errno(os));
    }
    SyscallResult::ok(name, u64::try_from(n).unwrap_or(0))
}

/// `read`.
pub(crate) fn handle_read(args: SyscallArgs) -> SyscallResult {
    let name = "read";
    let gfd = super::common::reg_as_i32(args.x0);
    tracing::debug!(gfd, len = args.x2, "read");
    let Some(host_fd) = guest_to_host_fd(args.x0) else {
        return SyscallResult::err(name, EBADF);
    };
    let Ok(len) = usize::try_from(args.x2) else {
        return SyscallResult::err(name, EFAULT);
    };
    if len == 0 {
        return SyscallResult::ok(name, 0);
    }
    if len > (1 << 30) || !registry_check_range(args.x1, len, true) {
        return SyscallResult::err(name, EFAULT);
    }

    read_into(name, gfd, host_fd, guest_slice_mut(args.x1, len))
}

/// `readv`.
pub(crate) fn handle_readv(args: SyscallArgs) -> SyscallResult {
    let name = "readv";
    let gfd = super::common::reg_as_i32(args.x0);
    let iovcnt = super::common::reg_as_i32(args.x2);
    tracing::debug!(gfd, iovcnt, "readv");
    let Some(host_fd) = guest_to_host_fd(args.x0) else {
        return SyscallResult::err(name, EBADF);
    };
    if iovcnt < 0 {
        return SyscallResult::err(name, EFAULT);
    }
    if iovcnt == 0 {
        return SyscallResult::ok(name, 0);
    }
    let Ok(n_iov) = usize::try_from(iovcnt) else {
        return SyscallResult::err(name, EFAULT);
    };
    if n_iov > 1024 {
        return SyscallResult::err(name, EFAULT);
    }
    let bytes = n_iov.saturating_mul(16);
    if args.x1 == 0 || !registry_check_range(args.x1, bytes, false) {
        return SyscallResult::err(name, EFAULT);
    }
    let iov = guest_slice(args.x1, bytes).to_vec();
    let mut total = 0_u64;
    for i in 0..n_iov {
        let off = i.saturating_mul(16);
        let base = u64::from_le_bytes(
            iov.get(off..off.saturating_add(8))
                .and_then(|s| s.try_into().ok())
                .unwrap_or([0; 8]),
        );
        let len = u64::from_le_bytes(
            iov.get(off.saturating_add(8)..off.saturating_add(16))
                .and_then(|s| s.try_into().ok())
                .unwrap_or([0; 8]),
        );
        let Ok(n) = usize::try_from(len) else {
            return SyscallResult::err(name, EFAULT);
        };
        if n == 0 {
            continue;
        }
        if n > (1 << 30) || base == 0 || !registry_check_range(base, n, true) {
            return SyscallResult::err(name, EFAULT);
        }
        let r = read_into(name, gfd, host_fd, guest_slice_mut(base, n));
        if r.error {
            if total > 0 && r.retval == Some(DARWIN_EAGAIN.unsigned_abs()) {
                return SyscallResult::ok(name, total);
            }
            return r;
        }
        let got = r.retval.unwrap_or(0);
        total = total.saturating_add(got);
        if got < len || got == 0 {
            break;
        }
    }
    SyscallResult::ok(name, total)
}

fn read_into(
    name: &'static str,
    gfd: i32,
    host_fd: std::os::fd::RawFd,
    buf: &mut [u8],
) -> SyscallResult {
    if buf.is_empty() {
        return SyscallResult::ok(name, 0);
    }
    // Read straight into guest memory (identity map) — no intermediate heap
    // buffer. Double-copy + `Vec` was a major cost on multi‑MiB archive I/O.
    // TLS-wrapped guest FD: plaintext from rustls (path B freestanding curl).
    if crate::tls_fd::is_tls_fd(gfd) {
        let guest_blocking = !crate::process::fd_guest_nonblock(gfd);
        return match crate::tls_fd::read(gfd, host_fd, buf, guest_blocking) {
            Ok(nread) => {
                tracing::debug!(gfd, nread, "tls read ok");
                SyscallResult::ok(name, u64::try_from(nread).unwrap_or(0))
            }
            Err(e) => {
                let os = e.raw_os_error().unwrap_or(0);
                if os == libc::EAGAIN
                    || os == libc::EWOULDBLOCK
                    || e.kind() == std::io::ErrorKind::WouldBlock
                {
                    tracing::debug!(gfd, "tls read EAGAIN");
                    return SyscallResult::err(name, DARWIN_EAGAIN);
                }
                tracing::warn!(gfd, error = %e, "tls read fail");
                SyscallResult::err(name, host_io_errno(os))
            }
        };
    }
    // Host pipes/sockets are O_NONBLOCK (curl multi). Darwin guests expect
    // blocking reads until they fcntl O_NONBLOCK — wait on EAGAIN when the
    // guest flag is clear (git notify-pipe, helper stdin). When the guest set
    // nonblock (or the fd is a socket marked nonblock at alloc), surface EAGAIN.
    loop {
        match read_host_fd(host_fd, buf) {
            Ok(nread) => {
                tracing::debug!(gfd, nread, "read ok");
                return SyscallResult::ok(name, u64::try_from(nread).unwrap_or(0));
            }
            Err(e) => {
                let os = e.raw_os_error().unwrap_or(0);
                if os == libc::EAGAIN || os == libc::EWOULDBLOCK {
                    // Guest-blocking FD: wait for data (git notify-pipe / helper
                    // stdin). Guest-nonblock (curl multi / sockets): EAGAIN.
                    if !crate::process::fd_guest_nonblock(gfd)
                        && crate::host::poll_fd_readable(host_fd, -1)
                    {
                        continue;
                    }
                    tracing::debug!(gfd, "read EAGAIN");
                    return SyscallResult::err(name, DARWIN_EAGAIN);
                }
                if os == libc::EPIPE {
                    tracing::debug!(gfd, "read EPIPE");
                } else {
                    tracing::warn!(gfd, os, "read fail");
                }
                return SyscallResult::err(name, host_io_errno(os));
            }
        }
    }
}
