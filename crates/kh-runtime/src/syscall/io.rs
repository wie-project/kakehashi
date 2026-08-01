//! BSD `read` / `write`.

use crate::mem::registry_check_range;

use super::common::{
    EBADF, EFAULT, EPERM, SyscallArgs, SyscallResult, guest_slice, guest_slice_mut,
};
use super::fd::{guest_to_host_fd, read_host_fd, write_host_fd};

/// `write`.
pub(crate) fn handle_write(args: SyscallArgs) -> SyscallResult {
    let name = "write";
    let gfd = super::common::reg_as_i32(args.x0);
    tracing::debug!(gfd, len = args.x2, "write");
    let Some(host_fd) = guest_to_host_fd(args.x0) else {
        tracing::warn!(gfd, x0 = format_args!("{:#x}", args.x0), "write fail EBADF");
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

    let slice = guest_slice(args.x1, len);
    match write_host_fd(host_fd, slice) {
        Ok(n) => SyscallResult::ok(name, u64::try_from(n).unwrap_or(0)),
        Err(e) => {
            tracing::warn!(gfd, error = %e, "write fail");
            SyscallResult::err(name, EPERM)
        }
    }
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

    // Read straight into guest memory (identity map) — no intermediate heap
    // buffer. Double-copy + `Vec` was a major cost on multi‑MiB archive I/O.
    let buf = guest_slice_mut(args.x1, len);
    match read_host_fd(host_fd, buf) {
        Ok(nread) => {
            tracing::debug!(gfd, nread, "read ok");
            SyscallResult::ok(name, u64::try_from(nread).unwrap_or(0))
        }
        Err(e) => {
            let os = e.raw_os_error().unwrap_or(0);
            // Map Linux EAGAIN/EWOULDBLOCK → Darwin EAGAIN (35).
            if os == libc::EAGAIN || os == libc::EWOULDBLOCK {
                tracing::debug!(gfd, "read EAGAIN");
                return SyscallResult::err(name, 35);
            }
            tracing::warn!(gfd, os, "read fail");
            SyscallResult::err(name, EPERM)
        }
    }
}
