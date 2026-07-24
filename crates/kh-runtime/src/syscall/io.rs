//! BSD `read` / `write`.

use crate::mem::registry_check_range;

use super::common::{EBADF, EFAULT, EPERM, SyscallArgs, SyscallResult, guest_ptr, guest_ptr_mut};
use super::fd::{guest_to_host_fd, read_host_fd, write_host_fd};

/// `write`.
pub(crate) fn handle_write(args: SyscallArgs) -> SyscallResult {
    let name = "write";
    let Some(host_fd) = guest_to_host_fd(args.x0) else {
        return SyscallResult::err(name, EBADF);
    };
    let Ok(len) = usize::try_from(args.x2) else {
        return SyscallResult::err(name, EFAULT);
    };
    if !registry_check_range(args.x1, len, false) {
        return SyscallResult::err(name, EFAULT);
    }
    if len == 0 {
        return SyscallResult::ok(name, 0);
    }

    // SAFETY: range checked against the guest registry (or unit-test bypass).
    let slice = unsafe { std::slice::from_raw_parts(guest_ptr(args.x1), len) };
    match write_host_fd(host_fd, slice) {
        Ok(n) => SyscallResult::ok(name, u64::try_from(n).unwrap_or(0)),
        Err(_) => SyscallResult::err(name, EPERM),
    }
}

/// `read`.
pub(crate) fn handle_read(args: SyscallArgs) -> SyscallResult {
    let name = "read";
    let Some(host_fd) = guest_to_host_fd(args.x0) else {
        return SyscallResult::err(name, EBADF);
    };
    let Ok(len) = usize::try_from(args.x2) else {
        return SyscallResult::err(name, EFAULT);
    };
    if !registry_check_range(args.x1, len, true) {
        return SyscallResult::err(name, EFAULT);
    }
    if len == 0 {
        return SyscallResult::ok(name, 0);
    }

    let mut buf = vec![0_u8; len];
    match read_host_fd(host_fd, &mut buf) {
        Ok(nread) => {
            // SAFETY: range checked writable in the registry.
            let dst = unsafe { std::slice::from_raw_parts_mut(guest_ptr_mut(args.x1), nread) };
            if let Some(src) = buf.get(..nread) {
                dst.copy_from_slice(src);
            }
            SyscallResult::ok(name, u64::try_from(nread).unwrap_or(0))
        }
        Err(_) => SyscallResult::err(name, EPERM),
    }
}
