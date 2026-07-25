//! BSD `read` / `write`.

use crate::mem::registry_check_range;

use super::common::{
    EBADF, EFAULT, EPERM, SyscallArgs, SyscallResult, guest_slice, guest_slice_mut,
};
use super::fd::{guest_to_host_fd, read_host_fd, write_host_fd};

/// `write`.
pub(crate) fn handle_write(args: SyscallArgs) -> SyscallResult {
    let name = "write";
    let Some(host_fd) = guest_to_host_fd(args.x0) else {
        log_io_fail("write", "EBADF", args.x0, args.x1, args.x2);
        return SyscallResult::err(name, EBADF);
    };
    let Ok(len) = usize::try_from(args.x2) else {
        return SyscallResult::err(name, EFAULT);
    };
    if !registry_check_range(args.x1, len, false) {
        log_io_fail("write", "EFAULT", args.x0, args.x1, args.x2);
        return SyscallResult::err(name, EFAULT);
    }
    if len == 0 {
        return SyscallResult::ok(name, 0);
    }

    let slice = guest_slice(args.x1, len);
    match write_host_fd(host_fd, slice) {
        Ok(n) => SyscallResult::ok(name, u64::try_from(n).unwrap_or(0)),
        Err(e) => {
            log_io_fail("write", &format!("EPERM({e})"), args.x0, args.x1, args.x2);
            SyscallResult::err(name, EPERM)
        }
    }
}

fn log_io_fail(op: &str, why: &str, x0: u64, x1: u64, x2: u64) {
    use std::sync::atomic::{AtomicU32, Ordering};
    static N: AtomicU32 = AtomicU32::new(0);
    if N.fetch_add(1, Ordering::Relaxed) >= 24 {
        return;
    }
    let msg = format!("kh: {op} fail {why} x0={x0:#x} buf={x1:#x} len={x2:#x}\n");
    drop(std::io::Write::write_all(
        &mut std::io::stderr(),
        msg.as_bytes(),
    ));
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
            if let Some(src) = buf.get(..nread) {
                guest_slice_mut(args.x1, nread).copy_from_slice(src);
            }
            SyscallResult::ok(name, u64::try_from(nread).unwrap_or(0))
        }
        Err(_) => SyscallResult::err(name, EPERM),
    }
}
