//! Process-related BSD syscalls.

use super::common::{SyscallArgs, SyscallResult, exit_status};

/// `exit`.
pub(crate) fn handle_exit(args: SyscallArgs) -> SyscallResult {
    SyscallResult::exit(exit_status(args.x0))
}

/// `getpid`.
/// `getuid` — host real user id (must match file owners for git safe.directory).
#[allow(unsafe_code)]
pub(crate) fn handle_getuid() -> SyscallResult {
    // SAFETY: host getuid has no preconditions.
    let uid = unsafe { libc::getuid() };
    SyscallResult::ok("getuid", u64::from(uid))
}

/// `geteuid`.
#[allow(unsafe_code)]
pub(crate) fn handle_geteuid() -> SyscallResult {
    let uid = unsafe { libc::geteuid() };
    SyscallResult::ok("geteuid", u64::from(uid))
}

/// `getgid`.
#[allow(unsafe_code)]
pub(crate) fn handle_getgid() -> SyscallResult {
    let gid = unsafe { libc::getgid() };
    SyscallResult::ok("getgid", u64::from(gid))
}

/// `getegid`.
#[allow(unsafe_code)]
pub(crate) fn handle_getegid() -> SyscallResult {
    let gid = unsafe { libc::getegid() };
    SyscallResult::ok("getegid", u64::from(gid))
}

pub(crate) fn handle_getpid() -> SyscallResult {
    SyscallResult::ok("getpid", u64::from(std::process::id()))
}

/// `getppid` — parent of the host process (same identity as guest under kh).
#[allow(unsafe_code)] // thin libc wrapper; no safer std equivalent
pub(crate) fn handle_getppid() -> SyscallResult {
    // SAFETY: `getppid` is always defined and has no preconditions.
    let ppid = unsafe { libc::getppid() };
    SyscallResult::ok("getppid", u64::try_from(ppid).unwrap_or(1))
}

/// `issetugid` — always 0 (not setuid in the translator).
pub(crate) fn handle_issetugid() -> SyscallResult {
    SyscallResult::ok("issetugid", 0)
}
