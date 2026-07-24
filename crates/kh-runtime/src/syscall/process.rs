//! Process-related BSD syscalls.

use super::common::{SyscallArgs, SyscallResult, exit_status};

/// `exit`.
pub(crate) fn handle_exit(args: SyscallArgs) -> SyscallResult {
    SyscallResult::exit(exit_status(args.x0))
}

/// `getpid`.
pub(crate) fn handle_getpid() -> SyscallResult {
    SyscallResult::ok("getpid", u64::from(std::process::id()))
}

/// `issetugid` — always 0 (not setuid in the translator).
pub(crate) fn handle_issetugid() -> SyscallResult {
    SyscallResult::ok("issetugid", 0)
}
