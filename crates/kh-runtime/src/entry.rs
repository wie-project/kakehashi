//! Jump / call into mapped guest code (AArch64 only).
#![allow(unsafe_code)]

use thiserror::Error;

/// Errors when transferring control to guest code.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum EntryError {
    /// Host is not AArch64.
    #[error("guest entry requires aarch64 host")]
    UnsupportedArch,

    /// Entry address is null / obviously invalid.
    #[error("invalid guest entry address {0:#x}")]
    InvalidEntry(u64),

    /// Stack pointer is not 16-byte aligned.
    #[error("stack pointer {0:#x} is not 16-byte aligned")]
    MisalignedStack(u64),
}

/// Transfers control to `entry` with stack pointer `sp`.
///
/// Does not return on success: guest code must trap into the trap backend
/// (e.g. Darwin `exit` rewritten as `brk`) which terminates the process.
///
/// # Safety
///
/// Caller must guarantee:
/// - `entry` points at executable mapped guest code;
/// - `sp` points at a valid mapped stack with bootstrapped argv;
/// - trap handlers are installed if guest may issue syscalls;
/// - no Rust objects requiring Drop need to run after the jump (or the trap
///   path exits the process).
pub unsafe fn jump_to_guest(entry: u64, sp: u64) -> Result<(), EntryError> {
    // SAFETY: same invariants; extra arg regs zeroed.
    unsafe { jump_to_guest_args(entry, sp, 0, 0, 0, 0) }
}

/// Like [`jump_to_guest`], but places `x0`–`x3` before the branch (pthread start).
///
/// Does not return: guest must `exit` the process or `bsdthread_terminate` the
/// host thread (trap backend redirects to host `pthread_exit`).
///
/// # Safety
///
/// Same as [`jump_to_guest`], plus argument registers must match the guest
/// entry convention (Darwin `_pthread_start`: pthread, port, func, arg).
pub unsafe fn jump_to_guest_args(
    entry: u64,
    sp: u64,
    x0: u64,
    x1: u64,
    x2: u64,
    x3: u64,
) -> Result<(), EntryError> {
    if entry == 0 {
        return Err(EntryError::InvalidEntry(entry));
    }
    if !sp.is_multiple_of(16) {
        return Err(EntryError::MisalignedStack(sp));
    }

    #[cfg(not(target_arch = "aarch64"))]
    {
        let _ = (entry, sp, x0, x1, x2, x3);
        return Err(EntryError::UnsupportedArch);
    }

    #[cfg(target_arch = "aarch64")]
    {
        // SAFETY: caller invariants documented above. We zero FP/LR so a
        // guest return would fault rather than walk a bogus Rust frame.
        unsafe {
            std::arch::asm!(
                "mov sp, {sp}",
                "mov x0, {arg0}",
                "mov x1, {arg1}",
                "mov x2, {arg2}",
                "mov x3, {arg3}",
                "mov x4, xzr",
                "mov x5, xzr",
                "mov x6, xzr",
                "mov x7, xzr",
                "mov x29, xzr",
                "mov x30, xzr",
                "br {entry}",
                sp = in(reg) sp,
                arg0 = in(reg) x0,
                arg1 = in(reg) x1,
                arg2 = in(reg) x2,
                arg3 = in(reg) x3,
                entry = in(reg) entry,
                options(noreturn),
            );
        }
    }
}

/// Calls a guest function at `entry` and returns its `x0` to the host.
///
/// Uses a real `blr` so a guest `ret` resumes the host. Guest may take Darwin
/// syscalls via the trap backend (must be installed first if needed). Guest
/// `exit` still terminates the process.
///
/// `arg0` is placed in guest `x0` (remaining argument registers are zeroed).
///
/// # Safety
///
/// Caller must guarantee:
/// - `entry` points at executable mapped guest code that returns with `ret`
///   (or never returns via `exit` / fatal trap);
/// - `sp` is a valid 16-byte-aligned guest stack;
/// - trap handlers are installed if the callee may issue syscalls;
/// - the guest does not unwind into host frames (standard AAPCS64 `ret` only).
pub unsafe fn call_guest(entry: u64, sp: u64, arg0: u64) -> Result<u64, EntryError> {
    // SAFETY: same invariants as [`call_guest_args`]; extra arg regs zeroed.
    unsafe { call_guest_args(entry, sp, arg0, 0, 0, 0) }
}

/// Like [`call_guest`], but sets guest `x0`–`x3` (Darwin `main` / AAPCS64).
///
/// Used for `LC_MAIN` so `return` from `main` resumes the host with the status
/// in `x0` (dyld then calls `exit`; we do the same via
/// [`crate::trap::finish_with_exit_code`]).
///
/// # Safety
///
/// Same as [`call_guest`].
pub unsafe fn call_guest_args(
    entry: u64,
    sp: u64,
    x0: u64,
    x1: u64,
    x2: u64,
    x3: u64,
) -> Result<u64, EntryError> {
    if entry == 0 {
        return Err(EntryError::InvalidEntry(entry));
    }
    if !sp.is_multiple_of(16) {
        return Err(EntryError::MisalignedStack(sp));
    }

    #[cfg(not(target_arch = "aarch64"))]
    {
        let _ = (entry, sp, x0, x1, x2, x3);
        return Err(EntryError::UnsupportedArch);
    }

    #[cfg(target_arch = "aarch64")]
    {
        let mut ret: u64;
        // Host SP lives in a callee-saved reg chosen by LLVM (`inout`), which
        // AAPCS64 guests must preserve across `blr`/`ret`.
        let mut host_sp: u64 = 0;
        // SAFETY: caller invariants above. Volatile regs are listed as outs so
        // Rust does not assume they survive the guest call.
        unsafe {
            std::arch::asm!(
                "mov {host_sp}, sp",
                "mov sp, {guest_sp}",
                "mov x0, {arg0}",
                "mov x1, {arg1}",
                "mov x2, {arg2}",
                "mov x3, {arg3}",
                "mov x4, xzr",
                "mov x5, xzr",
                "mov x6, xzr",
                "mov x7, xzr",
                "blr {entry}",
                "mov sp, {host_sp}",
                host_sp = inout(reg) host_sp,
                guest_sp = in(reg) sp,
                arg0 = in(reg) x0,
                arg1 = in(reg) x1,
                arg2 = in(reg) x2,
                arg3 = in(reg) x3,
                entry = in(reg) entry,
                lateout("x0") ret,
                out("x1") _,
                out("x2") _,
                out("x3") _,
                out("x4") _,
                out("x5") _,
                out("x6") _,
                out("x7") _,
                out("x8") _,
                out("x9") _,
                out("x10") _,
                out("x11") _,
                out("x12") _,
                out("x13") _,
                out("x14") _,
                out("x15") _,
                out("x16") _,
                out("x17") _,
                out("x30") _,
            );
        }
        let _ = host_sp;
        Ok(ret)
    }
}
