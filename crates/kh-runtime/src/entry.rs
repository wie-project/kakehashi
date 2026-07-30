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
/// (e.g. Darwin `svc` rewritten as `brk`) which terminates the process.
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
        // Guest TPIDR only for guest code (see `install_main_guest_tls`).
        let guest = crate::tls::guest_tpidr();
        if guest != 0 {
            crate::tls::enter_guest_tls(guest);
        }
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
        // Host SP must survive the guest call. `clobber_abi("C")` tells LLVM
        // that `blr` is a full C call, so live values (including host SP) are
        // kept only in callee-saved regs — never in x18. That matters because
        // freestanding hypercalls run host Rust under **Linux** AAPCS64 (x18
        // is scratch) while Darwin guests treat x18 as reserved; parking host
        // SP in x18 then produced `SIGBUS BUS_ADRALN` at `si_addr=0x1` after
        // guest `main` returned under `KAKEHASHI_HYPERCALL`.
        let mut host_sp: u64 = 0;
        // Guest TPIDR only around guest code; restore host before returning to
        // Rust (constructors / `main` return path use host TLS for logging etc.).
        let guest = crate::tls::guest_tpidr();
        if guest != 0 {
            crate::tls::enter_guest_tls(guest);
        }
        // SAFETY: caller invariants above. `clobber_abi("C")` clobbers x0–x18 /
        // x30; host SP and ret live in explicit callee-saved regs. x19 is
        // reserved by LLVM on aarch64 and cannot be an asm operand.
        unsafe {
            std::arch::asm!(
                "mov x20, sp",
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
                "mov x21, x0",
                "mov sp, x20",
                guest_sp = in(reg) sp,
                arg0 = in(reg) x0,
                arg1 = in(reg) x1,
                arg2 = in(reg) x2,
                arg3 = in(reg) x3,
                entry = in(reg) entry,
                inout("x20") host_sp,
                lateout("x21") ret,
                clobber_abi("C"),
            );
        }
        crate::tls::enter_host_tls();
        let _ = host_sp;
        Ok(ret)
    }
}
