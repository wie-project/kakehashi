//! Darwin arm64 syscall entry (`svc #0x80`, number in `x16`).

use core::sync::atomic::{AtomicBool, Ordering};

/// BSD `exit`.
pub(crate) const SYS_EXIT: u32 = 1;
/// BSD `read`.
pub(crate) const SYS_READ: u32 = 3;
/// BSD `write`.
pub(crate) const SYS_WRITE: u32 = 4;
/// BSD `open`.
pub(crate) const SYS_OPEN: u32 = 5;
/// BSD `close`.
pub(crate) const SYS_CLOSE: u32 = 6;
/// BSD `unlink`.
pub(crate) const SYS_UNLINK: u32 = 10;
/// BSD `getpid`.
pub(crate) const SYS_GETPID: u32 = 20;
/// BSD `getppid`.
pub(crate) const SYS_GETPPID: u32 = 39;
/// BSD `munmap`.
pub(crate) const SYS_MUNMAP: u32 = 73;
/// BSD `fsync`.
pub(crate) const SYS_FSYNC: u32 = 95;
/// BSD `gettimeofday`.
pub(crate) const SYS_GETTIMEOFDAY: u32 = 116;
/// BSD `rename`.
pub(crate) const SYS_RENAME: u32 = 128;
/// BSD `mkdir`.
pub(crate) const SYS_MKDIR: u32 = 136;
/// BSD `rmdir`.
pub(crate) const SYS_RMDIR: u32 = 137;
/// BSD `mmap`.
pub(crate) const SYS_MMAP: u32 = 197;
/// BSD `lseek`.
pub(crate) const SYS_LSEEK: u32 = 199;
/// BSD `ftruncate`.
pub(crate) const SYS_FTRUNCATE: u32 = 201;
/// BSD `sysctl`.
pub(crate) const SYS_SYSCTL: u32 = 202;
/// BSD `sysctlbyname`.
pub(crate) const SYS_SYSCTLBYNAME: u32 = 274;
/// BSD `stat64`.
pub(crate) const SYS_STAT64: u32 = 338;
/// BSD `fstat64`.
pub(crate) const SYS_FSTAT64: u32 = 339;
/// BSD `lstat64`.
pub(crate) const SYS_LSTAT64: u32 = 340;
/// BSD `bsdthread_create`.
pub(crate) const SYS_BSDTHREAD_CREATE: u32 = 360;
/// BSD `bsdthread_terminate`.
pub(crate) const SYS_BSDTHREAD_TERMINATE: u32 = 361;
/// BSD `bsdthread_register`.
pub(crate) const SYS_BSDTHREAD_REGISTER: u32 = 366;
/// BSD `fstatat` / `fstatat64`.
pub(crate) const SYS_FSTATAT: u32 = 470;
/// BSD `openat`.
pub(crate) const SYS_OPENAT: u32 = 463;

/// Invokes a Darwin BSD syscall with zero arguments.
///
/// # Safety
///
/// Valid Darwin call for the guest (or translated by `kh-runtime`).
#[inline]
pub(crate) unsafe fn syscall0(number: u32) -> isize {
    unsafe { syscall6(number, 0, 0, 0, 0, 0, 0) }
}

/// Invokes a Darwin BSD syscall with one argument.
///
/// # Safety
///
/// Valid Darwin call for the guest (or translated by `kh-runtime`).
#[inline]
pub(crate) unsafe fn syscall1(number: u32, a0: u64) -> isize {
    unsafe { syscall6(number, a0, 0, 0, 0, 0, 0) }
}

/// Invokes a Darwin BSD syscall with two arguments.
///
/// # Safety
///
/// Valid Darwin call for the guest (or translated by `kh-runtime`).
#[inline]
pub(crate) unsafe fn syscall2(number: u32, a0: u64, a1: u64) -> isize {
    unsafe { syscall6(number, a0, a1, 0, 0, 0, 0) }
}

/// Invokes a Darwin BSD syscall with up to three arguments.
///
/// Success → non-negative `isize` (raw `x0`). Error → negative errno (Darwin
/// carry + positive errno in `x0` mapped to `-errno`).
///
/// # Safety
///
/// Valid Darwin call for the guest (or translated by `kh-runtime`).
#[inline]
pub(crate) unsafe fn syscall3(number: u32, a0: u64, a1: u64, a2: u64) -> isize {
    unsafe { syscall6(number, a0, a1, a2, 0, 0, 0) }
}

/// Invokes a Darwin BSD syscall with up to six arguments.
///
/// # Safety
///
/// Valid Darwin call for the guest (or translated by `kh-runtime`).
#[inline]
pub(crate) unsafe fn syscall6(
    number: u32,
    a0: u64,
    a1: u64,
    a2: u64,
    a3: u64,
    a4: u64,
    a5: u64,
) -> isize {
    // SAFETY: forwarded with x6=0.
    unsafe { syscall7(number, a0, a1, a2, a3, a4, a5, 0) }
}

/// Return of the Kakehashi BSD hypercall (matches `kh_trampoline_dispatch`).
#[repr(C)]
struct HyperRet {
    retval: u64,
    error: u64,
}

/// Optional direct hypercall into the host translator (identity-mapped).
///
/// The runtime writes the address of `kh_trampoline_dispatch` here after
/// mapping freestanding `libSystem`. When zero (real Darwin / unset), fall
/// back to `svc #0x80`.
///
/// Exported as `_kh_bsd_hypercall` (Darwin nlist) for the loader to patch.
///
/// Use bare `kh_bsd_hypercall` so the Darwin toolchain adds a single `_`.
#[unsafe(export_name = "kh_bsd_hypercall")]
#[allow(dead_code)] // written by host loader via export name
static mut KH_BSD_HYPERCALL: usize = 0;

/// Set when any guest worker has been spawned (`pthread_create` / bsdthread).
///
/// Hypercall is ST-fast but still races under 7zz `-mmt>1` NEON workers even
/// with full Q-reg save (host runs on the guest stack; intermittent SEGV with
/// no fault frame). After the first worker, fall back to patched `svc`→`brk`
/// which is green under MT. Single-thread guests keep the hypercall path.
static WORKERS_SPAWNED: AtomicBool = AtomicBool::new(false);

/// Mark that multi-thread guests are live (disables freestanding hypercall).
#[inline]
pub(crate) fn note_worker_spawned() {
    WORKERS_SPAWNED.store(true, Ordering::Release);
}

/// Invokes a Darwin BSD syscall with up to seven arguments (`x0`–`x6`).
///
/// # Safety
///
/// Valid Darwin call for the guest (or translated by `kh-runtime`).
#[inline]
#[allow(clippy::too_many_arguments)] // Darwin register ABI: x0–x6 + number
pub(crate) unsafe fn syscall7(
    number: u32,
    a0: u64,
    a1: u64,
    a2: u64,
    a3: u64,
    a4: u64,
    a5: u64,
    a6: u64,
) -> isize {
    #[cfg(target_arch = "aarch64")]
    {
        // Prefer host hypercall when wired and still single-threaded.
        // SAFETY: slot is process-local; runtime writes once before guest entry.
        let hyper = unsafe { core::ptr::addr_of!(KH_BSD_HYPERCALL).read_volatile() };
        if hyper != 0 && !WORKERS_SPAWNED.load(Ordering::Acquire) {
            // Darwin `svc` preserves full SIMD. Host Rust does not. Save
            // Q0–Q31 + FPCR/FPSR around the call (same as host veneer tramp).
            let r = unsafe {
                hypercall_preserve_neon(hyper, a0, a1, a2, a3, a4, a5, a6, u64::from(number))
            };
            if r.error != 0 {
                let err = isize::try_from(r.retval).unwrap_or(1);
                if err > 0 {
                    return err.saturating_neg();
                }
                return -1;
            }
            return if let Ok(v) = i64::try_from(r.retval) {
                isize::try_from(v).unwrap_or(-1)
            } else {
                -1
            };
        }

        let mut ret: u64;
        let mut flags: u64;
        // SAFETY: pure register syscall (real Darwin / unpatched path).
        unsafe {
            core::arch::asm!(
                "svc #0x80",
                "mrs {flags}, nzcv",
                in("x16") u64::from(number),
                inout("x0") a0 => ret,
                in("x1") a1,
                in("x2") a2,
                in("x3") a3,
                in("x4") a4,
                in("x5") a5,
                in("x6") a6,
                flags = out(reg) flags,
                options(nostack),
            );
        }
        let carry = (flags & (1_u64 << 29)) != 0;
        if carry {
            let err = isize::try_from(ret).unwrap_or(1);
            if err > 0 {
                err.saturating_neg()
            } else {
                -1
            }
        } else if let Ok(v) = i64::try_from(ret) {
            isize::try_from(v).unwrap_or(-1)
        } else {
            -1
        }
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        let _ = (number, a0, a1, a2, a3, a4, a5, a6);
        -1
    }
}

/// Call host hyper entry with full NEON preserved (Darwin `svc` contract).
///
/// `hyper` is the absolute address of the host shim / dispatcher. Args use the
/// AAPCS64 8-arg layout (`x0`–`x6` + number in `x7`); the host NEON shim maps
/// that to Darwin `x16` before dispatch.
#[cfg(target_arch = "aarch64")]
#[inline(never)]
#[allow(clippy::too_many_arguments)]
unsafe fn hypercall_preserve_neon(
    hyper: usize,
    a0: u64,
    a1: u64,
    a2: u64,
    a3: u64,
    a4: u64,
    a5: u64,
    a6: u64,
    number: u64,
) -> HyperRet {
    let mut retval: u64;
    let mut error: u64;
    // Frame: 0x280 bytes — matches host TRAMP_BYTES layout (Q0–Q31 + FPCR/FPSR + temps).
    // SAFETY: pure register/stack traffic; `hyper` is identity-mapped host code.
    // Stash `hyper` at [sp,#88] before reusing x8/x9 for FPCR/FPSR — a plain
    // `in(reg)` could land in x8 and be clobbered by `mrs x8, fpcr`.
    unsafe {
        core::arch::asm!(
            "sub sp, sp, #0x280",
            "str {hyper}, [sp, #88]",
            "stp x8, x9, [sp, #0]",
            "stp x10, x11, [sp, #16]",
            "stp x12, x13, [sp, #32]",
            "stp x14, x15, [sp, #48]",
            "stp x17, x18, [sp, #64]",
            "str x30, [sp, #80]",
            "mrs x8, fpcr",
            "mrs x9, fpsr",
            "stp x8, x9, [sp, #96]",
            "stp q0, q1, [sp, #112]",
            "stp q2, q3, [sp, #144]",
            "stp q4, q5, [sp, #176]",
            "stp q6, q7, [sp, #208]",
            "stp q8, q9, [sp, #240]",
            "stp q10, q11, [sp, #272]",
            "stp q12, q13, [sp, #304]",
            "stp q14, q15, [sp, #336]",
            "stp q16, q17, [sp, #368]",
            "stp q18, q19, [sp, #400]",
            "stp q20, q21, [sp, #432]",
            "stp q22, q23, [sp, #464]",
            "stp q24, q25, [sp, #496]",
            "stp q26, q27, [sp, #528]",
            "stp q28, q29, [sp, #560]",
            "stp q30, q31, [sp, #592]",
            "ldr x8, [sp, #88]",
            "blr x8",
            "ldp x8, x9, [sp, #96]",
            "msr fpcr, x8",
            "msr fpsr, x9",
            "ldp q0, q1, [sp, #112]",
            "ldp q2, q3, [sp, #144]",
            "ldp q4, q5, [sp, #176]",
            "ldp q6, q7, [sp, #208]",
            "ldp q8, q9, [sp, #240]",
            "ldp q10, q11, [sp, #272]",
            "ldp q12, q13, [sp, #304]",
            "ldp q14, q15, [sp, #336]",
            "ldp q16, q17, [sp, #368]",
            "ldp q18, q19, [sp, #400]",
            "ldp q20, q21, [sp, #432]",
            "ldp q22, q23, [sp, #464]",
            "ldp q24, q25, [sp, #496]",
            "ldp q26, q27, [sp, #528]",
            "ldp q28, q29, [sp, #560]",
            "ldp q30, q31, [sp, #592]",
            "ldr x30, [sp, #80]",
            "ldp x17, x18, [sp, #64]",
            "ldp x14, x15, [sp, #48]",
            "ldp x12, x13, [sp, #32]",
            "ldp x10, x11, [sp, #16]",
            "ldp x8, x9, [sp, #0]",
            "add sp, sp, #0x280",
            inout("x0") a0 => retval,
            inout("x1") a1 => error,
            in("x2") a2,
            in("x3") a3,
            in("x4") a4,
            in("x5") a5,
            in("x6") a6,
            in("x7") number,
            hyper = in(reg) hyper,
            // Preserve AAPCS callee-saved; do not let the compiler reuse our
            // stack frame mid-sequence.
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
            // x18 is Darwin-reserved (cannot name in constraints); save/restore above.
        );
    }
    HyperRet { retval, error }
}

/// Host-helper call (`x16` in the `0x4B48_xxxx` range).
///
/// # Safety
///
/// Helper id must match `kh-runtime`.
#[inline]
pub(crate) unsafe fn helper1(number: u32, a0: u64) -> isize {
    // SAFETY: forwarded to syscall3.
    unsafe { syscall3(number, a0, 0, 0) }
}

/// Host helper with two arguments.
///
/// # Safety
///
/// Helper id must match `kh-runtime`.
#[inline]
pub(crate) unsafe fn helper2(number: u32, a0: u64, a1: u64) -> isize {
    // SAFETY: forwarded to syscall3.
    unsafe { syscall3(number, a0, a1, 0) }
}

/// Host helper with three arguments.
///
/// # Safety
///
/// Helper id must match `kh-runtime`.
#[inline]
pub(crate) unsafe fn helper3(number: u32, a0: u64, a1: u64, a2: u64) -> isize {
    // SAFETY: forwarded to syscall3.
    unsafe { syscall3(number, a0, a1, a2) }
}

/// Host helper with zero arguments.
///
/// # Safety
///
/// Helper id must match `kh-runtime`.
#[inline]
pub(crate) unsafe fn helper0(number: u32) -> isize {
    // SAFETY: forwarded to syscall0.
    unsafe { syscall0(number) }
}
