//! Darwin arm64 syscall entry (`svc #0x80`, number in `x16`).

use core::sync::atomic::{AtomicUsize, Ordering};

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

/// Host writes 1 when worker hypercall is enabled (`KAKEHASHI_HYPERCALL_WORKERS=1`).
///
/// Default 0: only the LC_MAIN stack uses freestanding hypercall; workers keep
/// `svc`→`brk` (NEON MT compression is green there). When non-zero, every thread
/// uses hypercall (experimental — may SEGV under 7zz `-mmt>1 -mx>0`).
#[unsafe(export_name = "kh_hypercall_workers")]
#[allow(dead_code)] // written by host loader / runtime
static mut KH_HYPERCALL_WORKERS: u32 = 0;

/// SP bucket of the first syscall (LC_MAIN). Worker stacks are separate mmaps.
static MAIN_STACK_SP: AtomicUsize = AtomicUsize::new(0);

/// 4 MiB bucket (matches guest worker `STACK_SIZE`).
const STACK_BUCKET: usize = 4 * 1024 * 1024;

/// True when current SP is the main guest stack (or worker hypercall is on).
#[cfg(target_arch = "aarch64")]
#[inline]
fn hypercall_allowed_here() -> bool {
    // SAFETY: host writes once before / at guest entry; workers only read.
    let workers = unsafe { core::ptr::addr_of!(KH_HYPERCALL_WORKERS).read_volatile() };
    if workers != 0 {
        return true;
    }
    let sp = read_sp();
    let bucket = sp & !(STACK_BUCKET.saturating_sub(1));
    match MAIN_STACK_SP.compare_exchange(0, bucket, Ordering::AcqRel, Ordering::Acquire) {
        Ok(_) => true,
        Err(main_bucket) => bucket == main_bucket,
    }
}

#[cfg(target_arch = "aarch64")]
#[inline]
fn read_sp() -> usize {
    let sp: u64;
    // SAFETY: pure register read.
    unsafe {
        core::arch::asm!("mov {}, sp", out(reg) sp, options(nomem, nostack, preserves_flags));
    }
    usize::try_from(sp).unwrap_or(0)
}

/// Invokes a Darwin BSD syscall with up to seven arguments (`x0`–`x6`).
///
/// When the host has wired [`KH_BSD_HYPERCALL`]:
/// - **Main** stack always uses freestanding hypercall (fast I/O).
/// - **Workers** use hypercall only if [`KH_HYPERCALL_WORKERS`] ≠ 0; otherwise
///   `svc`→`brk` (safe for 7zz MT NEON compression).
///
/// Join completion is published from the host stack after `bsdthread_terminate`
/// (see `kh-runtime::thread`).
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
        // Prefer host hypercall when wired and allowed on this stack.
        // SAFETY: slot is process-local; runtime writes once before guest entry.
        let hyper = unsafe { core::ptr::addr_of!(KH_BSD_HYPERCALL).read_volatile() };
        if hyper != 0 && hypercall_allowed_here() {
            let r = unsafe {
                hypercall_thin(hyper, a0, a1, a2, a3, a4, a5, a6, u64::from(number))
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

/// Thin call into the host hyper entry (NEON preserved by the host tramp).
///
/// Args use AAPCS64 (`x0`–`x6` + number in `x7`). The host entry switches to a
/// host alt stack and runs TRAMP_BYTES (full Q0–Q31 + FPCR/FPSR).
#[cfg(target_arch = "aarch64")]
#[inline(never)]
#[allow(clippy::too_many_arguments)]
unsafe fn hypercall_thin(
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
    // SAFETY: `hyper` is identity-mapped host code; host preserves NEON.
    // Save x18 (Darwin-reserved) across the Linux AAPCS call.
    unsafe {
        core::arch::asm!(
            "str x18, [sp, #-16]!",
            "blr {hyper}",
            "ldr x18, [sp], #16",
            inout("x0") a0 => retval,
            inout("x1") a1 => error,
            in("x2") a2,
            in("x3") a3,
            in("x4") a4,
            in("x5") a5,
            in("x6") a6,
            in("x7") number,
            hyper = in(reg) hyper,
            // Caller-saved GPRs may be clobbered by the host entry.
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
            // NEON: host tramp restores full Q0–Q31; mark clobbered so LLVM
            // does not keep live values across the call without its own save.
            out("v0") _,
            out("v1") _,
            out("v2") _,
            out("v3") _,
            out("v4") _,
            out("v5") _,
            out("v6") _,
            out("v7") _,
            out("v8") _,
            out("v9") _,
            out("v10") _,
            out("v11") _,
            out("v12") _,
            out("v13") _,
            out("v14") _,
            out("v15") _,
            out("v16") _,
            out("v17") _,
            out("v18") _,
            out("v19") _,
            out("v20") _,
            out("v21") _,
            out("v22") _,
            out("v23") _,
            out("v24") _,
            out("v25") _,
            out("v26") _,
            out("v27") _,
            out("v28") _,
            out("v29") _,
            out("v30") _,
            out("v31") _,
            clobber_abi("C"),
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
