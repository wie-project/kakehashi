//! Darwin arm64 syscall entry (`svc #0x80`, number in `x16`).

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
/// BSD `getpid`.
pub(crate) const SYS_GETPID: u32 = 20;
/// BSD `getppid`.
pub(crate) const SYS_GETPPID: u32 = 39;
/// BSD `gettimeofday`.
pub(crate) const SYS_GETTIMEOFDAY: u32 = 116;
/// BSD `lseek`.
pub(crate) const SYS_LSEEK: u32 = 199;
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
    #[cfg(target_arch = "aarch64")]
    {
        let mut ret: u64;
        let mut flags: u64;
        // SAFETY: pure register syscall.
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
        let _ = (number, a0, a1, a2, a3, a4, a5);
        -1
    }
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
