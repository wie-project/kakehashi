//! Darwin arm64 syscall entry (`svc #0x80`, number in `x16`).

/// BSD `exit`.
pub(crate) const SYS_EXIT: u32 = 1;
/// BSD `write`.
pub(crate) const SYS_WRITE: u32 = 4;

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
                flags = out(reg) flags,
                options(nostack),
            );
        }
        let carry = (flags & (1_u64 << 29)) != 0;
        if carry {
            let err = isize::try_from(ret).unwrap_or(1);
            if err > 0 { -err } else { -1 }
        } else if let Ok(v) = i64::try_from(ret) {
            isize::try_from(v).unwrap_or(-1)
        } else {
            -1
        }
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        let _ = (number, a0, a1, a2);
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
