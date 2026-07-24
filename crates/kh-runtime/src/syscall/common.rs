//! Shared syscall types, errno, and guest-memory helpers.
//!
//! Guest VA ↔ host pointer helpers assume the identity map model. Callers must
//! validate ranges with the active address space before reading or writing.

use crate::trap::TrapOutcome;

/// Darwin `errno` values we surface.
pub const EPERM: i64 = 1;
pub const ENOENT: i64 = 2;
pub const EBADF: i64 = 9;
pub const EFAULT: i64 = 14;
pub const EINVAL: i64 = 22;
pub const ENOSYS: i64 = 78;
pub const ENOMEM: i64 = 12;

/// Arguments for one BSD syscall (AArch64 Darwin convention).
#[derive(Debug, Clone, Copy)]
pub struct SyscallArgs {
    /// Guest PC of the trap instruction.
    pub pc: u64,
    /// Syscall number (`x16`).
    pub number: u32,
    /// `x0` … `x5` argument registers.
    pub x0: u64,
    pub x1: u64,
    pub x2: u64,
    pub x3: u64,
    pub x4: u64,
    pub x5: u64,
}

/// Result of dispatching one syscall.
#[derive(Debug, Clone)]
pub struct SyscallResult {
    /// Stable short name for traces.
    pub name: &'static str,
    /// Whether to exit the process or continue the guest.
    pub outcome: TrapOutcome,
    /// Value to write back into `x0`. `None` keeps `x0` (e.g. `exit`).
    pub retval: Option<u64>,
    /// When true, trap sets `PSTATE.C` and `retval` is a positive errno.
    pub error: bool,
}

impl SyscallResult {
    /// Successful return: clear carry, `x0 = value`.
    #[must_use]
    pub const fn ok(name: &'static str, value: u64) -> Self {
        Self {
            name,
            outcome: TrapOutcome::Continue,
            retval: Some(value),
            error: false,
        }
    }

    /// Error return: set carry, `x0 = positive errno`.
    #[must_use]
    pub const fn err(name: &'static str, errno: i64) -> Self {
        Self {
            name,
            outcome: TrapOutcome::Continue,
            retval: Some(errno.unsigned_abs()),
            error: true,
        }
    }

    /// Guest process exit (no register write-back required).
    #[must_use]
    pub const fn exit(code: i32) -> Self {
        Self {
            name: "exit",
            outcome: TrapOutcome::Exit { code },
            retval: None,
            error: false,
        }
    }
}

/// Low 8 bits as process exit status.
#[must_use]
pub(crate) fn exit_status(x0: u64) -> i32 {
    i32::try_from(x0 & 0xFF).unwrap_or(0)
}

/// Low 32 bits of a register as signed i32 (two's complement).
#[must_use]
pub(crate) fn reg_as_i32(x: u64) -> i32 {
    let lo = u32::try_from(x & 0xFFFF_FFFF).unwrap_or(0);
    i32::from_ne_bytes(lo.to_ne_bytes())
}

/// Full 64-bit register as signed i64.
#[must_use]
pub(crate) fn reg_as_i64(x: u64) -> i64 {
    i64::from_ne_bytes(x.to_ne_bytes())
}

/// Identity-map guest pointer → host `*const u8`.
#[must_use]
pub(crate) fn guest_ptr(addr: u64) -> *const u8 {
    let u = usize::try_from(addr).unwrap_or(0);
    std::ptr::with_exposed_provenance(u)
}

/// Identity-map guest pointer → host `*mut u8`.
#[must_use]
pub(crate) fn guest_ptr_mut(addr: u64) -> *mut u8 {
    let u = usize::try_from(addr).unwrap_or(0);
    std::ptr::with_exposed_provenance_mut(u)
}

/// Immutable view of `len` guest bytes (identity map).
///
/// # Safety contract
/// Caller must have validated `[addr, addr+len)` as readable guest memory.
#[must_use]
#[allow(unsafe_code)]
pub(crate) fn guest_slice<'a>(addr: u64, len: usize) -> &'a [u8] {
    if len == 0 {
        return &[];
    }
    // SAFETY: caller validated the range; identity map ⇒ guest VA is host VA.
    unsafe { std::slice::from_raw_parts(guest_ptr(addr), len) }
}

/// Mutable view of `len` guest bytes (identity map).
///
/// # Safety contract
/// Caller must have validated `[addr, addr+len)` as writable guest memory.
#[must_use]
#[allow(unsafe_code)]
pub(crate) fn guest_slice_mut<'a>(addr: u64, len: usize) -> &'a mut [u8] {
    if len == 0 {
        return &mut [];
    }
    // SAFETY: caller validated the range; identity map ⇒ guest VA is host VA.
    unsafe { std::slice::from_raw_parts_mut(guest_ptr_mut(addr), len) }
}

/// Write bytes into guest memory (identity map).
///
/// # Safety contract
/// Caller must have validated `[addr, addr+data.len())` as writable guest memory.
pub(crate) fn guest_write(addr: u64, data: &[u8]) {
    guest_slice_mut(addr, data.len()).copy_from_slice(data);
}

/// Read a little-endian `u32` from guest memory.
#[must_use]
pub(crate) fn guest_read_u32(addr: u64) -> u32 {
    let mut le = [0_u8; 4];
    le.copy_from_slice(guest_slice(addr, 4));
    u32::from_le_bytes(le)
}

/// Write a little-endian `u32` into guest memory.
pub(crate) fn guest_write_u32(addr: u64, value: u32) {
    guest_write(addr, &value.to_le_bytes());
}

/// Read a little-endian `u64` from guest memory.
#[must_use]
pub(crate) fn guest_read_u64(addr: u64) -> u64 {
    let mut le = [0_u8; 8];
    le.copy_from_slice(guest_slice(addr, 8));
    u64::from_le_bytes(le)
}

/// Read a little-endian `i32` from guest memory.
#[must_use]
pub(crate) fn guest_read_i32(addr: u64) -> i32 {
    i32::from_ne_bytes(guest_read_u32(addr).to_ne_bytes())
}
