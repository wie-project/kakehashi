//! Thin AArch64 register helpers (TPIDR_EL0, SP).
//!
//! **Safety wall:** this is the only module that may `mrs`/`msr` `TPIDR_EL0`.
//! All guest↔host TLS switches go through [`crate::thread`] wrappers that keep
//! a per-thread host snapshot in `HostMeta`.
#![allow(unsafe_code)]

/// Reads `TPIDR_EL0` (user thread pointer; host glibc TLS / guest TSD).
///
/// # Safety
///
/// Pure register read; always safe on AArch64. Callers must treat the value as
/// either host libc TLS or guest TSD depending on the current execution realm.
#[cfg(target_arch = "aarch64")]
#[inline]
#[must_use]
pub fn read_tpidr_el0() -> u64 {
    let val: u64;
    // SAFETY: `mrs` of TPIDR_EL0 is a pure register read.
    unsafe {
        core::arch::asm!(
            "mrs {}, tpidr_el0",
            out(reg) val,
            options(nomem, nostack, preserves_flags),
        );
    }
    val
}

/// Writes `TPIDR_EL0`.
///
/// # Safety
///
/// Caller must ensure `val` is a valid pointer for the next execution realm
/// (host glibc TLS or guest TSD base). Wrong value breaks host TLS or guest
/// `___error` / TSD until restored.
#[cfg(target_arch = "aarch64")]
#[inline]
pub unsafe fn write_tpidr_el0(val: u64) {
    // SAFETY: caller guarantees `val` is the correct realm pointer.
    unsafe {
        core::arch::asm!(
            "msr tpidr_el0, {}",
            in(reg) val,
            options(nomem, nostack, preserves_flags),
        );
    }
}

/// Reads the current stack pointer.
///
/// # Safety
///
/// Pure register read.
#[cfg(target_arch = "aarch64")]
#[inline]
#[must_use]
pub fn read_sp() -> u64 {
    let sp: u64;
    // SAFETY: pure SP move.
    unsafe {
        core::arch::asm!(
            "mov {}, sp",
            out(reg) sp,
            options(nomem, nostack, preserves_flags),
        );
    }
    sp
}

#[cfg(not(target_arch = "aarch64"))]
#[inline]
#[must_use]
pub fn read_tpidr_el0() -> u64 {
    0
}

#[cfg(not(target_arch = "aarch64"))]
#[inline]
/// # Safety
///
/// No-op on non-AArch64.
pub unsafe fn write_tpidr_el0(_val: u64) {}

#[cfg(not(target_arch = "aarch64"))]
#[inline]
#[must_use]
pub fn read_sp() -> u64 {
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tpidr_roundtrip_restores() {
        #[cfg(target_arch = "aarch64")]
        {
            let original = read_tpidr_el0();
            // SAFETY: host libc TLS uses TPIDR_EL0 — never assert/format while it
            // points at a non-host value (glibc would SEGV on thread-locals).
            let seen = unsafe {
                write_tpidr_el0(0xDEAD_BEEF_CAFE_u64);
                let v = read_tpidr_el0();
                write_tpidr_el0(original);
                v
            };
            assert_eq!(seen, 0xDEAD_BEEF_CAFE_u64);
            assert_eq!(read_tpidr_el0(), original);
        }
        #[cfg(not(target_arch = "aarch64"))]
        {
            assert_eq!(read_tpidr_el0(), 0);
        }
    }
}
