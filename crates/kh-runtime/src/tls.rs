//! Guest↔host TLS boundary: `TPIDR_EL0` + per-thread host snapshot.
//!
//! On Linux aarch64, host glibc and Darwin guest both use `TPIDR_EL0`. While
//! guest code runs the register points at a freestanding [`GUEST_TLS_MAGIC`]
//! block; every host entry (hypercall / SIGTRAP) restores the host value saved
//! at thread prepare time.
//!
//! **Host snapshots live in [`crate::host_slot`]**, not `thread_local!`, so they
//! remain reachable when `TPIDR_EL0` already points at guest TSD.
//!
//! Layout of the guest block (must match `kh-libsystem`):
//! ```text
//! offset 0:  magic: u64   == GUEST_TLS_MAGIC
//! offset 8:  errno: i32
//! offset 12: pad
//! offset 16: pthread_self: u64  (guest pthread_t VA, optional)
//! ```
#![allow(unsafe_code)]

use std::sync::atomic::{AtomicU64, Ordering};

use crate::cpu;
use crate::host_slot;

/// Freestanding guest TLS magic (`"KHTLS\x01"`).
pub const GUEST_TLS_MAGIC: u64 = 0x4B48_544C_5301;
/// Size of the guest TLS control block (one page is fine; we use 64 B).
pub const GUEST_TLS_SIZE: usize = 64;
/// Offset of the `errno` cell inside the guest TLS block.
pub const GUEST_TLS_ERRNO_OFF: usize = 8;
/// Offset of `pthread_self` pointer storage.
pub const GUEST_TLS_PTHREAD_OFF: usize = 16;

/// Process-wide main guest TLS VA (for diagnostics / tests).
static MAIN_GUEST_TLS: AtomicU64 = AtomicU64::new(0);

/// Captures the current (host) `TPIDR_EL0` into this thread's host slot.
///
/// Must run on every host thread **before** guest code may `msr tpidr_el0`.
pub fn prepare_host_meta() {
    let host = cpu::read_tpidr_el0();
    // May allocate map entry — must run with host TPIDR live.
    host_slot::with_tls_init(|m| {
        m.host_tpidr = host;
        m.active = true;
    });
}

/// Installs a guest TLS block for the **main** thread and switches `TPIDR_EL0`.
///
/// Returns the guest TLS VA, or `0` on allocation failure / non-Linux aarch64.
#[must_use]
pub fn install_main_guest_tls() -> u64 {
    prepare_host_meta();
    // Hypercall alt stack for the main thread while host TPIDR is live.
    let _ = crate::thread::ensure_host_alt_stack();
    #[cfg(all(target_arch = "aarch64", target_os = "linux"))]
    {
        let Some(base) = map_guest_tls_page() else {
            return 0;
        };
        init_guest_tls_block(base, 0);
        let va = crate::host::ptr_addr_u64(base);
        MAIN_GUEST_TLS.store(va, Ordering::Release);
        enter_guest_tls(va);
        va
    }
    #[cfg(not(all(target_arch = "aarch64", target_os = "linux")))]
    {
        0
    }
}

/// Switches `TPIDR_EL0` to `guest_tpidr` and records it in the host slot.
///
/// `guest_tpidr` must point at a live guest TLS block (or 0 to skip). Host
/// meta must already be prepared so host TPIDR can be restored later.
pub fn enter_guest_tls(guest_tpidr: u64) {
    if guest_tpidr == 0 {
        return;
    }
    // Still on host TPIDR here — ensure slot exists, then msr guest.
    host_slot::with_tls_init(|m| {
        if !m.active {
            m.host_tpidr = cpu::read_tpidr_el0();
            m.active = true;
        }
        m.guest_tpidr = guest_tpidr;
    });
    // SAFETY: caller / freestanding layout owns this block for the thread life.
    unsafe {
        cpu::write_tpidr_el0(guest_tpidr);
    }
}

/// Hypercall / trap entry: leave guest TLS, restore host glibc TLS.
///
/// # Safety
///
/// Must be paired with [`kh_tls_leave_host`] (or process exit) before returning
/// to guest code. Safe to call when already on host TLS (idempotent).
/// Does **not** use Rust `thread_local!` (may run under guest `TPIDR_EL0`).
#[cfg(all(target_arch = "aarch64", target_os = "linux"))]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kh_tls_enter_host() {
    enter_host_tls_inner();
}

/// Hypercall / trap leave: restore guest `TPIDR_EL0`.
///
/// # Safety
///
/// Guest TLS block must still be mapped (thread not torn down).
#[cfg(all(target_arch = "aarch64", target_os = "linux"))]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kh_tls_leave_host() {
    leave_host_tls_inner();
}

/// # Safety
///
/// Stub on non-Linux aarch64; no-op.
#[cfg(not(all(target_arch = "aarch64", target_os = "linux")))]
#[allow(dead_code)]
pub unsafe extern "C" fn kh_tls_enter_host() {}

/// # Safety
///
/// Stub on non-Linux aarch64; no-op.
#[cfg(not(all(target_arch = "aarch64", target_os = "linux")))]
#[allow(dead_code)]
pub unsafe extern "C" fn kh_tls_leave_host() {}

/// Safe wrapper used from Rust trap handlers.
#[inline]
pub fn enter_host_tls() {
    enter_host_tls_inner();
}

/// Safe wrapper used from Rust trap handlers.
#[inline]
pub fn leave_host_tls() {
    leave_host_tls_inner();
}

fn enter_host_tls_inner() {
    let cur = cpu::read_tpidr_el0();
    // Existing slot only — no HashMap insert (safe under guest TPIDR).
    let host = host_slot::with_tls_existing_mut(|m| {
        if !m.active {
            // Slot present but inactive: treat current as host (best effort).
            m.host_tpidr = cur;
            m.active = true;
            return m.host_tpidr;
        }
        if cur != m.host_tpidr {
            m.guest_tpidr = cur;
        }
        m.host_tpidr
    });
    let Some(host) = host else {
        // No prepare yet — leave TPIDR alone.
        return;
    };
    if cur != host {
        // SAFETY: restoring host glibc TLS pointer captured at prepare time.
        unsafe {
            cpu::write_tpidr_el0(host);
        }
    }
}

fn leave_host_tls_inner() {
    let guest = host_slot::with_tls_existing_mut(|m| {
        if m.active {
            m.guest_tpidr
        } else {
            0
        }
    })
    .unwrap_or(0);
    if guest == 0 {
        return;
    }
    // SAFETY: guest TLS block still valid for this live guest thread.
    unsafe {
        cpu::write_tpidr_el0(guest);
    }
}

/// Restores host TLS and clears the active guest snapshot (worker exit).
pub fn clear_guest_tls_on_exit() {
    enter_host_tls_inner();
    let _ = host_slot::with_tls_existing_mut(|m| {
        m.guest_tpidr = 0;
    });
}

/// Current host TPIDR snapshot (0 if unprepared).
#[must_use]
pub fn host_tpidr() -> u64 {
    host_slot::tls_get().host_tpidr
}

/// Current guest TPIDR snapshot (0 if none).
#[must_use]
pub fn guest_tpidr() -> u64 {
    host_slot::tls_get().guest_tpidr
}

/// Main thread guest TLS VA installed by [`install_main_guest_tls`].
#[must_use]
pub fn main_guest_tls() -> u64 {
    MAIN_GUEST_TLS.load(Ordering::Acquire)
}

#[cfg(all(target_arch = "aarch64", target_os = "linux"))]
fn map_guest_tls_page() -> Option<*mut u8> {
    let len = GUEST_TLS_SIZE.max(64);
    let page = crate::host::page_size().unwrap_or(4096);
    let map_len = len.saturating_add(page.saturating_sub(1)) & !(page.saturating_sub(1));
    let flags = libc::MAP_PRIVATE | libc::MAP_ANONYMOUS;
    let prot = libc::PROT_READ | libc::PROT_WRITE;
    crate::host::mmap(None, map_len, prot, flags, -1, 0)
}

/// Writes magic + errno=0 + optional pthread into a guest TLS block.
///
/// `base` must be 16-byte aligned and at least [`GUEST_TLS_SIZE`] bytes.
pub fn init_guest_tls_block(base: *mut u8, pthread_va: u64) {
    if base.is_null() {
        return;
    }
    // SAFETY: caller-owned RW mapping ≥ GUEST_TLS_SIZE; mmap returns page-aligned.
    unsafe {
        let addr = base.addr();
        core::ptr::with_exposed_provenance_mut::<u64>(addr).write(GUEST_TLS_MAGIC);
        core::ptr::with_exposed_provenance_mut::<i32>(addr.saturating_add(GUEST_TLS_ERRNO_OFF))
            .write(0);
        core::ptr::with_exposed_provenance_mut::<u64>(addr.saturating_add(GUEST_TLS_PTHREAD_OFF))
            .write(pthread_va);
    }
}

/// True when `tpidr` looks like a freestanding guest TLS block.
#[must_use]
pub fn is_guest_tls(tpidr: u64) -> bool {
    if tpidr == 0 {
        return false;
    }
    let Ok(addr) = usize::try_from(tpidr) else {
        return false;
    };
    // SAFETY: best-effort identity-map probe; only used diagnostically.
    let magic = unsafe { core::ptr::with_exposed_provenance::<u64>(addr).read_volatile() };
    magic == GUEST_TLS_MAGIC
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prepare_captures_host() {
        prepare_host_meta();
        let h = host_tpidr();
        let _ = h;
        assert!(host_slot::tls_get().active);
    }

    #[test]
    fn enter_leave_restores_host() {
        #[cfg(target_arch = "aarch64")]
        {
            prepare_host_meta();
            let host = host_tpidr();
            let fake_guest = 0x1000_u64;
            host_slot::with_tls_init(|m| {
                m.guest_tpidr = fake_guest;
            });
            // SAFETY: TPIDR briefly non-host; host_slot is gettid-keyed so
            // enter_host_tls is safe; never assert while TPIDR is non-host.
            let after_enter = unsafe {
                cpu::write_tpidr_el0(fake_guest);
                enter_host_tls();
                cpu::read_tpidr_el0()
            };
            assert_eq!(after_enter, host);

            let after_leave = {
                leave_host_tls();
                let v = cpu::read_tpidr_el0();
                enter_host_tls();
                v
            };
            assert_eq!(after_leave, fake_guest);

            clear_guest_tls_on_exit();
            assert_eq!(cpu::read_tpidr_el0(), host);
        }
    }
}
