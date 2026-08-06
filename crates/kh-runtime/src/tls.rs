//! Guest↔host TLS boundary: `TPIDR_EL0` + per-thread host snapshot.
//!
//! On Linux aarch64, host glibc and Darwin guest both use `TPIDR_EL0`. While
//! guest code runs the register points at a freestanding [`GUEST_TLS_MAGIC`]
//! block; every host entry (hypercall / SIGTRAP) restores the host value saved
//! at thread prepare time.
//!
//! **Host snapshots live in [`crate::host_slot`]** (gettid map) **and** are
//! mirrored into the guest TLS block (A1) so hypercall enter can restore host
//! TPIDR + alt SP **without** `gettid` / map `Mutex` / host `thread_local!`.
//!
//! Layout of the guest block (must match `kh-libsystem`):
//! ```text
//! offset 0:  magic: u64   == GUEST_TLS_MAGIC
//! offset 8:  errno: i32
//! offset 12: pad
//! offset 16: pthread_self: u64  (guest pthread_t VA, optional)
//! offset 24: host_tpidr: u64    (host-owned mirror; A1)
//! offset 32: alt_top: u64       (host-owned mirror; A1)
//! offset 40: tsd_vals: u64      (guest-owned; per-thread pthread TSD array)
//! ```
//! Host only publishes offsets 24/32; freestanding owns `tsd_vals`.
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
/// Host `TPIDR_EL0` mirror (written only by host while host TPIDR is live).
pub const GUEST_TLS_HOST_TPIDR_OFF: usize = 24;
/// Hypercall alt-stack top mirror (host-owned).
pub const GUEST_TLS_ALT_TOP_OFF: usize = 32;
/// Guest-owned per-thread `pthread` TSD array pointer (freestanding).
pub const GUEST_TLS_TSD_VALS_OFF: usize = 40;

/// Process-wide main guest TLS VA (for diagnostics / tests).
static MAIN_GUEST_TLS: AtomicU64 = AtomicU64::new(0);

/// Hypercall enter return: alt SP + guest TLS VA for leave (AAPCS64 `x0`/`x1`).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct HyperEnterRet {
    /// Host alt stack top, or 0 if unavailable.
    pub alt_top: u64,
    /// Guest `TPIDR_EL0` to restore on leave (0 if unknown).
    pub guest_tpidr: u64,
}

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

/// Allocates the main-thread guest TLS block and records it in [`host_slot`].
///
/// **Does not** leave `TPIDR_EL0` on the guest value. Host Rust / glibc / tracing
/// must keep host TPIDR until [`enter_guest_tls`] at the actual guest entry
/// (`call_guest` / `jump_to_guest`). Leaving guest TPIDR active caused immediate
/// `SIGSEGV` in host `libc` (`si_addr=0xa0`) on some Ubuntu/glibc builds when
/// any host code touched TLS (e.g. `tracing` thread-local dispatch).
///
/// Returns the guest TLS VA, or `0` on allocation failure / non-Linux aarch64.
#[must_use]
pub fn install_main_guest_tls() -> u64 {
    prepare_host_meta();
    // Hypercall alt stack for the main thread while host TPIDR is live.
    let alt = crate::thread::ensure_host_alt_stack();
    #[cfg(all(target_arch = "aarch64", target_os = "linux"))]
    {
        let Some(base) = map_guest_tls_page() else {
            return 0;
        };
        init_guest_tls_block(base, 0);
        let va = crate::host::ptr_addr_u64(base);
        MAIN_GUEST_TLS.store(va, Ordering::Release);
        let host = cpu::read_tpidr_el0();
        // Record guest TSD for the boundary; keep host TPIDR for host code.
        host_slot::with_tls_init(|m| {
            m.guest_tpidr = va;
            m.host_tpidr = host;
            m.active = true;
        });
        publish_boundary_to_guest_tls(va, host, alt);
        va
    }
    #[cfg(not(all(target_arch = "aarch64", target_os = "linux")))]
    {
        let _ = alt;
        0
    }
}

/// Switches `TPIDR_EL0` to `guest_tpidr` and records it in the host slot.
///
/// `guest_tpidr` must point at a live guest TLS block (or 0 to skip). Host
/// meta must already be prepared so host TPIDR can be restored later.
///
/// Publishes host/alt mirrors into the guest block (A1 fast enter).
pub fn enter_guest_tls(guest_tpidr: u64) {
    if guest_tpidr == 0 {
        return;
    }
    let host = cpu::read_tpidr_el0();
    let alt = host_slot::with_alt_mut(|cell| cell.map_or(0, |s| s.top));
    // Still on host TPIDR here — ensure slot exists, then msr guest.
    host_slot::with_tls_init(|m| {
        if !m.active {
            m.host_tpidr = host;
            m.active = true;
        } else if m.host_tpidr == 0 {
            m.host_tpidr = host;
        }
        m.guest_tpidr = guest_tpidr;
    });
    let host_pub = host_slot::tls_get().host_tpidr;
    publish_boundary_to_guest_tls(guest_tpidr, host_pub, alt);
    // SAFETY: caller / freestanding layout owns this block for the thread life.
    unsafe {
        cpu::write_tpidr_el0(guest_tpidr);
    }
}

/// Write host boundary fields into a freestanding guest TLS block.
///
/// **MUST** run only while host `TPIDR_EL0` is live (or with raw stores that do
/// not depend on host TLS). Safe no-op if `guest_va` is 0 / unmapped magic.
pub fn publish_boundary_to_guest_tls(guest_va: u64, host_tpidr: u64, alt_top: u64) {
    if guest_va == 0 || host_tpidr == 0 {
        return;
    }
    let Ok(addr) = usize::try_from(guest_va) else {
        return;
    };
    // SAFETY: identity-mapped guest TLS when magic matches; otherwise skip.
    let magic = unsafe { core::ptr::with_exposed_provenance::<u64>(addr).read_volatile() };
    if magic != GUEST_TLS_MAGIC {
        return;
    }
    unsafe {
        core::ptr::with_exposed_provenance_mut::<u64>(
            addr.saturating_add(GUEST_TLS_HOST_TPIDR_OFF),
        )
        .write(host_tpidr);
        core::ptr::with_exposed_provenance_mut::<u64>(addr.saturating_add(GUEST_TLS_ALT_TOP_OFF))
            .write(alt_top);
    }
}

/// Update alt_top mirror for the current thread's guest TLS (host TPIDR live).
pub fn publish_alt_top_to_current_guest(alt_top: u64) {
    let guest = host_slot::tls_get().guest_tpidr;
    let host = host_slot::tls_get().host_tpidr;
    if guest != 0 && host != 0 {
        publish_boundary_to_guest_tls(guest, host, alt_top);
    }
}

/// Hypercall entry: restore host glibc TLS; return alt top + guest VA (`x0`/`x1`).
///
/// A1: prefer guest-TLS mirror (no gettid). A2 fallback: one gettid for map.
///
/// # Safety
///
/// Must be paired with [`kh_tls_leave_host`] before returning to guest.
#[cfg(all(target_arch = "aarch64", target_os = "linux"))]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kh_tls_enter_host() -> HyperEnterRet {
    enter_host_tls_inner()
}

/// Hypercall leave: restore guest `TPIDR_EL0`.
///
/// `guest_tpidr` is the value parked by enter/asm (A1). Pass `0` to fall back
/// to the gettid-keyed host slot (SIGTRAP / failed enter).
///
/// # Safety
///
/// Guest TLS block must still be mapped when `guest_tpidr != 0`.
#[cfg(all(target_arch = "aarch64", target_os = "linux"))]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kh_tls_leave_host(guest_tpidr: u64) {
    leave_host_tls_inner(guest_tpidr);
}

/// # Safety
///
/// Stub on non-Linux aarch64.
#[cfg(not(all(target_arch = "aarch64", target_os = "linux")))]
#[allow(dead_code)]
pub unsafe extern "C" fn kh_tls_enter_host() -> HyperEnterRet {
    HyperEnterRet::default()
}

/// # Safety
///
/// Stub on non-Linux aarch64.
#[cfg(not(all(target_arch = "aarch64", target_os = "linux")))]
#[allow(dead_code)]
pub unsafe extern "C" fn kh_tls_leave_host(_guest_tpidr: u64) {}

/// Safe wrapper used from Rust trap handlers.
#[inline]
pub fn enter_host_tls() {
    let _ = enter_host_tls_inner();
}

/// Safe wrapper used from Rust trap handlers (map fallback).
#[inline]
pub fn leave_host_tls() {
    leave_host_tls_inner(0);
}

/// Try A1 fast path: guest TLS block holds host_tpidr + alt_top.
///
/// **Only** valid when `cur` is known-or-likely guest TPIDR. Rejects host glibc
/// TLS because magic will not match [`GUEST_TLS_MAGIC`].
fn try_enter_from_guest_tls(cur: u64) -> Option<(u64 /*host*/, u64 /*alt*/)> {
    if cur == 0 {
        return None;
    }
    let Ok(addr) = usize::try_from(cur) else {
        return None;
    };
    // SAFETY: identity-map probe; magic gate before other fields.
    let magic = unsafe { core::ptr::with_exposed_provenance::<u64>(addr).read_volatile() };
    if magic != GUEST_TLS_MAGIC {
        return None;
    }
    let host = unsafe {
        core::ptr::with_exposed_provenance::<u64>(addr.saturating_add(GUEST_TLS_HOST_TPIDR_OFF))
            .read_volatile()
    };
    if host == 0 || host == cur {
        // Uninitialized mirror, or nonsense (host==guest).
        return None;
    }
    let alt = unsafe {
        core::ptr::with_exposed_provenance::<u64>(addr.saturating_add(GUEST_TLS_ALT_TOP_OFF))
            .read_volatile()
    };
    Some((host, alt))
}

fn enter_host_tls_inner() -> HyperEnterRet {
    let cur = cpu::read_tpidr_el0();

    // --- A1 fast path: no gettid, no map Mutex ---
    if let Some((host, alt)) = try_enter_from_guest_tls(cur) {
        if cur != host {
            // SAFETY: restoring host glibc TLS from guest-TLS mirror.
            unsafe {
                cpu::write_tpidr_el0(host);
            }
        }
        let alt_top = if alt != 0 {
            alt
        } else {
            // Cold alt map after host TPIDR; refresh mirror for next enter.
            // (gettid only on this rare cold path via ensure_host_alt_stack.)
            let top = crate::thread::ensure_host_alt_stack();
            publish_boundary_to_guest_tls(cur, host, top);
            top
        };
        // No map/gettid on the hot path — leave uses guest_tpidr from this ret.
        return HyperEnterRet {
            alt_top,
            guest_tpidr: cur,
        };
    }

    // --- A2 slow path: gettid + map ---
    let Some(prep) = host_slot::prepare_enter_under_guest(cur) else {
        return HyperEnterRet {
            alt_top: 0,
            guest_tpidr: cur,
        };
    };
    if cur != prep.host_tpidr {
        // SAFETY: restoring host glibc TLS pointer captured at prepare time.
        unsafe {
            cpu::write_tpidr_el0(prep.host_tpidr);
        }
    }
    let alt_top = if prep.alt_top != 0 {
        prep.alt_top
    } else {
        crate::thread::ensure_host_alt_stack()
    };
    // If we were on guest TLS without mirrors, publish for next hypercall.
    if is_guest_tls(cur) {
        publish_boundary_to_guest_tls(cur, prep.host_tpidr, alt_top);
    }
    HyperEnterRet {
        alt_top,
        guest_tpidr: if is_guest_tls(cur) {
            cur
        } else {
            host_slot::tls_get().guest_tpidr
        },
    }
}

fn leave_host_tls_inner(guest_hint: u64) {
    let guest = if guest_hint != 0 {
        guest_hint
    } else {
        host_slot::with_tls_existing_mut(|m| if m.active { m.guest_tpidr } else { 0 }).unwrap_or(0)
    };
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
    let ret = enter_host_tls_inner();
    let _ = host_slot::with_tls_existing_mut(|m| {
        m.guest_tpidr = 0;
    });
    if ret.guest_tpidr != 0 {
        // Clear host mirrors so a reused block cannot fast-enter.
        publish_boundary_to_guest_tls(ret.guest_tpidr, 0, 0);
        // publish skips host==0 — force clear:
        clear_guest_tls_mirrors(ret.guest_tpidr);
    }
}

fn clear_guest_tls_mirrors(guest_va: u64) {
    let Ok(addr) = usize::try_from(guest_va) else {
        return;
    };
    let magic = unsafe { core::ptr::with_exposed_provenance::<u64>(addr).read_volatile() };
    if magic != GUEST_TLS_MAGIC {
        return;
    }
    unsafe {
        core::ptr::with_exposed_provenance_mut::<u64>(
            addr.saturating_add(GUEST_TLS_HOST_TPIDR_OFF),
        )
        .write(0);
        core::ptr::with_exposed_provenance_mut::<u64>(addr.saturating_add(GUEST_TLS_ALT_TOP_OFF))
            .write(0);
    }
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
/// Host boundary fields (`host_tpidr` / `alt_top`) start as 0 until
/// [`publish_boundary_to_guest_tls`].
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
        core::ptr::with_exposed_provenance_mut::<u64>(
            addr.saturating_add(GUEST_TLS_HOST_TPIDR_OFF),
        )
        .write(0);
        core::ptr::with_exposed_provenance_mut::<u64>(addr.saturating_add(GUEST_TLS_ALT_TOP_OFF))
            .write(0);
        // Freestanding lazily allocates the TSD array; start null.
        core::ptr::with_exposed_provenance_mut::<u64>(addr.saturating_add(GUEST_TLS_TSD_VALS_OFF))
            .write(0);
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
    fn guest_tls_fast_enter_without_gettid_map() {
        #[cfg(all(target_arch = "aarch64", target_os = "linux"))]
        {
            prepare_host_meta();
            let host = host_tpidr();
            let Some(base) = map_guest_tls_page() else {
                return;
            };
            init_guest_tls_block(base, 0);
            let guest = crate::host::ptr_addr_u64(base);
            let fake_alt = 0x_aaa0_u64;
            publish_boundary_to_guest_tls(guest, host, fake_alt);

            let ret = unsafe {
                cpu::write_tpidr_el0(guest);
                enter_host_tls_inner()
            };
            assert_eq!(cpu::read_tpidr_el0(), host);
            assert_eq!(ret.alt_top, fake_alt);
            assert_eq!(ret.guest_tpidr, guest);

            leave_host_tls_inner(ret.guest_tpidr);
            assert_eq!(cpu::read_tpidr_el0(), guest);

            clear_guest_tls_on_exit();
            assert_eq!(cpu::read_tpidr_el0(), host);
            let _ = crate::host::munmap(base, crate::host::page_size().unwrap_or(4096));
        }
    }

    #[test]
    fn enter_leave_restores_host() {
        #[cfg(all(target_arch = "aarch64", target_os = "linux"))]
        {
            prepare_host_meta();
            let host = host_tpidr();
            let Some(base) = map_guest_tls_page() else {
                return;
            };
            init_guest_tls_block(base, 0);
            let fake_guest = crate::host::ptr_addr_u64(base);
            host_slot::with_tls_init(|m| {
                m.guest_tpidr = fake_guest;
            });
            publish_boundary_to_guest_tls(fake_guest, host, 0);
            // SAFETY: TPIDR briefly non-host; A1 mirror or gettid recovers host.
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
            let _ = crate::host::munmap(base, crate::host::page_size().unwrap_or(4096));
        }
    }
}
