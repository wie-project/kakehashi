//! Per-host-thread state reachable without host `TPIDR_EL0` / Rust TLS.
//!
//! Guest code may point `TPIDR_EL0` at freestanding Darwin TSD. While that is
//! live, `thread_local!` and glibc TLS are unusable. Everything needed on the
//! guest→host boundary is stored here, keyed by the OS thread id (`gettid` on
//! Linux, `pthread_self` elsewhere).
//!
//! **Hot path under guest TPIDR** must not allocate (glibc malloc may touch TLS).
//! Insert/claim slots only while host TPIDR is live (prepare paths).
//!
//! ## A2 (enter + alt merge)
//!
//! Hypercall entry uses [`prepare_enter_under_guest`]: one `gettid` + one map
//! lock updates TLS and returns the pre-mapped alt-stack top so asm need not
//! call `kh_host_alt_sp` (second gettid). Leave still uses `gettid` (guest-safe).
//! No host `thread_local!` on this path — probing TLS under guest TPIDR SEGV's
//! even when the cell is empty (invariant 10).
#![allow(unsafe_code)]

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

/// Host glibc / guest TSD snapshots for one OS thread.
#[derive(Clone, Copy, Debug, Default)]
pub struct TlsSlot {
    /// Host `TPIDR_EL0` captured before any guest `msr`.
    pub host_tpidr: u64,
    /// Last guest `TPIDR_EL0` (refreshed via `mrs` on host entry).
    pub guest_tpidr: u64,
    /// True after prepare.
    pub active: bool,
}

/// Hypercall alt stack (host private map).
#[derive(Clone, Copy, Debug)]
pub struct AltStackSlot {
    pub base: *mut u8,
    pub len: usize,
    pub top: u64,
}

// SAFETY: each slot is only mutated from its owning OS thread; the map lock
// serializes insert/remove. Pointers are private anonymous maps.
unsafe impl Send for AltStackSlot {}

/// Worker exit trampoline + guest pthread identity.
#[derive(Clone, Copy, Debug, Default)]
pub struct WorkerSlot {
    pub exit_pc: u64,
    pub exit_sp: u64,
    pub has_exit: bool,
    pub guest_pthread: u64,
    pub guest_tid: u64,
}

#[derive(Default)]
struct ThreadSlot {
    tls: TlsSlot,
    alt: Option<AltStackSlot>,
    worker: WorkerSlot,
}

fn slots() -> &'static Mutex<HashMap<u64, ThreadSlot>> {
    static SLOTS: OnceLock<Mutex<HashMap<u64, ThreadSlot>>> = OnceLock::new();
    SLOTS.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Stable key for the current OS thread (does not touch `TPIDR_EL0`).
///
/// Safe under guest TPIDR (raw syscall / `pthread_self` cookie).
#[must_use]
pub fn os_tid() -> u64 {
    #[cfg(target_os = "linux")]
    {
        // SAFETY: `gettid` returns a scalar; no TLS required.
        let raw = unsafe { libc::syscall(libc::SYS_gettid) };
        u64::try_from(raw).unwrap_or(0)
    }
    #[cfg(not(target_os = "linux"))]
    {
        // SAFETY: pthread_self is a thread cookie for map keying.
        let p = unsafe { libc::pthread_self() };
        #[allow(clippy::as_conversions)]
        {
            p as u64
        }
    }
}

/// Guest-safe hypercall enter prep: one `gettid` + one lock.
#[derive(Clone, Copy, Debug)]
pub struct EnterPrep {
    pub host_tpidr: u64,
    pub tid: u64,
    /// Pre-mapped hypercall alt stack top, or 0 if missing.
    pub alt_top: u64,
}

/// Under **guest** TPIDR: `gettid` + map lock; update TLS; read alt top if any.
///
/// Does **not** touch `thread_local!`.
pub fn prepare_enter_under_guest(cur_tpidr: u64) -> Option<EnterPrep> {
    let tid = os_tid();
    let mut guard = slots()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let slot = guard.get_mut(&tid)?;
    let m = &mut slot.tls;
    if !m.active {
        m.host_tpidr = cur_tpidr;
        m.active = true;
    } else if cur_tpidr != m.host_tpidr {
        m.guest_tpidr = cur_tpidr;
    }
    let alt_top = slot.alt.map_or(0, |s| s.top);
    Some(EnterPrep {
        host_tpidr: m.host_tpidr,
        tid,
        alt_top,
    })
}

/// Insert/update while **host** TPIDR is live (may allocate).
fn with_slot_init<R>(f: impl FnOnce(&mut ThreadSlot) -> R) -> R {
    let tid = os_tid();
    let mut guard = slots()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let slot = guard.entry(tid).or_default();
    f(slot)
}

/// Mutate an existing slot only (no HashMap insert — safe under guest TPIDR).
fn with_slot_existing_mut<R>(f: impl FnOnce(&mut ThreadSlot) -> R) -> Option<R> {
    let tid = os_tid();
    let mut guard = slots()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let slot = guard.get_mut(&tid)?;
    Some(f(slot))
}

/// Read snapshot without insert.
fn with_slot_existing<R>(f: impl FnOnce(&ThreadSlot) -> R) -> Option<R> {
    let tid = os_tid();
    let guard = slots()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    guard.get(&tid).map(f)
}

/// Prepare/update TLS fields (host TPIDR live — may create slot).
pub fn with_tls_init<R>(f: impl FnOnce(&mut TlsSlot) -> R) -> R {
    with_slot_init(|s| f(&mut s.tls))
}

/// Mutate TLS on an existing slot only.
pub fn with_tls_existing_mut<R>(f: impl FnOnce(&mut TlsSlot) -> R) -> Option<R> {
    with_slot_existing_mut(|s| f(&mut s.tls))
}

/// Alias for call sites that want an explicit guest-safe name (same as mut).
#[inline]
pub fn with_tls_existing_mut_guest_safe<R>(f: impl FnOnce(&mut TlsSlot) -> R) -> Option<R> {
    with_tls_existing_mut(f)
}

#[must_use]
pub fn tls_get() -> TlsSlot {
    with_slot_existing(|s| s.tls).unwrap_or_default()
}

/// Alt stack accessor. Uses existing slot when present (guest-TPIDR safe).
pub fn with_alt_mut<R>(f: impl FnOnce(&mut Option<AltStackSlot>) -> R) -> R {
    let tid = os_tid();
    let mut guard = slots()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(slot) = guard.get_mut(&tid) {
        return f(&mut slot.alt);
    }
    // First touch without prepare — allocate under whatever TLS is current.
    // Prefer prepare_host_meta first in production paths.
    let slot = guard.entry(tid).or_default();
    f(&mut slot.alt)
}

/// Worker slot accessor.
pub fn with_worker_mut<R>(f: impl FnOnce(&mut WorkerSlot) -> R) -> R {
    let tid = os_tid();
    let mut guard = slots()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(slot) = guard.get_mut(&tid) {
        return f(&mut slot.worker);
    }
    let slot = guard.entry(tid).or_default();
    f(&mut slot.worker)
}

#[must_use]
pub fn worker_get() -> WorkerSlot {
    with_slot_existing(|s| s.worker).unwrap_or_default()
}

/// Drop this OS thread's slot (worker exit). Caller unmaps alt stack first.
pub fn clear_current() {
    let tid = os_tid();
    let mut guard = slots()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let _removed = guard.remove(&tid);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[allow(clippy::expect_used)]
    fn prepare_enter_updates_guest_snapshot() {
        with_tls_init(|m| {
            m.active = true;
            m.host_tpidr = 0xabcd;
            m.guest_tpidr = 0;
        });
        let prep = prepare_enter_under_guest(0xdead).expect("slot");
        assert_eq!(prep.host_tpidr, 0xabcd);
        assert_ne!(prep.tid, 0);
        let snap = tls_get();
        assert_eq!(snap.guest_tpidr, 0xdead);
        clear_current();
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn prepare_enter_returns_alt_top() {
        with_tls_init(|m| {
            m.active = true;
            m.host_tpidr = 0x1;
        });
        with_alt_mut(|cell| {
            *cell = Some(AltStackSlot {
                base: core::ptr::null_mut(),
                len: 0,
                top: 0x_dead_beef,
            });
        });
        let prep = prepare_enter_under_guest(0x1).expect("slot");
        assert_eq!(prep.alt_top, 0x_dead_beef);
        clear_current();
    }
}
