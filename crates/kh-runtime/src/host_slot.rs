//! Per-host-thread state reachable **without** host `TPIDR_EL0` / Rust TLS.
//!
//! Guest code may point `TPIDR_EL0` at freestanding Darwin TSD. While that is
//! live, `thread_local!` and glibc TLS are unusable. Everything needed on the
//! guest→host boundary is stored here, keyed by the OS thread id (`gettid` on
//! Linux, `pthread_self` elsewhere).
//!
//! **Hot path under guest TPIDR** must not allocate (glibc malloc may touch TLS).
//! Insert/claim slots only while host TPIDR is live (prepare paths).
//!
//! ## Host-only cache (roadmap A2)
//!
//! After [`crate::tls::enter_host_tls`] restores host `TPIDR_EL0`, this module
//! may cache the current OS tid and a stable `*mut ThreadSlot` in Rust
//! `thread_local!`. That skips the second/third `gettid` + map `Mutex` within
//! the same hypercall (`kh_host_alt_sp`, `kh_tls_leave_host`).
//!
//! **MUST NOT** read the host cache while guest TPIDR is live (invariant 10).
//! Arm only after host `msr`; disarm before restoring guest TPIDR / slot drop.
#![allow(unsafe_code)]

use std::cell::Cell;
use std::collections::HashMap;
use std::ptr;
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

/// Host-only fast path after enter: stable heap slot + tid (no guest TPIDR use).
#[derive(Clone, Copy)]
struct HostCache {
    tid: u64,
    slot: *mut ThreadSlot,
}

// SAFETY: HostCache is thread-local; only the owning OS thread reads/writes it.
// The `*mut ThreadSlot` points at a `Box` heap allocation that outlives the
// cache (disarmed before map remove).
unsafe impl Send for HostCache {}

impl HostCache {
    const EMPTY: Self = Self {
        tid: 0,
        slot: ptr::null_mut(),
    };

    #[inline]
    fn is_armed(self) -> bool {
        self.tid != 0 && !self.slot.is_null()
    }
}

thread_local! {
    /// Valid only while host `TPIDR_EL0` is live (after enter, before leave/clear).
    static HOST_CACHE: Cell<HostCache> = const { Cell::new(HostCache::EMPTY) };
}

/// `Box` keeps `*mut ThreadSlot` stable across HashMap rehash.
fn slots() -> &'static Mutex<HashMap<u64, Box<ThreadSlot>>> {
    static SLOTS: OnceLock<Mutex<HashMap<u64, Box<ThreadSlot>>>> = OnceLock::new();
    SLOTS.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Stable key for the current OS thread (does not touch `TPIDR_EL0`).
///
/// Safe under guest TPIDR (raw syscall / `pthread_self` cookie). Prefer
/// [`os_tid_host_cached`] once host TLS is live.
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

/// OS tid using the host-only cache when armed (no `gettid`).
///
/// **MUST** only be called while host `TPIDR_EL0` is live, or when the cache
/// is known disarmed (falls back to [`os_tid`]).
#[must_use]
pub fn os_tid_host_cached() -> u64 {
    let cached = HOST_CACHE.with(Cell::get);
    if cached.is_armed() {
        return cached.tid;
    }
    os_tid()
}

/// Result of a guest-TPIDR-safe enter prepare: host TPIDR + stable slot ptr.
///
/// Opaque slot pointer — only [`arm_host_cache`] may consume it.
#[derive(Clone, Copy)]
pub struct EnterPrep {
    pub host_tpidr: u64,
    tid: u64,
    slot: *mut ThreadSlot,
}

/// Under **guest** TPIDR: one `gettid` + one map lock, update TLS, return data
/// for host `msr` + cache arm. Does **not** touch `thread_local!`.
pub fn prepare_enter_under_guest(cur_tpidr: u64) -> Option<EnterPrep> {
    let tid = os_tid();
    let mut guard = slots()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let slot_box = guard.get_mut(&tid)?;
    let slot = slot_box.as_mut();
    let m = &mut slot.tls;
    if !m.active {
        m.host_tpidr = cur_tpidr;
        m.active = true;
    } else if cur_tpidr != m.host_tpidr {
        m.guest_tpidr = cur_tpidr;
    }
    let host_tpidr = m.host_tpidr;
    let ptr: *mut ThreadSlot = slot;
    Some(EnterPrep {
        host_tpidr,
        tid,
        slot: ptr,
    })
}

/// Arm host-only cache. **MUST** run only after host `TPIDR_EL0` is restored.
#[inline]
pub fn arm_host_cache(prep: EnterPrep) {
    if prep.tid == 0 || prep.slot.is_null() {
        return;
    }
    HOST_CACHE.with(|c| {
        c.set(HostCache {
            tid: prep.tid,
            slot: prep.slot,
        });
    });
}

/// Disarm host cache. Call **before** restoring guest `TPIDR_EL0` or dropping
/// the map entry for this thread.
#[inline]
pub fn disarm_host_cache() {
    HOST_CACHE.with(|c| c.set(HostCache::EMPTY));
}

#[inline]
fn cached_slot_mut() -> Option<*mut ThreadSlot> {
    let cached = HOST_CACHE.with(Cell::get);
    if cached.is_armed() {
        Some(cached.slot)
    } else {
        None
    }
}

/// Insert/update while **host** TPIDR is live (may allocate).
fn with_slot_init<R>(f: impl FnOnce(&mut ThreadSlot) -> R) -> R {
    if let Some(ptr) = cached_slot_mut() {
        // SAFETY: cache armed only on host TPIDR; slot is this thread's Box.
        return f(unsafe { &mut *ptr });
    }
    let tid = os_tid();
    let mut guard = slots()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let slot = guard
        .entry(tid)
        .or_insert_with(|| Box::new(ThreadSlot::default()));
    f(slot.as_mut())
}

/// Mutate an existing slot only (no HashMap insert — safe under guest TPIDR
/// when cache is disarmed; uses cache when host-only path is active).
fn with_slot_existing_mut<R>(f: impl FnOnce(&mut ThreadSlot) -> R) -> Option<R> {
    if let Some(ptr) = cached_slot_mut() {
        // SAFETY: host cache armed ⇒ host TPIDR live; Box still in map.
        return Some(f(unsafe { &mut *ptr }));
    }
    let tid = os_tid();
    let mut guard = slots()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let slot = guard.get_mut(&tid)?;
    Some(f(slot.as_mut()))
}

/// Read snapshot without insert.
fn with_slot_existing<R>(f: impl FnOnce(&ThreadSlot) -> R) -> Option<R> {
    if let Some(ptr) = cached_slot_mut() {
        // SAFETY: host cache armed ⇒ host TPIDR live; Box still in map.
        return Some(f(unsafe { &*ptr }));
    }
    let tid = os_tid();
    let guard = slots()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    guard.get(&tid).map(|s| f(s.as_ref()))
}

/// Prepare/update TLS fields (host TPIDR live — may create slot).
pub fn with_tls_init<R>(f: impl FnOnce(&mut TlsSlot) -> R) -> R {
    with_slot_init(|s| f(&mut s.tls))
}

/// Mutate TLS on an existing slot only.
pub fn with_tls_existing_mut<R>(f: impl FnOnce(&mut TlsSlot) -> R) -> Option<R> {
    with_slot_existing_mut(|s| f(&mut s.tls))
}

#[must_use]
pub fn tls_get() -> TlsSlot {
    with_slot_existing(|s| s.tls).unwrap_or_default()
}

/// Alt stack accessor. Uses existing slot when present (guest-TPIDR safe).
pub fn with_alt_mut<R>(f: impl FnOnce(&mut Option<AltStackSlot>) -> R) -> R {
    if let Some(ptr) = cached_slot_mut() {
        // SAFETY: host cache armed ⇒ host TPIDR live; Box still in map.
        return f(unsafe { &mut (*ptr).alt });
    }
    let tid = os_tid();
    let mut guard = slots()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(slot) = guard.get_mut(&tid) {
        return f(&mut slot.alt);
    }
    // First touch without prepare — allocate under whatever TLS is current.
    // Prefer prepare_host_meta first in production paths.
    let slot = guard
        .entry(tid)
        .or_insert_with(|| Box::new(ThreadSlot::default()));
    f(&mut slot.alt)
}

/// Worker slot accessor.
pub fn with_worker_mut<R>(f: impl FnOnce(&mut WorkerSlot) -> R) -> R {
    if let Some(ptr) = cached_slot_mut() {
        // SAFETY: host cache armed ⇒ host TPIDR live; Box still in map.
        return f(unsafe { &mut (*ptr).worker });
    }
    let tid = os_tid();
    let mut guard = slots()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(slot) = guard.get_mut(&tid) {
        return f(&mut slot.worker);
    }
    let slot = guard
        .entry(tid)
        .or_insert_with(|| Box::new(ThreadSlot::default()));
    f(&mut slot.worker)
}

#[must_use]
pub fn worker_get() -> WorkerSlot {
    with_slot_existing(|s| s.worker).unwrap_or_default()
}

/// Drop this OS thread's slot (worker exit). Caller unmaps alt stack first.
pub fn clear_current() {
    // Drop TLS cookie before the Box is freed (host TPIDR expected here).
    disarm_host_cache();
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
    fn cache_disarmed_by_default() {
        disarm_host_cache();
        assert!(cached_slot_mut().is_none());
        assert_eq!(os_tid_host_cached(), os_tid());
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn arm_disarm_roundtrip() {
        // Ensure a slot exists under host TPIDR.
        with_tls_init(|m| {
            m.active = true;
            m.host_tpidr = 0x1111;
        });
        let tid = os_tid();
        let prep = {
            let mut guard = slots()
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let slot = guard.get_mut(&tid).expect("slot after init");
            EnterPrep {
                host_tpidr: slot.tls.host_tpidr,
                tid,
                slot: slot.as_mut(),
            }
        };
        arm_host_cache(prep);
        assert!(cached_slot_mut().is_some());
        assert_eq!(os_tid_host_cached(), tid);

        // Cached path must not need the map lock for tls read.
        let snap = tls_get();
        assert!(snap.active);
        assert_eq!(snap.host_tpidr, 0x1111);

        disarm_host_cache();
        assert!(cached_slot_mut().is_none());
        clear_current();
    }

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
        // Guest snapshot recorded when cur != host.
        let snap = tls_get();
        assert_eq!(snap.guest_tpidr, 0xdead);
        clear_current();
    }
}
