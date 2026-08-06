//! Guest thread support: host pthread spawn + `bsdthread_*` helpers.
//!
//! Model (micro / clean-room):
//! - `bsdthread_register` stores the libpthread start trampoline VA.
//! - `bsdthread_create` spawns a **host** thread that jumps into that trampoline
//!   with Darwin `_pthread_start` register convention (`x0`–`x3`).
//! - `bsdthread_terminate` switches back to a saved **host** stack then ends
//!   this host thread only (never exit on the guest stack).
//! - Guest `pthread_join` completion (`done` + futex wake) is published from
//!   the host stack so joiners never `munmap` a stack still in use.
//! - Worker teardown uses raw `SYS_exit` (not `pthread_exit`): glibc
//!   `pthread_exit` runs `_Unwind_ForcedUnwind`, which walks `x29` into guest /
//!   hypercall frames and SEGV's in `libgcc_s` under 7zz MT.
//! - Live spawn requires **Linux aarch64** (same as the trap backend).

#![allow(unsafe_code)]

use std::sync::atomic::{AtomicU64, Ordering};

use crate::host_slot;

/// Monotonic guest-visible thread id counter (`thread_selfid`).
static NEXT_TID: AtomicU64 = AtomicU64::new(1);

/// Size of the per-thread host hypercall stack (grows down from the top).
#[cfg(all(target_arch = "aarch64", target_os = "linux"))]
const HOST_ALT_STACK_SIZE: usize = 512 * 1024;

/// Returns a 16-byte-aligned host SP for freestanding hypercall dispatch.
///
/// Prefer calling [`ensure_host_alt_stack`] while host `TPIDR_EL0` is live
/// (worker prepare / main TLS install). The hypercall entry also restores host
/// TLS before invoking this so a cold first map is safe.
///
/// Uses [`host_slot`] — never Rust `thread_local!`.
///
/// # Safety
///
/// Caller must restore guest SP after the call returns. The buffer is
/// valid until [`drop_host_alt_stack`] / process exit.
#[cfg(all(target_arch = "aarch64", target_os = "linux"))]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kh_host_alt_sp() -> u64 {
    ensure_host_alt_stack()
}

/// Map this OS thread's hypercall alt stack if missing; return its top SP.
///
/// Safe to call repeatedly. Must run with **host** `TPIDR_EL0` for the first
/// map (glibc `mmap` / map mutex).
#[cfg(all(target_arch = "aarch64", target_os = "linux"))]
#[must_use]
pub fn ensure_host_alt_stack() -> u64 {
    let top = host_slot::with_alt_mut(|cell| {
        if let Some(s) = *cell {
            return s.top;
        }
        match map_host_alt_stack() {
            Some(s) => {
                let t = s.top;
                *cell = Some(s);
                t
            }
            None => 0,
        }
    });
    // A1: keep guest-TLS alt_top mirror current for gettid-free enter.
    if top != 0 {
        crate::tls::publish_alt_top_to_current_guest(top);
    }
    top
}

#[cfg(not(all(target_arch = "aarch64", target_os = "linux")))]
#[must_use]
pub fn ensure_host_alt_stack() -> u64 {
    0
}

#[cfg(all(target_arch = "aarch64", target_os = "linux"))]
fn map_host_alt_stack() -> Option<host_slot::AltStackSlot> {
    let len = HOST_ALT_STACK_SIZE;
    let flags = libc::MAP_PRIVATE | libc::MAP_ANONYMOUS;
    let prot = libc::PROT_READ | libc::PROT_WRITE;
    // Prefer raw syscall so a mistaken guest-TPIDR call does not enter glibc
    // arena code that depends on host TLS.
    let ptr = mmap_anon_raw(len, prot, flags)?;
    let base_u = crate::host::ptr_addr_u64(ptr);
    let top = base_u.saturating_add(u64::try_from(len).unwrap_or(0)) & !0xF;
    if top <= base_u {
        let _ = crate::host::munmap(ptr, len);
        return None;
    }
    Some(host_slot::AltStackSlot {
        base: ptr,
        len,
        top,
    })
}

/// Anonymous `mmap` via raw syscall (no glibc TLS dependency).
#[cfg(all(target_arch = "aarch64", target_os = "linux"))]
fn mmap_anon_raw(len: usize, prot: libc::c_int, flags: libc::c_int) -> Option<*mut u8> {
    // SAFETY: anonymous map; fd/offset unused with MAP_ANONYMOUS.
    let raw = unsafe {
        libc::syscall(
            libc::SYS_mmap,
            core::ptr::null_mut::<libc::c_void>(),
            len,
            prot,
            flags,
            -1_i32,
            0_i64,
        )
    };
    if raw < 0 {
        return None;
    }
    let addr = usize::try_from(raw).ok()?;
    Some(core::ptr::with_exposed_provenance_mut(addr))
}

/// Unmaps this thread's hypercall alt stack (worker exit / tests).
#[cfg(all(target_arch = "aarch64", target_os = "linux"))]
pub(crate) fn drop_host_alt_stack() {
    host_slot::with_alt_mut(|cell| {
        if let Some(s) = cell.take() {
            let _ = crate::host::munmap(s.base, s.len);
        }
    });
}

#[cfg(not(all(target_arch = "aarch64", target_os = "linux")))]
#[allow(dead_code)] // Linux aarch64 only; stub keeps call sites compiling.
pub(crate) fn drop_host_alt_stack() {}

/// Live guest worker threads (not including the main `LC_MAIN` thread).
static LIVE_WORKERS: AtomicU64 = AtomicU64::new(0);

/// Darwin `EAGAIN`.
#[cfg(all(target_arch = "aarch64", target_os = "linux"))]
const EAGAIN: i64 = 35;

/// Resets thread counters for a new guest run.
pub fn reset_thread_runtime() {
    NEXT_TID.store(1, Ordering::SeqCst);
    LIVE_WORKERS.store(0, Ordering::SeqCst);
}

/// Allocates a new guest thread id (unique within the process run).
#[must_use]
pub fn alloc_tid() -> u64 {
    NEXT_TID.fetch_add(1, Ordering::SeqCst)
}

/// Current host thread's guest tid (stable for the host thread lifetime).
///
/// Uses [`host_slot`] so it remains safe under guest `TPIDR_EL0`.
#[must_use]
pub fn thread_selfid() -> u64 {
    host_slot::with_worker_mut(|w| {
        if w.guest_tid == 0 {
            w.guest_tid = alloc_tid();
        }
        w.guest_tid
    })
}

/// Number of live worker threads spawned via `bsdthread_create`.
#[must_use]
pub fn live_workers() -> u64 {
    LIVE_WORKERS.load(Ordering::SeqCst)
}

/// Arguments for a newly created guest worker.
#[derive(Debug, Clone, Copy)]
pub struct GuestThreadStart {
    /// Registered `threadstart` trampoline VA.
    pub entry: u64,
    /// Guest stack pointer (16-byte aligned top of stack).
    pub sp: u64,
    /// `x0` — pthread structure VA.
    pub pthread: u64,
    /// `x1` — Mach thread port (stubbed to 0).
    pub port: u64,
    /// `x2` — user start routine VA.
    pub func: u64,
    /// `x3` — user argument.
    pub func_arg: u64,
}

/// Spawns a host thread that enters guest code at `start.entry`.
pub fn spawn_guest_thread(start: GuestThreadStart) -> Result<(), i64> {
    #[cfg(not(all(target_arch = "aarch64", target_os = "linux")))]
    {
        let _ = start;
        Err(crate::syscall::ENOSYS)
    }

    #[cfg(all(target_arch = "aarch64", target_os = "linux"))]
    {
        linux_spawn(start)
    }
}

#[cfg(all(target_arch = "aarch64", target_os = "linux"))]
mod linux {
    use super::{EAGAIN, GuestThreadStart, LIVE_WORKERS, thread_selfid};
    use crate::host_slot;
    use std::sync::atomic::{AtomicU32, Ordering};

    /// Must match freestanding `kh-libsystem` `KhThread` / `MAGIC`.
    ///
    /// Layout (`repr(C, align(16))` on aarch64):
    /// ```text
    /// offset 0:  magic: u64
    /// offset 8:  done: AtomicU32   ← join wait / host publish
    /// offset 12: detached: AtomicU32
    /// offset 16: result: AtomicUsize
    /// … stack fields follow; host only touches magic + done.
    /// offset 56: tsd
    /// ```
    const KH_THREAD_MAGIC: u64 = 0x4B48_5054_4852_4401;
    const KH_THREAD_DONE_OFF: usize = 8;

    pub(super) fn linux_spawn(start: GuestThreadStart) -> Result<(), i64> {
        if start.entry == 0 || start.sp == 0 || !start.sp.is_multiple_of(16) {
            return Err(crate::syscall::EINVAL);
        }

        let builder = std::thread::Builder::new().name("kh-guest".into());
        match builder.spawn(move || guest_worker_main(start)) {
            Ok(_handle) => {
                LIVE_WORKERS.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }
            Err(_) => Err(EAGAIN),
        }
    }

    fn guest_worker_main(start: GuestThreadStart) {
        let _ = thread_selfid();
        host_slot::with_worker_mut(|w| {
            w.guest_pthread = start.pthread;
        });

        // Capture host TPIDR *before* guest code may msr guest TSD into TPIDR_EL0.
        crate::tls::prepare_host_meta();
        // Map hypercall alt stack while host TLS is still live (workers hit
        // freestanding hypercall immediately under 7zz `-mmt>1`).
        let _ = super::ensure_host_alt_stack();

        // `bsdthread_create` runs inside the SIGTRAP handler, where SIGTRAP is
        // blocked. `std::thread::spawn` copies that mask, so the worker would
        // die on the first guest `brk` unless we unblock here.
        unblock_sigtrap();

        let host_sp = crate::cpu::read_sp();
        // Leave room for host exit / join-publish frames (not just 512 B).
        let frame_sp = host_sp.saturating_sub(4096) & !0xF;
        set_host_exit_frame(host_thread_exit_pc(), frame_sp);

        // Prefer freestanding KhThread.tsd (offset 56) when present; else guest
        // trampoline will install TLS itself and boundary will mrs it.
        if let Some(tsd) = guest_tsd_from_pthread(start.pthread) {
            crate::tls::enter_guest_tls(tsd);
        }

        // SAFETY: trap handlers installed by `run_micro` before create; entry/stack
        // are guest `bsdthread_create` arguments (mapped stack region).
        let result = unsafe {
            crate::entry::jump_to_guest_args(
                start.entry,
                start.sp,
                start.pthread,
                start.port,
                start.func,
                start.func_arg,
            )
        };
        if let Err(err) = result {
            tracing::error!(?err, "guest worker failed to enter");
        }
        // jump_to_guest is noreturn on success; if we return, publish join + exit.
        finish_worker_on_host();
    }

    /// Freestanding `KhThread` layout: `tsd: *mut GuestTls` at offset 56.
    const KH_THREAD_TSD_OFF: usize = 56;

    fn guest_tsd_from_pthread(pthread: u64) -> Option<u64> {
        let base = usize::try_from(pthread).ok()?;
        if base == 0 {
            return None;
        }
        // SAFETY: identity-mapped freestanding KhThread from pthread_create.
        let magic_ptr = std::ptr::with_exposed_provenance::<u64>(base);
        let magic = unsafe { core::ptr::read_volatile(magic_ptr) };
        if magic != KH_THREAD_MAGIC {
            return None;
        }
        let tsd_ptr =
            std::ptr::with_exposed_provenance::<u64>(base.saturating_add(KH_THREAD_TSD_OFF));
        let tsd = unsafe { core::ptr::read_volatile(tsd_ptr) };
        if tsd == 0 {
            return None;
        }
        Some(tsd)
    }

    fn unblock_sigtrap() {
        // SAFETY: only clears the per-thread SIGTRAP block bit inherited from
        // the spawning signal handler; disposition is already installed.
        unsafe {
            let mut set: libc::sigset_t = std::mem::zeroed();
            libc::sigemptyset(std::ptr::addr_of_mut!(set));
            libc::sigaddset(std::ptr::addr_of_mut!(set), libc::SIGTRAP);
            libc::pthread_sigmask(
                libc::SIG_UNBLOCK,
                std::ptr::addr_of!(set),
                std::ptr::null_mut(),
            );
        }
    }

    #[allow(unknown_lints, clippy::as_conversions, function_casts_as_integer)]
    fn host_thread_exit_pc() -> u64 {
        u64::try_from(host_thread_exit as usize).unwrap_or(0)
    }

    /// Landing pad on the **host** stack after `bsdthread_terminate`.
    unsafe extern "C" fn host_thread_exit() -> ! {
        finish_worker_on_host();
    }

    /// Publish guest join state, drop live-worker count, end this host thread.
    ///
    /// Must run with SP on the host stack (never on the guest worker stack that
    /// `pthread_join` may munmap once `done` is visible).
    fn finish_worker_on_host() -> ! {
        clear_host_exit_frame();
        // Host TLS before any further host libc (join publish, munmap, exit).
        crate::tls::clear_guest_tls_on_exit();
        publish_guest_join_done();
        host_slot::with_worker_mut(|w| {
            w.guest_pthread = 0;
        });
        super::drop_host_alt_stack();
        host_slot::clear_current();
        worker_finished();
        // End **this** OS thread only. Do **not** call `pthread_exit`:
        // glibc runs `_Unwind_ForcedUnwind` for cleanup handlers; after a
        // hypercall/guest jump the FP chain still points into guest memory
        // and the DWARF walker SEGV's in `libgcc_s` (seen as pc=libgcc+0xe320
        // under 7zz `-mmt>1`). Raw `SYS_exit` skips forced unwind.
        // SAFETY: Linux `exit` (not `exit_group`) terminates only the caller.
        unsafe {
            libc::syscall(libc::SYS_exit, 0);
        }
        // syscall exit is noreturn; keep the type checker happy.
        loop {
            core::hint::spin_loop();
        }
    }

    /// Set freestanding `KhThread.done` and futex-wake joiners.
    ///
    /// Guest `kh_pthread_start` stores `result` before `bsdthread_terminate` but
    /// **must not** set `done` early: that allowed `pthread_join` to munmap the
    /// guest stack while hypercall terminate / Rust still ran on it (intermittent
    /// SEGV under 7zz `-mmt>1` with freestanding hypercall).
    fn publish_guest_join_done() {
        let pthread = host_slot::worker_get().guest_pthread;
        if pthread == 0 {
            return;
        }
        let base = usize::try_from(pthread).unwrap_or(0);
        if base == 0 {
            return;
        }
        // SAFETY: identity-mapped guest heap block from freestanding pthread_create.
        let magic_ptr = std::ptr::with_exposed_provenance::<u64>(base);
        let magic = unsafe { core::ptr::read_volatile(magic_ptr) };
        if magic != KH_THREAD_MAGIC {
            tracing::warn!(
                pthread = format_args!("{pthread:#x}"),
                magic = format_args!("{magic:#x}"),
                "guest pthread magic mismatch; skip join publish"
            );
            return;
        }
        let done_addr = base.saturating_add(KH_THREAD_DONE_OFF);
        let done_ptr = std::ptr::with_exposed_provenance_mut::<AtomicU32>(done_addr);
        // SAFETY: aligned AtomicU32 at known freestanding layout offset.
        unsafe {
            (*done_ptr).store(1, Ordering::Release);
        }
        futex_wake(done_ptr.cast::<u32>(), i32::MAX);
    }

    fn futex_wake(addr: *mut u32, n: i32) {
        // SAFETY: same identity-mapped word guests park on via KH_HELPER_PARK.
        // FUTEX_WAKE_PRIVATE (129) must match `helpers::wake_u32` (park uses PRIVATE).
        let _ = unsafe {
            libc::syscall(
                libc::SYS_futex,
                addr,
                129_i32, // FUTEX_WAKE_PRIVATE
                n,
                core::ptr::null::<libc::timespec>(),
                core::ptr::null_mut::<u32>(),
                0_i32,
            )
        };
    }

    fn worker_finished() {
        let _ = LIVE_WORKERS.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| {
            Some(n.saturating_sub(1))
        });
    }

    /// Hypercall / trap path: leave the guest stack, then end this host worker.
    ///
    /// Switching SP (and clearing FP) before teardown is mandatory: freestanding
    /// hypercall may have left `x29` pointing at a guest frame that joiners
    /// munmap once `done` is published; forced unwind must never see that chain.
    pub(crate) fn exit_worker_now() -> ! {
        let (pc, sp, has) = host_slot::with_worker_mut(|w| {
            let has = w.has_exit;
            let pc = w.exit_pc;
            let sp = w.exit_sp;
            w.has_exit = false;
            (pc, sp, has)
        });
        if has {
            // SAFETY: frame was recorded on this host thread before guest entry;
            // `pc` is `host_thread_exit`, `sp` is 16-byte aligned host stack.
            // Zero `x29` so any accidental libc unwind cannot follow guest FP.
            unsafe {
                std::arch::asm!(
                    "mov sp, {sp}",
                    "mov x29, xzr",
                    "br {pc}",
                    sp = in(reg) sp,
                    pc = in(reg) pc,
                    options(noreturn),
                );
            }
        }
        // No frame (should not happen for workers): best-effort host exit.
        finish_worker_on_host();
    }

    fn set_host_exit_frame(pc: u64, sp: u64) {
        host_slot::with_worker_mut(|w| {
            w.exit_pc = pc;
            w.exit_sp = sp;
            w.has_exit = true;
        });
    }

    fn clear_host_exit_frame() {
        host_slot::with_worker_mut(|w| {
            w.has_exit = false;
        });
    }

    /// Rewrite `mcontext` so sigreturn jumps to the host worker-exit trampoline.
    pub(crate) fn redirect_ucontext_to_host_exit(m: &mut libc::mcontext_t) -> bool {
        host_slot::with_worker_mut(|w| {
            if !w.has_exit {
                return false;
            }
            // Consume so a second terminate does not reuse a stale frame.
            w.has_exit = false;
            m.pc = w.exit_pc;
            m.sp = w.exit_sp;
            // Drop guest FP chain (same rationale as `exit_worker_now`).
            m.regs[29] = 0;
            true
        })
    }
}

#[cfg(all(target_arch = "aarch64", target_os = "linux"))]
use linux::linux_spawn;

/// Rewrite `mcontext` so sigreturn jumps to the host worker-exit trampoline.
///
/// Returns `false` when no frame is installed (main thread / non-worker).
#[cfg(all(target_arch = "aarch64", target_os = "linux"))]
pub(crate) use linux::redirect_ucontext_to_host_exit;

/// End the current guest worker from hypercall/trap (not signal ucontext).
///
/// Switches to the saved host stack, publishes join `done`, then ends the
/// host OS thread (`SYS_exit` — see `finish_worker_on_host`).
#[cfg(all(target_arch = "aarch64", target_os = "linux"))]
pub(crate) fn exit_current_guest_worker() -> ! {
    linux::exit_worker_now();
}

#[cfg(not(all(target_arch = "aarch64", target_os = "linux")))]
#[allow(dead_code)] // live only via Linux aarch64 trap/hypercall path
pub(crate) fn redirect_ucontext_to_host_exit() -> bool {
    false
}

#[cfg(not(all(target_arch = "aarch64", target_os = "linux")))]
#[allow(dead_code)] // live only via Linux aarch64 trap/hypercall path
pub(crate) fn exit_current_guest_worker() -> ! {
    loop {
        core::hint::spin_loop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selfid_stable_on_thread() {
        let a = thread_selfid();
        let b = thread_selfid();
        assert_eq!(a, b);
        assert!(a > 0);
    }

    #[test]
    fn alloc_tid_monotonic() {
        let a = alloc_tid();
        let b = alloc_tid();
        assert!(b > a);
    }
}
