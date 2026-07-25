//! Guest thread support: host pthread spawn + `bsdthread_*` helpers.
//!
//! Model (micro / clean-room):
//! - `bsdthread_register` stores the libpthread start trampoline VA.
//! - `bsdthread_create` spawns a **host** thread that jumps into that trampoline
//!   with Darwin `_pthread_start` register convention (`x0`–`x3`).
//! - `bsdthread_terminate` switches back to a saved **host** stack then
//!   `pthread_exit`s this host thread only (never exit on the guest stack).
//! - Guest `pthread_join` completion (`done` + futex wake) is published from
//!   the host stack so joiners never `munmap` a stack still in use.
//! - Live spawn requires **Linux aarch64** (same as the trap backend).

#![allow(unsafe_code)]

use std::cell::Cell;
use std::sync::atomic::{AtomicU64, Ordering};

thread_local! {
    static TID: Cell<u64> = const { Cell::new(0) };
}

// Per-thread host stack for freestanding hypercall dispatch (see `kh_host_alt_sp`).
// Guest SP is unsafe for host Rust under 7zz `-mmt>1`.
#[cfg(all(target_arch = "aarch64", target_os = "linux"))]
thread_local! {
    static HOST_ALT: Cell<Option<HostAltStack>> = const { Cell::new(None) };
}

/// Monotonic guest-visible thread id counter (`thread_selfid`).
static NEXT_TID: AtomicU64 = AtomicU64::new(1);

/// Size of the per-thread host hypercall stack (grows down from the top).
#[cfg(all(target_arch = "aarch64", target_os = "linux"))]
const HOST_ALT_STACK_SIZE: usize = 512 * 1024;

#[cfg(all(target_arch = "aarch64", target_os = "linux"))]
#[derive(Clone, Copy)]
struct HostAltStack {
    base: *mut u8,
    len: usize,
    /// 16-byte-aligned top address used as initial SP.
    top: u64,
}

/// Returns a 16-byte-aligned host SP for freestanding hypercall dispatch.
///
/// Called from the hypercall asm entry **before** Rust dispatch. Lazy-maps a
/// private stack the first time each host thread hypercalls.
///
/// # Safety
///
/// Caller must restore guest SP after the call returns. The buffer is
/// thread-local and valid until [`drop_host_alt_stack`] / process exit.
#[cfg(all(target_arch = "aarch64", target_os = "linux"))]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kh_host_alt_sp() -> u64 {
    HOST_ALT.with(|cell| {
        if let Some(s) = cell.get() {
            return s.top;
        }
        match map_host_alt_stack() {
            Some(s) => {
                cell.set(Some(s));
                s.top
            }
            None => 0,
        }
    })
}

#[cfg(all(target_arch = "aarch64", target_os = "linux"))]
fn map_host_alt_stack() -> Option<HostAltStack> {
    let len = HOST_ALT_STACK_SIZE;
    let flags = libc::MAP_PRIVATE | libc::MAP_ANONYMOUS;
    // Linux: MAP_STACK is advisory; omit for portability of the flag set.
    let prot = libc::PROT_READ | libc::PROT_WRITE;
    let ptr = crate::host::mmap(None, len, prot, flags, -1, 0)?;
    let base_u = crate::host::ptr_addr_u64(ptr);
    let top = base_u.saturating_add(u64::try_from(len).unwrap_or(0)) & !0xF;
    if top <= base_u {
        let _ = crate::host::munmap(ptr, len);
        return None;
    }
    Some(HostAltStack {
        base: ptr,
        len,
        top,
    })
}

/// Unmaps this thread's hypercall alt stack (worker exit / tests).
#[cfg(all(target_arch = "aarch64", target_os = "linux"))]
pub(crate) fn drop_host_alt_stack() {
    HOST_ALT.with(|cell| {
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
#[must_use]
pub fn thread_selfid() -> u64 {
    TID.with(|c| {
        let mut v = c.get();
        if v == 0 {
            v = alloc_tid();
            c.set(v);
        }
        v
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
    use std::cell::Cell;
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
    /// ```
    const KH_THREAD_MAGIC: u64 = 0x4B48_5054_4852_4401;
    const KH_THREAD_DONE_OFF: usize = 8;

    /// Host `(pc, sp)` used when a guest worker hits `bsdthread_terminate`.
    #[derive(Clone, Copy)]
    struct HostExitFrame {
        pc: u64,
        sp: u64,
    }

    thread_local! {
        static HOST_EXIT: Cell<Option<HostExitFrame>> = const { Cell::new(None) };
        /// Guest `pthread_t` VA for this worker (identity-mapped `KhThread`).
        static GUEST_PTHREAD: Cell<u64> = const { Cell::new(0) };
    }

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
        GUEST_PTHREAD.set(start.pthread);

        // `bsdthread_create` runs inside the SIGTRAP handler, where SIGTRAP is
        // blocked. `std::thread::spawn` copies that mask, so the worker would
        // die on the first guest `brk` unless we unblock here.
        unblock_sigtrap();

        let host_sp = read_sp();
        // Leave room for host exit / join-publish frames (not just 512 B).
        let frame_sp = host_sp.saturating_sub(4096) & !0xF;
        set_host_exit_frame(host_thread_exit_pc(), frame_sp);

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

    fn read_sp() -> u64 {
        let sp: u64;
        // SAFETY: reading SP is a pure register move.
        unsafe {
            std::arch::asm!("mov {}, sp", out(reg) sp, options(nomem, nostack, preserves_flags));
        }
        sp
    }

    #[allow(clippy::as_conversions, function_casts_as_integer)]
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
        publish_guest_join_done();
        GUEST_PTHREAD.set(0);
        super::drop_host_alt_stack();
        worker_finished();
        // SAFETY: intentional end of this host thread only (not the process).
        unsafe {
            libc::pthread_exit(std::ptr::null_mut());
        }
    }

    /// Set freestanding `KhThread.done` and futex-wake joiners.
    ///
    /// Guest `kh_pthread_start` stores `result` before `bsdthread_terminate` but
    /// **must not** set `done` early: that allowed `pthread_join` to munmap the
    /// guest stack while hypercall terminate / Rust still ran on it (intermittent
    /// SEGV under 7zz `-mmt>1` with freestanding hypercall).
    fn publish_guest_join_done() {
        let pthread = GUEST_PTHREAD.get();
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
        let _ = unsafe {
            libc::syscall(
                libc::SYS_futex,
                addr,
                1_i32, // FUTEX_WAKE
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
    /// Switching SP before `pthread_exit` is mandatory: freestanding hypercall
    /// runs host Rust on the guest stack, and joiners reclaim that stack once
    /// the worker is joinable.
    pub(crate) fn exit_worker_now() -> ! {
        let frame = HOST_EXIT.take();
        if let Some(frame) = frame {
            // SAFETY: frame was recorded on this host thread before guest entry;
            // `pc` is `host_thread_exit`, `sp` is 16-byte aligned host stack.
            unsafe {
                std::arch::asm!(
                    "mov sp, {sp}",
                    "br {pc}",
                    sp = in(reg) frame.sp,
                    pc = in(reg) frame.pc,
                    options(noreturn),
                );
            }
        }
        // No frame (should not happen for workers): best-effort host exit.
        finish_worker_on_host();
    }

    fn set_host_exit_frame(pc: u64, sp: u64) {
        HOST_EXIT.set(Some(HostExitFrame { pc, sp }));
    }

    fn clear_host_exit_frame() {
        HOST_EXIT.set(None);
    }

    /// Rewrite `mcontext` so sigreturn jumps to the host `pthread_exit` trampoline.
    pub(crate) fn redirect_ucontext_to_host_exit(m: &mut libc::mcontext_t) -> bool {
        HOST_EXIT.with(|cell| {
            let Some(frame) = cell.get() else {
                return false;
            };
            // Consume so a second terminate does not reuse a stale frame.
            cell.set(None);
            m.pc = frame.pc;
            m.sp = frame.sp;
            true
        })
    }
}

#[cfg(all(target_arch = "aarch64", target_os = "linux"))]
use linux::linux_spawn;

/// Rewrite `mcontext` so sigreturn jumps to the host `pthread_exit` trampoline.
///
/// Returns `false` when no frame is installed (main thread / non-worker).
#[cfg(all(target_arch = "aarch64", target_os = "linux"))]
pub(crate) use linux::redirect_ucontext_to_host_exit;

/// End the current guest worker from hypercall/trap (not signal ucontext).
///
/// Switches to the saved host stack, publishes join `done`, then `pthread_exit`s.
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
