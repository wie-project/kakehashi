//! Guest thread support: host pthread spawn + `bsdthread_*` helpers.
//!
//! Model (micro / clean-room):
//! - `bsdthread_register` stores the libpthread start trampoline VA.
//! - `bsdthread_create` spawns a **host** thread that jumps into that trampoline
//!   with Darwin `_pthread_start` register convention (`x0`–`x3`).
//! - `bsdthread_terminate` redirects the trap ucontext to a host
//!   `pthread_exit` landing (this host thread only).
//! - Live spawn requires **Linux aarch64** (same as the trap backend).

#![allow(unsafe_code)]

use std::cell::Cell;
use std::sync::atomic::{AtomicU64, Ordering};

thread_local! {
    static TID: Cell<u64> = const { Cell::new(0) };
}

/// Monotonic guest-visible thread id counter (`thread_selfid`).
static NEXT_TID: AtomicU64 = AtomicU64::new(1);

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
    use std::sync::atomic::Ordering;

    /// Host `(pc, sp)` used when a guest worker hits `bsdthread_terminate`.
    #[derive(Clone, Copy)]
    struct HostExitFrame {
        pc: u64,
        sp: u64,
    }

    thread_local! {
        static HOST_EXIT: Cell<Option<HostExitFrame>> = const { Cell::new(None) };
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

        // `bsdthread_create` runs inside the SIGTRAP handler, where SIGTRAP is
        // blocked. `std::thread::spawn` copies that mask, so the worker would
        // die on the first guest `brk` unless we unblock here.
        unblock_sigtrap();

        let host_sp = read_sp();
        let frame_sp = host_sp.saturating_sub(512) & !0xF;
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
        worker_finished();
    }

    fn unblock_sigtrap() {
        // SAFETY: only clears the per-thread SIGTRAP block bit inherited from
        // the spawning signal handler; disposition is already installed.
        unsafe {
            let mut set: libc::sigset_t = std::mem::zeroed();
            libc::sigemptyset(std::ptr::addr_of_mut!(set));
            libc::sigaddset(std::ptr::addr_of_mut!(set), libc::SIGTRAP);
            libc::pthread_sigmask(libc::SIG_UNBLOCK, std::ptr::addr_of!(set), std::ptr::null_mut());
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

    unsafe extern "C" fn host_thread_exit() -> ! {
        clear_host_exit_frame();
        worker_finished();
        // SAFETY: intentional end of this host thread only (not the process).
        unsafe {
            libc::pthread_exit(std::ptr::null_mut());
        }
    }

    fn worker_finished() {
        let _ = LIVE_WORKERS.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| {
            Some(n.saturating_sub(1))
        });
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

#[cfg(not(all(target_arch = "aarch64", target_os = "linux")))]
#[allow(dead_code)]
pub(crate) fn redirect_ucontext_to_host_exit() -> bool {
    false
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
