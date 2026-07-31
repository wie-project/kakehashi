//! Synthetic bottle helpers reached via high `x16` numbers (not real BSD).
//!
//! Used by the license-clean `libSystem` stubs for C functions that are
//! awkward as pure guest assembly (`puts`, minimal `printf`, `readdir`, yield).
//! Guest code is: `movz x16, #HELPER; svc #0x80; ret` with args in AAPCS64 regs.

#![allow(unsafe_code)] // futex park/wake via libc::syscall

use std::io::{self, Write};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;

use crate::bottle;
use crate::mem::registry_check_range;
use crate::process as proc_state;

use super::common::{
    EBADF, EFAULT, EINVAL, ENOSYS, SyscallArgs, SyscallResult, guest_write, reg_as_i32,
};

// ── Opt-in park/wake stats (`KAKEHASHI_FUTEX_STATS=1`) ───────────────────────
//
// Classifies guest KH_HELPER_PARK / WAKE without changing lock semantics.
// On UTM after F1, use this to see *what* still drives ~257k host futex:
//
// | park expected | Typical source                         |
// |---------------|----------------------------------------|
// | 0             | `pthread_join` on `KhThread.done`      |
// | 1             | **pre-F1** mutex (`park while locked`)  |
// | 2             | **F1** mutex (`MUTEX_CONTENDED`)        |
// | other         | `pthread_cond_*` generation wait        |
//
// Many `wake` with `woken=0` ⇒ uncontended always-wake (old dylib) or races.
// High `park_exp1` after F1 stage ⇒ bottle still has pre-F1 libSystem.

static PARK_TOTAL: AtomicU64 = AtomicU64::new(0);
static PARK_EXP0: AtomicU64 = AtomicU64::new(0);
static PARK_EXP1: AtomicU64 = AtomicU64::new(0);
static PARK_EXP2: AtomicU64 = AtomicU64::new(0);
static PARK_EXP_OTHER: AtomicU64 = AtomicU64::new(0);
/// Value already ≠ expected before `FUTEX_WAIT` (no sleep).
static PARK_MISMATCH: AtomicU64 = AtomicU64::new(0);
static WAKE_TOTAL: AtomicU64 = AtomicU64::new(0);
static WAKE_N1: AtomicU64 = AtomicU64::new(0);
static WAKE_NBROAD: AtomicU64 = AtomicU64::new(0);
static WAKE_WOKEN_SUM: AtomicU64 = AtomicU64::new(0);
static WAKE_ZERO: AtomicU64 = AtomicU64::new(0);

/// Clear park/wake counters (new guest run).
pub(crate) fn reset_futex_stats() {
    for a in [
        &PARK_TOTAL,
        &PARK_EXP0,
        &PARK_EXP1,
        &PARK_EXP2,
        &PARK_EXP_OTHER,
        &PARK_MISMATCH,
        &WAKE_TOTAL,
        &WAKE_N1,
        &WAKE_NBROAD,
        &WAKE_WOKEN_SUM,
        &WAKE_ZERO,
    ] {
        a.store(0, Ordering::Relaxed);
    }
}

fn futex_stats_enabled() -> bool {
    match std::env::var_os("KAKEHASHI_FUTEX_STATS") {
        None => false,
        Some(v) => {
            v == "1"
                || v.eq_ignore_ascii_case("true")
                || v.eq_ignore_ascii_case("yes")
                || v.eq_ignore_ascii_case("on")
        }
    }
}

/// Print park/wake summary to stderr when `KAKEHASHI_FUTEX_STATS` is set.
///
/// Safe to call under host TPIDR at process exit (`finish_with_exit_code`).
pub(crate) fn dump_futex_stats_if_enabled() {
    if !futex_stats_enabled() {
        return;
    }
    let park = PARK_TOTAL.load(Ordering::Relaxed);
    let wake = WAKE_TOTAL.load(Ordering::Relaxed);
    if park == 0 && wake == 0 {
        drop(io::stderr().write_all(b"kh futex stats: park=0 wake=0 (no helpers)\n"));
        return;
    }
    let msg = format!(
        "kh futex stats:\n\
         \tpark total={park}  mismatch_before_wait={}  \
exp0(join)={} exp1(pre-F1 mutex)={} exp2(F1 mutex)={} other(cond)={}\n\
         \twake total={wake}  n=1={}  n=broad={}  woken_sum={}  woken0={}\n",
        PARK_MISMATCH.load(Ordering::Relaxed),
        PARK_EXP0.load(Ordering::Relaxed),
        PARK_EXP1.load(Ordering::Relaxed),
        PARK_EXP2.load(Ordering::Relaxed),
        PARK_EXP_OTHER.load(Ordering::Relaxed),
        WAKE_N1.load(Ordering::Relaxed),
        WAKE_NBROAD.load(Ordering::Relaxed),
        WAKE_WOKEN_SUM.load(Ordering::Relaxed),
        WAKE_ZERO.load(Ordering::Relaxed),
    );
    drop(io::stderr().write_all(msg.as_bytes()));
}

#[inline]
fn note_park(expected: u32, mismatch: bool) {
    PARK_TOTAL.fetch_add(1, Ordering::Relaxed);
    if mismatch {
        PARK_MISMATCH.fetch_add(1, Ordering::Relaxed);
    }
    match expected {
        0 => {
            PARK_EXP0.fetch_add(1, Ordering::Relaxed);
        }
        1 => {
            PARK_EXP1.fetch_add(1, Ordering::Relaxed);
        }
        2 => {
            PARK_EXP2.fetch_add(1, Ordering::Relaxed);
        }
        _ => {
            PARK_EXP_OTHER.fetch_add(1, Ordering::Relaxed);
        }
    }
}

#[inline]
fn note_wake(n: i32, woken: i32) {
    WAKE_TOTAL.fetch_add(1, Ordering::Relaxed);
    if n <= 0 || n == i32::MAX {
        WAKE_NBROAD.fetch_add(1, Ordering::Relaxed);
    } else if n == 1 {
        WAKE_N1.fetch_add(1, Ordering::Relaxed);
    }
    if woken <= 0 {
        WAKE_ZERO.fetch_add(1, Ordering::Relaxed);
    } else {
        WAKE_WOKEN_SUM.fetch_add(u64::try_from(woken).unwrap_or(0), Ordering::Relaxed);
    }
}

/// Base for Kakehashi host helpers (`'KH' << 16`).
pub(super) const KH_HELPER_BASE: u32 = 0x4B48_0000;

/// `puts(const char *s)` — `x0` = C string.
pub(super) const KH_HELPER_PUTS: u32 = KH_HELPER_BASE | 1;

/// Minimal `printf(const char *fmt, ...)` — `x0` = format string.
///
/// Supports only format strings **without** `%` conversions (writes the format
/// text as-is). Enough for `printf("hello\n")`.
pub(super) const KH_HELPER_PRINTF: u32 = KH_HELPER_BASE | 2;

/// `readdir` next entry — `x0` = guest fd, `x1` = name buf (256), `x2` = `*u8` d_type.
///
/// Returns `1` if an entry was written, `0` on EOF.
pub(super) const KH_HELPER_READDIR: u32 = KH_HELPER_BASE | 3;

/// `sched_yield` / pthread backoff — no args.
pub(super) const KH_HELPER_YIELD: u32 = KH_HELPER_BASE | 4;

/// Host online CPU count — no args; return value is `ncpu`.
pub(super) const KH_HELPER_NCPU: u32 = KH_HELPER_BASE | 5;

/// Park current host thread while `*u32(addr) == expected` (Linux futex wait).
///
/// `x0` = guest VA of aligned `u32`, `x1` = expected value.
/// Returns 0 on wake / value mismatch / spurious; never hard-fails for park.
pub(super) const KH_HELPER_PARK: u32 = KH_HELPER_BASE | 6;

/// Wake waiters on a park address (Linux futex wake).
///
/// `x0` = guest VA of aligned `u32`, `x1` = max waiters to wake (`0` → all).
pub(super) const KH_HELPER_WAKE: u32 = KH_HELPER_BASE | 7;

const CSTR_MAX: usize = 1 << 20;
const NAME_MAX: usize = 255;

/// True when `number` is a synthetic bottle helper (not Darwin BSD).
#[must_use]
pub(super) const fn is_helper(number: u32) -> bool {
    number & 0xFFFF_0000 == KH_HELPER_BASE
}

/// Dispatches a bottle helper. Unknown helpers → `EINVAL`.
pub(crate) fn dispatch_helper(args: SyscallArgs) -> SyscallResult {
    match args.number {
        KH_HELPER_PUTS => handle_puts(args),
        KH_HELPER_PRINTF => handle_printf(args),
        KH_HELPER_READDIR => handle_readdir(args),
        KH_HELPER_YIELD => handle_yield(),
        KH_HELPER_NCPU => handle_ncpu(),
        KH_HELPER_PARK => handle_park(args),
        KH_HELPER_WAKE => handle_wake(args),
        _ => SyscallResult::err("kh_helper", EINVAL),
    }
}

fn handle_puts(args: SyscallArgs) -> SyscallResult {
    let name = "puts";
    let Some(s) = bottle::read_c_string(args.x0, CSTR_MAX) else {
        return SyscallResult::err(name, EFAULT);
    };
    let mut out = io::stdout().lock();
    if out.write_all(s.as_bytes()).is_err() || out.write_all(b"\n").is_err() {
        return SyscallResult::err(name, EFAULT);
    }
    // POSIX: non-negative on success (we return the string length + newline).
    let n = s.len().saturating_add(1);
    SyscallResult::ok(name, u64::try_from(n).unwrap_or(0))
}

fn handle_printf(args: SyscallArgs) -> SyscallResult {
    let name = "printf";
    let Some(fmt) = bottle::read_c_string(args.x0, CSTR_MAX) else {
        return SyscallResult::err(name, EFAULT);
    };
    // Minimal: no conversions. Reject '%' so we never silently mis-print.
    if fmt.contains('%') {
        return SyscallResult::err(name, EINVAL);
    }
    let mut out = io::stdout().lock();
    if out.write_all(fmt.as_bytes()).is_err() {
        return SyscallResult::err(name, EFAULT);
    }
    SyscallResult::ok(name, u64::try_from(fmt.len()).unwrap_or(0))
}

fn handle_readdir(args: SyscallArgs) -> SyscallResult {
    let name = "kh_readdir";
    let gfd = reg_as_i32(args.x0);
    let name_buf = args.x1;
    let dtype_ptr = args.x2;

    if name_buf == 0 || !registry_check_range(name_buf, NAME_MAX.saturating_add(1), true) {
        return SyscallResult::err(name, EFAULT);
    }

    let next = proc_state::with_mut(|p| p.readdir_next(gfd));
    match next {
        Ok(None) => SyscallResult::ok(name, 0),
        Ok(Some((bytes, d_type))) => {
            let mut out = [0_u8; NAME_MAX.saturating_add(1)];
            let n = bytes.len().min(NAME_MAX);
            if let (Some(dst), Some(src)) = (out.get_mut(..n), bytes.get(..n)) {
                dst.copy_from_slice(src);
            }
            // already zero-terminated via out init
            guest_write(name_buf, &out);
            if dtype_ptr != 0 && registry_check_range(dtype_ptr, 1, true) {
                guest_write(dtype_ptr, &[d_type]);
            }
            SyscallResult::ok(name, 1)
        }
        Err(9) => SyscallResult::err(name, EBADF),
        Err(78) => SyscallResult::err(name, ENOSYS),
        Err(e) => SyscallResult {
            name,
            outcome: crate::trap::TrapOutcome::Continue,
            retval: Some(e.unsigned_abs()),
            error: true,
        },
    }
}

fn handle_yield() -> SyscallResult {
    thread::yield_now();
    SyscallResult::ok("kh_yield", 0)
}

fn handle_ncpu() -> SyscallResult {
    let n = thread::available_parallelism()
        .map_or(1, |n| u64::try_from(n.get()).unwrap_or(1))
        .max(1);
    SyscallResult::ok("kh_ncpu", n)
}

fn handle_park(args: SyscallArgs) -> SyscallResult {
    let name = "kh_park";
    let addr = args.x0;
    let expected = u32::try_from(args.x1 & 0xFFFF_FFFF).unwrap_or(0);
    if addr == 0 || !addr.is_multiple_of(4) || !registry_check_range(addr, 4, false) {
        return SyscallResult::err(name, EFAULT);
    }
    // Identity map: guest VA is host VA.
    let ptr = usize::try_from(addr).unwrap_or(0);
    let u32_ptr = std::ptr::with_exposed_provenance_mut::<u32>(ptr);
    // SAFETY: range checked; identity-mapped guest word.
    let cur = unsafe { core::ptr::read_volatile(u32_ptr) };
    let mismatch = cur != expected;
    note_park(expected, mismatch);
    if !mismatch {
        park_u32(u32_ptr, expected);
    }
    SyscallResult::ok(name, 0)
}

fn handle_wake(args: SyscallArgs) -> SyscallResult {
    let name = "kh_wake";
    let addr = args.x0;
    let n = reg_as_i32(args.x1);
    if addr == 0 || !addr.is_multiple_of(4) || !registry_check_range(addr, 4, false) {
        return SyscallResult::err(name, EFAULT);
    }
    let ptr = usize::try_from(addr).unwrap_or(0);
    let u32_ptr = std::ptr::with_exposed_provenance_mut::<u32>(ptr);
    let count = if n <= 0 { i32::MAX } else { n };
    let woken = wake_u32(u32_ptr, count);
    note_wake(n, woken);
    SyscallResult::ok(name, u64::try_from(woken).unwrap_or(0))
}

/// Block while `*addr == expected` (Linux futex; portable fallback = yield).
///
/// Uses a **bounded wait** (50 ms) so a lost guest wake cannot wedgelock
/// multi-thread `7zz -tzip -mmt≥3` forever. Callers recheck the word in a
/// loop (`pthread_mutex` / `pthread_cond` / join).
fn park_u32(addr: *mut u32, expected: u32) {
    #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
    {
        // SAFETY: guest identity-mapped u32; FUTEX_WAIT returns if value ≠ expected.
        let ts = libc::timespec {
            tv_sec: 0,
            tv_nsec: 50_000_000, // 50 ms safety-net against lost wakeups
        };
        unsafe {
            // SYS_futex = 98 on aarch64 Linux.
            // FUTEX_WAIT_PRIVATE = 0 | 128 — same-process guest threads only.
            let _ = libc::syscall(
                libc::SYS_futex,
                addr,
                128_i32, // FUTEX_WAIT_PRIVATE
                expected,
                core::ptr::from_ref(&ts),
                core::ptr::null_mut::<u32>(),
                0_i32,
            );
        }
    }
    #[cfg(not(all(target_os = "linux", target_arch = "aarch64")))]
    {
        let _ = (addr, expected);
        thread::yield_now();
    }
}

/// Wake up to `n` threads parked on `addr`.
fn wake_u32(addr: *mut u32, n: i32) -> i32 {
    #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
    {
        // SAFETY: same identity-mapped word as park.
        let rc = unsafe {
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
        i32::try_from(rc).unwrap_or(0).max(0)
    }
    #[cfg(not(all(target_os = "linux", target_arch = "aarch64")))]
    {
        let _ = (addr, n);
        0
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn helper_range() {
        assert!(is_helper(KH_HELPER_PUTS));
        assert!(is_helper(KH_HELPER_PRINTF));
        assert!(is_helper(KH_HELPER_READDIR));
        assert!(is_helper(KH_HELPER_YIELD));
        assert!(is_helper(KH_HELPER_NCPU));
        assert!(is_helper(KH_HELPER_PARK));
        assert!(is_helper(KH_HELPER_WAKE));
        assert!(!is_helper(4)); // write
        assert!(!is_helper(1)); // exit
    }
}
