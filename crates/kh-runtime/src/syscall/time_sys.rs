//! Time-related BSD syscalls: `gettimeofday`, `clock_gettime`.

use crate::host;
use crate::mem::registry_check_range;

use super::common::{EFAULT, EINVAL, SyscallArgs, SyscallResult, guest_write, reg_as_i32};

/// Darwin `struct timeval` (arm64): `time_t tv_sec` + `suseconds_t tv_usec` + pad.
const TIMEVAL_SIZE: usize = 16;
/// Darwin `struct timespec` (arm64): `time_t tv_sec` + `long tv_nsec`.
const TIMESPEC_SIZE: usize = 16;

/// Darwin `clockid_t` values (subset; differ from Linux).
const CLOCK_REALTIME: i32 = 0;
const CLOCK_MONOTONIC: i32 = 6;
const CLOCK_MONOTONIC_RAW: i32 = 4;
const CLOCK_MONOTONIC_RAW_APPROX: i32 = 5;
const CLOCK_UPTIME_RAW: i32 = 8;
const CLOCK_UPTIME_RAW_APPROX: i32 = 9;
const CLOCK_PROCESS_CPUTIME_ID: i32 = 12;
const CLOCK_THREAD_CPUTIME_ID: i32 = 16;

/// `gettimeofday(tp, tzp)` — `x0` = `timeval*`, `x1` = timezone (ignored / optional).
pub(crate) fn handle_gettimeofday(args: SyscallArgs) -> SyscallResult {
    let name = "gettimeofday";
    // NULL tp is allowed on Darwin (returns success with no write).
    if args.x0 != 0 {
        if !registry_check_range(args.x0, TIMEVAL_SIZE, true) {
            return SyscallResult::err(name, EFAULT);
        }
        let Some(tv) = host::gettimeofday() else {
            return SyscallResult::err(name, EINVAL);
        };
        write_darwin_timeval(args.x0, widen_i64(tv.tv_sec), widen_i64(tv.tv_usec));
    }
    let _ = args.x1;
    SyscallResult::ok(name, 0)
}

/// `clock_gettime(clock_id, tp)`.
pub(crate) fn handle_clock_gettime(args: SyscallArgs) -> SyscallResult {
    let name = "clock_gettime";
    let clock_id = reg_as_i32(args.x0);
    if args.x1 == 0 {
        return SyscallResult::err(name, EFAULT);
    }
    if !registry_check_range(args.x1, TIMESPEC_SIZE, true) {
        return SyscallResult::err(name, EFAULT);
    }
    let Some(host_clock) = darwin_to_host_clock(clock_id) else {
        return SyscallResult::err(name, EINVAL);
    };
    let Some(ts) = host::clock_gettime(host_clock) else {
        return SyscallResult::err(name, EINVAL);
    };
    write_darwin_timespec(args.x1, widen_i64(ts.tv_sec), widen_i64(ts.tv_nsec));
    SyscallResult::ok(name, 0)
}

fn darwin_to_host_clock(id: i32) -> Option<libc::clockid_t> {
    match id {
        CLOCK_REALTIME => Some(libc::CLOCK_REALTIME),
        CLOCK_MONOTONIC
        | CLOCK_MONOTONIC_RAW
        | CLOCK_MONOTONIC_RAW_APPROX
        | CLOCK_UPTIME_RAW
        | CLOCK_UPTIME_RAW_APPROX => Some(libc::CLOCK_MONOTONIC),
        CLOCK_PROCESS_CPUTIME_ID => Some(libc::CLOCK_PROCESS_CPUTIME_ID),
        CLOCK_THREAD_CPUTIME_ID => Some(libc::CLOCK_THREAD_CPUTIME_ID),
        _ => None,
    }
}

/// Widen host integer time fields to `i64` without host-specific casts.
fn widen_i64<T>(v: T) -> i64
where
    T: Copy + TryInto<i64>,
{
    v.try_into().unwrap_or(0)
}

fn write_darwin_timeval(addr: u64, sec: i64, usec: i64) {
    let usec_i = i32::try_from(usec).unwrap_or(0);
    // Layout: i64 tv_sec, i32 tv_usec, 4 pad (arm64 Darwin).
    let mut raw = [0_u8; TIMEVAL_SIZE];
    if let Some(slot) = raw.get_mut(..8) {
        slot.copy_from_slice(&sec.to_le_bytes());
    }
    if let Some(slot) = raw.get_mut(8..12) {
        slot.copy_from_slice(&usec_i.to_le_bytes());
    }
    guest_write(addr, &raw);
}

fn write_darwin_timespec(addr: u64, sec: i64, nsec: i64) {
    let mut raw = [0_u8; TIMESPEC_SIZE];
    if let Some(slot) = raw.get_mut(..8) {
        slot.copy_from_slice(&sec.to_le_bytes());
    }
    if let Some(slot) = raw.get_mut(8..16) {
        slot.copy_from_slice(&nsec.to_le_bytes());
    }
    guest_write(addr, &raw);
}
