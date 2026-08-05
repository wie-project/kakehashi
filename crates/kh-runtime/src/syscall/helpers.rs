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
    EBADF, EFAULT, EINVAL, ENOSYS, SyscallArgs, SyscallResult, guest_slice, guest_write, reg_as_i32,
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
pub(crate) const KH_HELPER_BASE: u32 = 0x4B48_0000;

/// `puts(const char *s)` — `x0` = C string.
pub(crate) const KH_HELPER_PUTS: u32 = KH_HELPER_BASE | 1;

/// Minimal `printf(const char *fmt, ...)` — `x0` = format string.
///
/// Supports only format strings **without** `%` conversions (writes the format
/// text as-is). Enough for `printf("hello\n")`.
pub(crate) const KH_HELPER_PRINTF: u32 = KH_HELPER_BASE | 2;

/// `readdir` next entry — `x0` = guest fd, `x1` = name buf (256), `x2` = `*u8` d_type.
///
/// Returns `1` if an entry was written, `0` on EOF.
pub(crate) const KH_HELPER_READDIR: u32 = KH_HELPER_BASE | 3;

/// `sched_yield` / pthread backoff — no args.
pub(crate) const KH_HELPER_YIELD: u32 = KH_HELPER_BASE | 4;

/// Host online CPU count — no args; return value is `ncpu`.
pub(crate) const KH_HELPER_NCPU: u32 = KH_HELPER_BASE | 5;

/// Park current host thread while `*u32(addr) == expected` (Linux futex wait).
///
/// `x0` = guest VA of aligned `u32`, `x1` = expected value.
/// Returns 0 on wake / value mismatch / spurious; never hard-fails for park.
pub(crate) const KH_HELPER_PARK: u32 = KH_HELPER_BASE | 6;

/// Wake waiters on a park address (Linux futex wake).
///
/// `x0` = guest VA of aligned `u32`, `x1` = max waiters to wake (`0` → all).
pub(crate) const KH_HELPER_WAKE: u32 = KH_HELPER_BASE | 7;

/// `getaddrinfo` packed into a guest buffer (curl G3).
///
/// `x0` = node C string (nullable), `x1` = service C string (nullable),
/// `x2` = Darwin `AF_*` preference, `x3` = out buffer VA, `x4` = capacity,
/// `x5` = preferred socktype (0 → any).
///
/// Buffer layout: `u32 count` then up to N records of 40 bytes:
/// `family_darwin:u32, socktype:u32, protocol:u32, addrlen:u32, addr[24]`.
/// Addr bytes are **Darwin** sockaddr layout (sa_len + sa_family + …).
pub(crate) const KH_HELPER_GETADDRINFO: u32 = KH_HELPER_BASE | 8;

/// TLS cert chain verify against the bottle CA bundle (SecTrust soft path).
///
/// Packed buffer at `x0` (`x1` = byte length):
/// ```text
/// u32 hostname_len; hostname bytes (no NUL required)
/// u32 n_certs;
/// for each cert: u32 der_len; der bytes
/// ```
/// Leaf is certs[0], intermediates follow. Returns `0` on success, `1` on
/// soft verify failure (maps to SecTrust false), other negative as errno-ish.
pub(crate) const KH_HELPER_VERIFY_CERT: u32 = KH_HELPER_BASE | 9;

/// Guest HOME path for freestanding `getenv` / soft env seed.
///
/// `x0` = out buffer VA, `x1` = capacity (incl. NUL). Writes
/// `/Volumes/linux{host $HOME}` when host HOME is absolute, else `/var/root`.
/// Returns byte length **including** NUL, or error via carry/`EINVAL`.
pub(crate) const KH_HELPER_GUEST_HOME: u32 = KH_HELPER_BASE | 0x0A;

const CSTR_MAX: usize = 1 << 20;
const NAME_MAX: usize = 255;
const GAI_REC: usize = 40;
const GAI_MAX: usize = 16;
const VERIFY_MAX_BUF: usize = 1 << 20;
const VERIFY_MAX_CERTS: usize = 16;

/// True when `number` is a synthetic bottle helper (not Darwin BSD).
#[must_use]
pub(crate) const fn is_helper(number: u32) -> bool {
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
        KH_HELPER_GETADDRINFO => handle_getaddrinfo(args),
        KH_HELPER_VERIFY_CERT => handle_verify_cert(args),
        KH_HELPER_GUEST_HOME => handle_guest_home(args),
        _ => SyscallResult::err("kh_helper", EINVAL),
    }
}

fn handle_guest_home(args: SyscallArgs) -> SyscallResult {
    let name = "kh_guest_home";
    let ptr = args.x0;
    let Ok(cap) = usize::try_from(args.x1) else {
        return SyscallResult::err(name, EINVAL);
    };
    if ptr == 0 || cap == 0 || !registry_check_range(ptr, cap, true) {
        return SyscallResult::err(name, EFAULT);
    }
    let path = match std::env::var("HOME") {
        Ok(h) if h.starts_with('/') && !h.contains('\0') => format!("/Volumes/linux{h}"),
        _ => "/var/root".to_owned(),
    };
    let bytes = path.as_bytes();
    // Need room for path + NUL.
    if bytes.len().saturating_add(1) > cap {
        return SyscallResult::err(name, EINVAL);
    }
    let mut out = vec![0_u8; bytes.len().saturating_add(1)];
    if let Some(dst) = out.get_mut(..bytes.len()) {
        dst.copy_from_slice(bytes);
    }
    guest_write(ptr, &out);
    SyscallResult::ok(
        name,
        u64::try_from(out.len()).unwrap_or(0),
    )
}

fn handle_verify_cert(args: SyscallArgs) -> SyscallResult {
    let name = "kh_verify_cert";
    let ptr = args.x0;
    let Ok(len) = usize::try_from(args.x1) else {
        return SyscallResult::err(name, EINVAL);
    };
    if ptr == 0 || len == 0 || len > VERIFY_MAX_BUF || !registry_check_range(ptr, len, false) {
        return SyscallResult::err(name, EFAULT);
    }
    let buf = guest_slice(ptr, len);

    let Some(ca) = crate::bottle::active_ca_pem_path().or_else(|| {
        // Fresh ensure may have just written it relative to bottle_root TLS.
        crate::bottle::bottle_root().and_then(|r| {
            let p = r.join(crate::bottle::GUEST_CA_FILE_REL);
            p.is_file().then_some(p)
        })
    }) else {
        tracing::warn!("tls verify: no bottle CA bundle");
        return SyscallResult::ok(name, 1);
    };

    let mut off = 0_usize;
    let Some(host_len) = read_u32(buf, &mut off) else {
        return SyscallResult::err(name, EINVAL);
    };
    let host_len = usize::try_from(host_len).unwrap_or(0);
    if host_len > 255 || off.saturating_add(host_len) > buf.len() {
        return SyscallResult::err(name, EINVAL);
    }
    let hostname = match buf.get(off..off.saturating_add(host_len)) {
        Some(s) => match std::str::from_utf8(s) {
            Ok(h) => h,
            Err(_) => return SyscallResult::err(name, EINVAL),
        },
        None => return SyscallResult::err(name, EINVAL),
    };
    off = off.saturating_add(host_len);

    let Some(n_certs) = read_u32(buf, &mut off) else {
        return SyscallResult::err(name, EINVAL);
    };
    let n_certs = usize::try_from(n_certs).unwrap_or(0);
    if n_certs == 0 || n_certs > VERIFY_MAX_CERTS {
        return SyscallResult::err(name, EINVAL);
    }

    let mut ders: Vec<Vec<u8>> = Vec::with_capacity(n_certs);
    for _ in 0..n_certs {
        let Some(der_len) = read_u32(buf, &mut off) else {
            return SyscallResult::err(name, EINVAL);
        };
        let der_len = usize::try_from(der_len).unwrap_or(0);
        if der_len == 0 || der_len > (1 << 18) || off.saturating_add(der_len) > buf.len() {
            return SyscallResult::err(name, EINVAL);
        }
        let Some(slice) = buf.get(off..off.saturating_add(der_len)) else {
            return SyscallResult::err(name, EINVAL);
        };
        ders.push(slice.to_vec());
        off = off.saturating_add(der_len);
    }

    let Some(leaf) = ders.first() else {
        return SyscallResult::err(name, EINVAL);
    };
    let inters: Vec<&[u8]> = ders.iter().skip(1).map(Vec::as_slice).collect();
    match crate::tls_verify::verify_der_chain(&ca, hostname, leaf, &inters) {
        Ok(()) => SyscallResult::ok(name, 0),
        Err(msg) => {
            tracing::warn!(%msg, "tls verify fail");
            SyscallResult::ok(name, 1)
        }
    }
}

fn read_u32(buf: &[u8], off: &mut usize) -> Option<u32> {
    let start = *off;
    let end = start.checked_add(4)?;
    let bytes = buf.get(start..end)?;
    *off = end;
    Some(u32::from_le_bytes(bytes.try_into().ok()?))
}

fn gai_put_u32(rec: &mut [u8], off: usize, v: u32) {
    if let Some(dst) = rec.get_mut(off..off.saturating_add(4))
        && dst.len() == 4
    {
        dst.copy_from_slice(&v.to_le_bytes());
    }
}

fn gai_put_bytes(rec: &mut [u8], off: usize, src: &[u8]) {
    if let Some(dst) = rec.get_mut(off..off.saturating_add(src.len()))
        && dst.len() == src.len()
    {
        dst.copy_from_slice(src);
    }
}

fn gai_put_u8(rec: &mut [u8], off: usize, v: u8) {
    if let Some(slot) = rec.get_mut(off) {
        *slot = v;
    }
}

fn handle_getaddrinfo(args: SyscallArgs) -> SyscallResult {
    use std::net::{SocketAddr, ToSocketAddrs};

    let name = "kh_getaddrinfo";
    let node = if args.x0 == 0 {
        None
    } else {
        match bottle::read_c_string(args.x0, CSTR_MAX) {
            Some(s) => Some(s),
            None => return SyscallResult::err(name, EFAULT),
        }
    };
    let service = if args.x1 == 0 {
        None
    } else {
        match bottle::read_c_string(args.x1, CSTR_MAX) {
            Some(s) => Some(s),
            None => return SyscallResult::err(name, EFAULT),
        }
    };
    tracing::debug!(
        node = ?node.as_deref(),
        service = ?service.as_deref(),
        family = reg_as_i32(args.x2),
        "getaddrinfo"
    );
    let family = reg_as_i32(args.x2);
    let out = args.x3;
    let Ok(cap) = usize::try_from(args.x4) else {
        return SyscallResult::err(name, EINVAL);
    };
    let socktype = reg_as_i32(args.x5);
    let min_cap = 4_usize.saturating_add(GAI_REC);
    if out == 0 || cap < min_cap || !registry_check_range(out, cap, true) {
        return SyscallResult::err(name, EFAULT);
    }

    // EAI_NONAME = 8 on Darwin when nothing to resolve.
    let host_s = node.as_deref().unwrap_or("localhost");
    let port_s = service.as_deref().unwrap_or("0");
    let target = format!("{host_s}:{port_s}");

    let addrs: Vec<SocketAddr> = match target.to_socket_addrs() {
        Ok(iter) => iter.collect(),
        Err(_) => {
            if let (Some(h), Some(p)) = (node.as_deref(), service.as_deref()) {
                if let Ok(port) = p.parse::<u16>() {
                    if let Ok(ip) = h.parse::<std::net::IpAddr>() {
                        vec![SocketAddr::new(ip, port)]
                    } else {
                        return SyscallResult::err(name, 8);
                    }
                } else {
                    return SyscallResult::err(name, 8);
                }
            } else {
                return SyscallResult::err(name, 8);
            }
        }
    };

    let want_v4 = family == 0 || family == 2;
    let want_v6 = family == 0 || family == 30;
    let st: i32 = if socktype == 0 { 1 } else { socktype };
    let proto: i32 = if st == 1 { 6 } else { 0 };
    let st_u = st.cast_unsigned();
    let proto_u = proto.cast_unsigned();

    let mut records: Vec<[u8; GAI_REC]> = Vec::new();
    for addr in addrs {
        if records.len() >= GAI_MAX {
            break;
        }
        match addr {
            SocketAddr::V4(v4) if want_v4 => {
                let mut rec = [0_u8; GAI_REC];
                gai_put_u32(&mut rec, 0, 2); // AF_INET
                gai_put_u32(&mut rec, 4, st_u);
                gai_put_u32(&mut rec, 8, proto_u);
                gai_put_u32(&mut rec, 12, 16);
                gai_put_u8(&mut rec, 16, 16); // sa_len
                gai_put_u8(&mut rec, 17, 2); // AF_INET
                gai_put_bytes(&mut rec, 18, &v4.port().to_be_bytes());
                gai_put_bytes(&mut rec, 20, &v4.ip().octets());
                records.push(rec);
            }
            SocketAddr::V6(v6) if want_v6 => {
                let mut rec = [0_u8; GAI_REC];
                gai_put_u32(&mut rec, 0, 30); // AF_INET6
                gai_put_u32(&mut rec, 4, st_u);
                gai_put_u32(&mut rec, 8, proto_u);
                gai_put_u32(&mut rec, 12, 28);
                gai_put_u8(&mut rec, 16, 28);
                gai_put_u8(&mut rec, 17, 30);
                gai_put_bytes(&mut rec, 18, &v6.port().to_be_bytes());
                // flowinfo stays zero at 20..24
                gai_put_bytes(&mut rec, 24, &v6.ip().octets());
                records.push(rec);
            }
            _ => {}
        }
    }

    if records.is_empty() {
        return SyscallResult::err(name, 8);
    }

    let need = 4_usize.saturating_add(records.len().saturating_mul(GAI_REC));
    if need > cap {
        return SyscallResult::err(name, 12);
    }
    let count = u32::try_from(records.len()).unwrap_or(0);
    guest_write(out, &count.to_le_bytes());
    for (i, rec) in records.iter().enumerate() {
        let off = 4_usize.saturating_add(i.saturating_mul(GAI_REC));
        guest_write(out.wrapping_add(u64::try_from(off).unwrap_or(0)), rec);
    }
    SyscallResult::ok(name, u64::from(count))
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
        assert!(is_helper(KH_HELPER_VERIFY_CERT));
        assert!(!is_helper(4)); // write
        assert!(!is_helper(1)); // exit
    }
}
