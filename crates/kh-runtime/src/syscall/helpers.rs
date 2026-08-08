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

/// Host dig/bench flag: non-zero when host `KAKEHASHI_HEAP_STATS` is truthy.
///
/// Freestanding cannot read host env; this is the opt-in path for heap dump
/// (replaces dig-time always-on seed).
pub(crate) const KH_HELPER_HEAP_STATS_ON: u32 = KH_HELPER_BASE | 0x0B;

/// Freestanding libcurl HTTP(S) perform — `x0` = guest VA of packed `KhHttpReq`.
///
/// Layout (LE, all fields `u32`/`u64` as documented in `kh-libsystem` curl.rs):
/// magic, version, method, flags, url, headers, headers_len, body, body_len,
/// ca_path, out_body, out_body_cap, out_body_len, out_code, errbuf, errbuf_cap.
///
/// Host runs system `curl` with bottle CA (or guest `ca_path`). Returns 0 on
/// success; negative errno-ish on failure.
pub(crate) const KH_HELPER_HTTP: u32 = KH_HELPER_BASE | 0x0C;

/// Host `getenv` for freestanding soft-env seed (nested `GIT_*` after re-exec).
///
/// `x0` = key C string VA, `x1` = out buffer VA, `x2` = capacity (incl. NUL).
/// Returns byte length **including** NUL when found; `0` if unset / too long.
pub(crate) const KH_HELPER_GETENV: u32 = KH_HELPER_BASE | 0x0D;

/// Host `regcomp` — `x0` = pattern C string, `x1` = Darwin cflags,
/// `x2` = out guest VA of two `u64`s: `[handle, re_nsub]`.
/// Returns `0` or a positive Darwin `REG_*` code (not errno carry).
pub(crate) const KH_HELPER_REGCOMP: u32 = KH_HELPER_BASE | 0x0E;

/// Host `regexec` — `x0` = guest VA of packed request
/// `{handle, string, nmatch, pmatch, eflags}` (5×`u64` LE).
/// Returns `0` / `REG_NOMATCH` / other `REG_*`.
pub(crate) const KH_HELPER_REGEXEC: u32 = KH_HELPER_BASE | 0x0F;

/// Host `regfree` — `x0` = handle from `REGCOMP`.
pub(crate) const KH_HELPER_REGFREE: u32 = KH_HELPER_BASE | 0x10;

/// TLS connect for freestanding libcurl (path B): host TCP + rustls handshake.
///
/// `x0` = guest VA of packed `KhTlsConnect` (LE):
/// ```text
/// u32 magic = 0x4B48_544C  // "KHTL"
/// u32 version = 1
/// u32 flags    // bit0 = verify peer (TLS_FLAG_VERIFY)
///              // bit1 = plain TCP only (TLS_FLAG_PLAIN; freestanding http://)
/// u32 port
/// u64 hostname_va, hostname_len
/// u64 ca_path_va   // 0 → bottle CA when verify; ignored when PLAIN
/// u64 out_fd_va    // writes i32 guest fd
/// u64 errbuf_va, errbuf_cap
/// ```
/// Returns 0 on success; negative errno-ish on failure.
pub(crate) const KH_HELPER_TLS_CONNECT: u32 = KH_HELPER_BASE | 0x11;

/// Guest main executable path for freestanding `_NSGetExecutablePath`.
///
/// `x0` = out buffer VA, `x1` = capacity (incl. NUL). Writes guest absolute
/// path (e.g. `/Library/Developer/CommandLineTools/usr/bin/clang`). Returns
/// byte length **including** NUL, or `0` if unset / too small.
pub(crate) const KH_HELPER_EXECUTABLE_PATH: u32 = KH_HELPER_BASE | 0x12;

/// Freestanding `dlopen`: `x0` = path C string VA (0 = main).
/// Returns opaque handle, or 0 if no mapped image matches.
pub(crate) const KH_HELPER_DLOPEN: u32 = KH_HELPER_BASE | 0x13;

/// Freestanding `dlsym`: `x0` = handle, `x1` = symbol name VA.
/// Returns guest VA, or 0 if missing.
pub(crate) const KH_HELPER_DLSYM: u32 = KH_HELPER_BASE | 0x14;

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
        KH_HELPER_HEAP_STATS_ON => handle_heap_stats_on(),
        KH_HELPER_HTTP => handle_http(args),
        KH_HELPER_GETENV => handle_getenv(args),
        KH_HELPER_REGCOMP => handle_regcomp(args),
        KH_HELPER_REGEXEC => handle_regexec(args),
        KH_HELPER_REGFREE => handle_regfree(args),
        KH_HELPER_TLS_CONNECT => handle_tls_connect(args),
        KH_HELPER_EXECUTABLE_PATH => handle_executable_path(args),
        KH_HELPER_DLOPEN => handle_dlopen(args),
        KH_HELPER_DLSYM => handle_dlsym(args),
        _ => SyscallResult::err("kh_helper", EINVAL),
    }
}

fn handle_dlopen(args: SyscallArgs) -> SyscallResult {
    let name = "kh_dlopen";
    let path_va = args.x0;
    // dlopen(NULL) → treat as RTLD_DEFAULT search handle (main is not special).
    if path_va == 0 {
        return SyscallResult::ok(name, crate::dyld_table::RTLD_DEFAULT);
    }
    let Some(guest_path) = bottle::read_c_string(path_va, CSTR_MAX) else {
        return SyscallResult::err(name, EFAULT);
    };
    let host = bottle::translate_path(&guest_path).ok();
    if let Some(h) = crate::dyld_table::dlopen_lookup(host.as_deref(), &guest_path) {
        SyscallResult::ok(name, h)
    } else {
        // Not mapped yet — soft fail (no on-demand load of 150 MiB plugins).
        tracing::debug!(guest = %guest_path, "dlopen: no mapped image");
        SyscallResult::ok(name, 0)
    }
}

fn handle_dlsym(args: SyscallArgs) -> SyscallResult {
    let name = "kh_dlsym";
    let handle = args.x0;
    let sym_va = args.x1;
    let Some(sym) = bottle::read_c_string(sym_va, CSTR_MAX) else {
        return SyscallResult::err(name, EFAULT);
    };
    if let Some(va) = crate::dyld_table::dlsym_lookup(handle, &sym) {
        SyscallResult::ok(name, va)
    } else {
        SyscallResult::ok(name, 0)
    }
}

const KHTLS_MAGIC: u32 = 0x4B48_544C; // KHTL
const KHTLS_REQ_BYTES: usize = 64; // 4×u32 + 6×u64

fn handle_tls_connect(args: SyscallArgs) -> SyscallResult {
    let name = "kh_tls_connect";
    let req_va = args.x0;
    if req_va == 0 || !registry_check_range(req_va, KHTLS_REQ_BYTES, false) {
        return SyscallResult::err(name, EFAULT);
    }
    let req = guest_slice(req_va, KHTLS_REQ_BYTES);
    let read_u32 = |off: usize| -> u32 {
        let end = off.saturating_add(4);
        req.get(off..end)
            .and_then(|b| b.try_into().ok())
            .map_or(0, u32::from_le_bytes)
    };
    let read_u64 = |off: usize| -> u64 {
        let end = off.saturating_add(8);
        req.get(off..end)
            .and_then(|b| b.try_into().ok())
            .map_or(0, u64::from_le_bytes)
    };

    let magic = read_u32(0);
    let version = read_u32(4);
    let flags = read_u32(8);
    let port = read_u32(12);
    let hostname_va = read_u64(16);
    let hostname_len = usize::try_from(read_u64(24)).unwrap_or(0);
    let ca_va = read_u64(32);
    let out_fd_va = read_u64(40);
    let errbuf_va = read_u64(48);
    let errbuf_cap = usize::try_from(read_u64(56)).unwrap_or(0);

    let write_err = |msg: &str| {
        if errbuf_va != 0 && errbuf_cap > 0 && registry_check_range(errbuf_va, errbuf_cap, true) {
            let mut bytes = msg.as_bytes().to_vec();
            if bytes.len() >= errbuf_cap {
                bytes.truncate(errbuf_cap.saturating_sub(1));
            }
            bytes.push(0);
            guest_write(errbuf_va, &bytes);
        }
    };

    if magic != KHTLS_MAGIC || version != 1 {
        write_err("bad tls connect magic/version");
        return SyscallResult::err(name, EINVAL);
    }
    if port == 0 || port > u32::from(u16::MAX) {
        write_err("bad port");
        return SyscallResult::err(name, EINVAL);
    }
    if hostname_va == 0 || hostname_len == 0 || hostname_len > 255 {
        write_err("bad hostname");
        return SyscallResult::err(name, EINVAL);
    }
    if !registry_check_range(hostname_va, hostname_len, false) {
        write_err("hostname EFAULT");
        return SyscallResult::err(name, EFAULT);
    }
    if out_fd_va == 0 || !registry_check_range(out_fd_va, 4, true) {
        return SyscallResult::err(name, EFAULT);
    }

    let host_bytes = guest_slice(hostname_va, hostname_len);
    let Ok(hostname) = std::str::from_utf8(host_bytes) else {
        write_err("hostname not utf8");
        return SyscallResult::err(name, EINVAL);
    };

    let ca_host = if ca_va != 0 {
        bottle::read_c_string(ca_va, CSTR_MAX).and_then(|guest_path| {
            bottle::translate_path(&guest_path)
                .ok()
                .filter(|p| p.is_file())
        })
    } else {
        None
    };
    let ca_host = ca_host.or_else(|| {
        bottle::active_ca_pem_path().or_else(|| {
            bottle::bottle_root().and_then(|r| {
                let p = r.join(crate::bottle::GUEST_CA_FILE_REL);
                p.is_file().then_some(p)
            })
        })
    });

    let port_u16 = u16::try_from(port).unwrap_or(0);
    match crate::tls_fd::connect(hostname, port_u16, flags, ca_host.as_deref()) {
        Ok(gfd) => {
            guest_write(out_fd_va, &gfd.to_le_bytes());
            SyscallResult::ok(name, 0)
        }
        Err(e) => {
            write_err(&e);
            // Prefer connect-ish / SSL-ish errno codes freestanding curl maps.
            let lower = e.to_ascii_lowercase();
            let err = if lower.contains("certificate")
                || lower.contains("tls")
                || lower.contains("ssl")
                || lower.contains("handshake")
            {
                35 // CURLE_SSL_CONNECT_ERROR mapped later
            } else if lower.contains("timed out") || lower.contains("timeout") {
                28
            } else {
                7 // connect failure
            };
            SyscallResult::err(name, i64::from(err))
        }
    }
}

const KHHTTP_MAGIC: u32 = 0x4B48_4854;
const KHHTTP_FLAG_SSL_VERIFY: u32 = 1;
const HTTP_MAX_BODY: usize = 64 * 1024 * 1024;
const HTTP_MAX_HDR: usize = 64 * 1024;
/// `KhHttpReq` v1: 4×u32 + 12×u64 = 112; v2 adds content-type out → 128.
const HTTP_REQ_BYTES_V1: usize = 112;
const HTTP_REQ_BYTES_V2: usize = 128;

fn handle_http(args: SyscallArgs) -> SyscallResult {
    use std::process::Command;

    let name = "kh_http";
    let req_va = args.x0;
    // Peek version with a short read so older guests (v1) still work.
    if req_va == 0 || !registry_check_range(req_va, HTTP_REQ_BYTES_V1, false) {
        return SyscallResult::err(name, EFAULT);
    }
    let peek = guest_slice(req_va, HTTP_REQ_BYTES_V1);
    let version_peek = peek
        .get(4..8)
        .and_then(|b| b.try_into().ok())
        .map_or(0_u32, u32::from_le_bytes);
    let req_bytes = if version_peek >= 2 {
        HTTP_REQ_BYTES_V2
    } else {
        HTTP_REQ_BYTES_V1
    };
    if !registry_check_range(req_va, req_bytes, false) {
        return SyscallResult::err(name, EFAULT);
    }
    let req = guest_slice(req_va, req_bytes);
    let read_u32 = |off: usize| -> u32 {
        let end = off.saturating_add(4);
        req.get(off..end)
            .and_then(|b| b.try_into().ok())
            .map_or(0, u32::from_le_bytes)
    };
    let magic = read_u32(0);
    let version = read_u32(4);
    let method = read_u32(8);
    let flags = read_u32(12);
    if magic != KHHTTP_MAGIC || !(1..=2).contains(&version) {
        return SyscallResult::err(name, EINVAL);
    }

    let read_u64 = |off: usize| -> u64 {
        let end = off.saturating_add(8);
        req.get(off..end)
            .and_then(|b| b.try_into().ok())
            .map_or(0, u64::from_le_bytes)
    };

    let url_va = read_u64(16);
    let headers_va = read_u64(24);
    let headers_len = usize::try_from(read_u64(32)).unwrap_or(0);
    let body_va = read_u64(40);
    let body_len = usize::try_from(read_u64(48)).unwrap_or(0);
    let ca_va = read_u64(56);
    let out_body_va = read_u64(64);
    let out_body_cap = usize::try_from(read_u64(72)).unwrap_or(0);
    let out_body_len_va = read_u64(80);
    let out_code_va = read_u64(88);
    let errbuf_va = read_u64(96);
    let errbuf_cap = usize::try_from(read_u64(104)).unwrap_or(0);
    let out_ctype_va = if version >= 2 { read_u64(112) } else { 0 };
    let out_ctype_cap = if version >= 2 {
        usize::try_from(read_u64(120)).unwrap_or(0)
    } else {
        0
    };

    let write_err = |msg: &str| {
        if errbuf_va != 0 && errbuf_cap > 0 && registry_check_range(errbuf_va, errbuf_cap, true) {
            let mut bytes = msg.as_bytes().to_vec();
            if bytes.len() >= errbuf_cap {
                bytes.truncate(errbuf_cap.saturating_sub(1));
            }
            bytes.push(0);
            guest_write(errbuf_va, &bytes);
        }
    };

    let Some(url) = bottle::read_c_string(url_va, CSTR_MAX) else {
        write_err("bad url");
        return SyscallResult::err(name, EFAULT);
    };
    if url.is_empty() {
        write_err("empty url");
        return SyscallResult::err(name, EINVAL);
    }

    if out_body_va == 0
        || out_body_cap == 0
        || out_body_cap > HTTP_MAX_BODY
        || !registry_check_range(out_body_va, out_body_cap, true)
    {
        write_err("bad out body");
        return SyscallResult::err(name, EFAULT);
    }
    if out_body_len_va == 0 || !registry_check_range(out_body_len_va, 8, true) {
        return SyscallResult::err(name, EFAULT);
    }
    if out_code_va == 0 || !registry_check_range(out_code_va, 4, true) {
        return SyscallResult::err(name, EFAULT);
    }

    let headers = if headers_va != 0 && headers_len > 0 && headers_len <= HTTP_MAX_HDR {
        if !registry_check_range(headers_va, headers_len, false) {
            write_err("bad headers");
            return SyscallResult::err(name, EFAULT);
        }
        Some(guest_slice(headers_va, headers_len).to_vec())
    } else {
        None
    };

    let body = if body_va != 0 && body_len > 0 && body_len <= HTTP_MAX_BODY {
        if !registry_check_range(body_va, body_len, false) {
            write_err("bad body");
            return SyscallResult::err(name, EFAULT);
        }
        Some(guest_slice(body_va, body_len).to_vec())
    } else {
        None
    };

    // Resolve CA: guest path → host, else bottle CA bundle.
    let ca_host = if ca_va != 0 {
        bottle::read_c_string(ca_va, CSTR_MAX).and_then(|guest_path| {
            bottle::translate_path(&guest_path)
                .ok()
                .filter(|p| p.is_file())
                .map(|p| p.display().to_string())
        })
    } else {
        None
    };
    let ca_host = ca_host.or_else(|| {
        bottle::active_ca_pem_path()
            .or_else(|| {
                bottle::bottle_root().and_then(|r| {
                    let p = r.join(crate::bottle::GUEST_CA_FILE_REL);
                    p.is_file().then_some(p)
                })
            })
            .map(|p| p.display().to_string())
    });

    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let tmp = std::env::temp_dir().join(format!("kh-http-{}-{nanos}", std::process::id()));
    let body_path = tmp.with_extension("body");
    let hdr_path = tmp.with_extension("hdr");
    let post_path = tmp.with_extension("post");

    let method_flag = match method {
        1 => "POST",
        2 => "HEAD",
        3 => "PUT",
        _ => "GET",
    };

    let mut cmd = Command::new("curl");
    cmd.arg("-sS")
        .arg("-L")
        .arg("-X")
        .arg(method_flag)
        .arg("-D")
        .arg(&hdr_path)
        .arg("-o")
        .arg(&body_path)
        .arg("-w")
        .arg("%{http_code}");
    if (flags & KHHTTP_FLAG_SSL_VERIFY) == 0 {
        cmd.arg("-k");
    } else if let Some(ref ca) = ca_host {
        cmd.arg("--cacert").arg(ca);
    }
    if let Some(ref hdrs) = headers {
        for line in hdrs.split(|b| *b == b'\n' || *b == 0) {
            if line.is_empty() {
                continue;
            }
            if let Ok(s) = std::str::from_utf8(line) {
                let t = s.trim();
                if !t.is_empty() {
                    cmd.arg("-H").arg(t);
                }
            }
        }
    }
    if let Some(ref b) = body {
        if let Err(e) = std::fs::write(&post_path, b) {
            write_err(&format!("post body write: {e}"));
            return SyscallResult::err(name, EINVAL);
        }
        cmd.arg("--data-binary")
            .arg(format!("@{}", post_path.display()));
    }
    cmd.arg(&url);

    tracing::debug!(%url, method = method_flag, "kh_http host curl");

    let output = match cmd.output() {
        Ok(o) => o,
        Err(e) => {
            write_err(&format!("spawn curl: {e}"));
            cleanup_http_tmp(&body_path, &hdr_path, &post_path);
            return SyscallResult::err(name, ENOSYS);
        }
    };

    let code_str = String::from_utf8_lossy(&output.stdout);
    let http_code: u32 = code_str.trim().parse().unwrap_or(0);

    if !output.status.success() && http_code == 0 {
        let stderr = String::from_utf8_lossy(&output.stderr);
        write_err(stderr.trim());
        cleanup_http_tmp(&body_path, &hdr_path, &post_path);
        // Map common curl failures.
        let msg = stderr.to_ascii_lowercase();
        let err = if msg.contains("timed out") || msg.contains("timeout") {
            28
        } else if msg.contains("ssl") || msg.contains("certificate") {
            35
        } else {
            7
        };
        return SyscallResult::err(name, i64::from(err));
    }

    let body_bytes = std::fs::read(&body_path).unwrap_or_default();
    if body_bytes.len() > out_body_cap {
        write_err("response too large for guest buffer");
        cleanup_http_tmp(&body_path, &hdr_path, &post_path);
        return SyscallResult::err(name, EINVAL);
    }
    guest_write(out_body_va, &body_bytes);
    let len_u64 = u64::try_from(body_bytes.len()).unwrap_or(0);
    guest_write(out_body_len_va, &len_u64.to_le_bytes());
    guest_write(out_code_va, &http_code.to_le_bytes());

    // Content-Type for CURLINFO_CONTENT_TYPE (git smart-HTTP discovery).
    if out_ctype_va != 0
        && out_ctype_cap > 0
        && registry_check_range(out_ctype_va, out_ctype_cap, true)
    {
        let ctype = std::fs::read(&hdr_path)
            .ok()
            .and_then(|raw| parse_content_type_header(&raw))
            .unwrap_or_default();
        let mut bytes = ctype.into_bytes();
        if bytes.len() >= out_ctype_cap {
            bytes.truncate(out_ctype_cap.saturating_sub(1));
        }
        bytes.push(0);
        guest_write(out_ctype_va, &bytes);
    }

    cleanup_http_tmp(&body_path, &hdr_path, &post_path);
    SyscallResult::ok(name, 0)
}

/// Extract `Content-Type` value from an HTTP response header block (`curl -D`).
fn parse_content_type_header(raw: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(raw).ok()?;
    for line in text.lines() {
        let line = line.trim();
        let Some(rest) = line
            .strip_prefix("Content-Type:")
            .or_else(|| line.strip_prefix("content-type:"))
            .or_else(|| line.strip_prefix("CONTENT-TYPE:"))
        else {
            continue;
        };
        // Take media type before any `; charset=…`.
        let value = rest.split(';').next().unwrap_or(rest).trim();
        if !value.is_empty() {
            return Some(value.to_owned());
        }
    }
    None
}

fn cleanup_http_tmp(body: &std::path::Path, hdr: &std::path::Path, post: &std::path::Path) {
    drop(std::fs::remove_file(body));
    drop(std::fs::remove_file(hdr));
    drop(std::fs::remove_file(post));
}

fn handle_heap_stats_on() -> SyscallResult {
    let name = "kh_heap_stats_on";
    let on = match std::env::var_os("KAKEHASHI_HEAP_STATS") {
        None => false,
        Some(v) => {
            !(v.is_empty()
                || v == "0"
                || v.eq_ignore_ascii_case("false")
                || v.eq_ignore_ascii_case("no")
                || v.eq_ignore_ascii_case("off"))
        }
    };
    SyscallResult::ok(name, u64::from(on))
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
        // Nested re-exec already has guest HOME in the host environ.
        Ok(h) if h.starts_with("/Volumes/linux") && !h.contains('\0') => h,
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
    SyscallResult::ok(name, u64::try_from(out.len()).unwrap_or(0))
}

fn handle_executable_path(args: SyscallArgs) -> SyscallResult {
    let name = "kh_executable_path";
    let ptr = args.x0;
    let Ok(cap) = usize::try_from(args.x1) else {
        return SyscallResult::err(name, EINVAL);
    };
    if ptr == 0 || cap == 0 || !registry_check_range(ptr, cap, true) {
        return SyscallResult::err(name, EFAULT);
    }
    let Some(path) = crate::process::guest_executable_path() else {
        // Unset: freestanding falls back (historically soft-git CLT path).
        return SyscallResult::ok(name, 0);
    };
    let bytes = path.as_bytes();
    if bytes.len().saturating_add(1) > cap {
        return SyscallResult::err(name, EINVAL);
    }
    let mut out = vec![0_u8; bytes.len().saturating_add(1)];
    if let Some(dst) = out.get_mut(..bytes.len()) {
        dst.copy_from_slice(bytes);
    }
    guest_write(ptr, &out);
    SyscallResult::ok(name, u64::try_from(out.len()).unwrap_or(0))
}

fn handle_getenv(args: SyscallArgs) -> SyscallResult {
    let name = "kh_getenv";
    let key_ptr = args.x0;
    let out_ptr = args.x1;
    let Ok(cap) = usize::try_from(args.x2) else {
        return SyscallResult::err(name, EINVAL);
    };
    if key_ptr == 0 || !registry_check_range(key_ptr, 1, false) {
        return SyscallResult::err(name, EFAULT);
    }
    let Some(key) = crate::bottle::read_c_string(key_ptr, 256) else {
        return SyscallResult::err(name, EFAULT);
    };
    if key.is_empty() || key.contains('\0') {
        return SyscallResult::err(name, EINVAL);
    }
    let Ok(val) = std::env::var(&key) else {
        return SyscallResult::ok(name, 0);
    };
    if val.contains('\0') {
        return SyscallResult::ok(name, 0);
    }
    let bytes = val.as_bytes();
    if out_ptr == 0 || cap == 0 || !registry_check_range(out_ptr, cap, true) {
        return SyscallResult::err(name, EFAULT);
    }
    if bytes.len().saturating_add(1) > cap {
        // Too long — treat as missing so guest does not get a truncated path.
        return SyscallResult::ok(name, 0);
    }
    let mut out = vec![0_u8; bytes.len().saturating_add(1)];
    if let Some(dst) = out.get_mut(..bytes.len()) {
        dst.copy_from_slice(bytes);
    }
    guest_write(out_ptr, &out);
    SyscallResult::ok(name, u64::try_from(out.len()).unwrap_or(0))
}

// ── Host POSIX-ish regex (for freestanding regcomp/regexec) ─────────────────

/// Darwin `REG_*` (cflags / errors) — must match freestanding `regex_posix.rs`.
const DARWIN_REG_EXTENDED: i32 = 1;
const DARWIN_REG_ICASE: i32 = 2;
const DARWIN_REG_NOSUB: i32 = 4;
const DARWIN_REG_NEWLINE: i32 = 8;
const DARWIN_REG_STARTEND: i32 = 4;
const DARWIN_REG_NOMATCH: u64 = 1;
const DARWIN_REG_BADPAT: u64 = 2;
const DARWIN_REG_INVARG: u64 = 16;
const DARWIN_REG_ESPACE: u64 = 12;

struct HostRegex {
    re: regex::Regex,
    nosub: bool,
}

fn regex_table() -> &'static std::sync::Mutex<Vec<Option<HostRegex>>> {
    static TABLE: std::sync::OnceLock<std::sync::Mutex<Vec<Option<HostRegex>>>> =
        std::sync::OnceLock::new();
    TABLE.get_or_init(|| std::sync::Mutex::new(Vec::new()))
}

/// Count capturing groups in a rust-style pattern (unescaped `(`).
fn count_groups(pat: &str) -> usize {
    let mut n = 0_usize;
    let mut chars = pat.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\\' {
            let _ = chars.next();
            continue;
        }
        if c == '(' && chars.peek() != Some(&'?') {
            n = n.saturating_add(1);
        }
    }
    n
}

/// Minimal BRE → rust-regex (subset used by git pathspecs).
#[allow(clippy::arithmetic_side_effects, clippy::indexing_slicing)]
fn bre_to_rust(bre: &str) -> String {
    let mut out = String::with_capacity(bre.len().saturating_mul(2));
    let bytes = bre.as_bytes();
    let mut i = 0_usize;
    while i < bytes.len() {
        let Some(&b) = bytes.get(i) else {
            break;
        };
        if b == b'\\'
            && let Some(&n) = bytes.get(i.saturating_add(1))
        {
            match n {
                b'(' | b')' | b'+' | b'?' | b'|' | b'{' | b'}' => {
                    out.push(char::from(n));
                    i = i.saturating_add(2);
                    continue;
                }
                _ => {
                    out.push('\\');
                    out.push(char::from(n));
                    i = i.saturating_add(2);
                    continue;
                }
            }
        }
        match b {
            b'(' | b')' | b'+' | b'?' | b'|' | b'{' | b'}' => {
                out.push('\\');
                out.push(char::from(b));
            }
            _ => out.push(char::from(b)),
        }
        i = i.saturating_add(1);
    }
    out
}

fn handle_regcomp(args: SyscallArgs) -> SyscallResult {
    let name = "kh_regcomp";
    let pat_ptr = args.x0;
    let cflags = i32::try_from(args.x1.cast_signed()).unwrap_or(0);
    let out_ptr = args.x2;
    if pat_ptr == 0 || !registry_check_range(pat_ptr, 1, false) {
        return SyscallResult::ok(name, DARWIN_REG_INVARG);
    }
    if out_ptr == 0 || !registry_check_range(out_ptr, 16, true) {
        return SyscallResult::ok(name, DARWIN_REG_INVARG);
    }
    let Some(pat) = crate::bottle::read_c_string(pat_ptr, 1 << 16) else {
        return SyscallResult::ok(name, DARWIN_REG_INVARG);
    };
    let is_ere = cflags & DARWIN_REG_EXTENDED != 0;
    let mut rust_pat = if is_ere { pat } else { bre_to_rust(&pat) };
    if cflags & DARWIN_REG_NEWLINE != 0 {
        rust_pat.insert_str(0, "(?m)");
    }
    if cflags & DARWIN_REG_ICASE != 0 {
        rust_pat.insert_str(0, "(?i)");
    }
    let Ok(re) = regex::Regex::new(&rust_pat) else {
        return SyscallResult::ok(name, DARWIN_REG_BADPAT);
    };
    // Engine capture count (includes group 0); Darwin `re_nsub` is parenthesized only.
    // Fall back to paren-scan if the crate reports 0 (should not happen on success).
    let nsub = match re.captures_len().saturating_sub(1) {
        0 => count_groups(&rust_pat),
        n => n,
    };
    let nosub = cflags & DARWIN_REG_NOSUB != 0;
    let host = HostRegex { re, nosub };
    let handle = {
        let Ok(mut table) = regex_table().lock() else {
            return SyscallResult::ok(name, DARWIN_REG_ESPACE);
        };
        // Find free slot; handles are 1-based indices.
        if let Some((idx, slot)) = table.iter_mut().enumerate().find(|(_, s)| s.is_none()) {
            *slot = Some(host);
            u64::try_from(idx.saturating_add(1)).unwrap_or(1)
        } else {
            table.push(Some(host));
            u64::try_from(table.len()).unwrap_or(1)
        }
    };
    let nsub_out = if nosub {
        0_u64
    } else {
        u64::try_from(nsub).unwrap_or(0)
    };
    let mut words = [0_u8; 16];
    if let Some(dst) = words.get_mut(..8) {
        dst.copy_from_slice(&handle.to_le_bytes());
    }
    if let Some(dst) = words.get_mut(8..) {
        dst.copy_from_slice(&nsub_out.to_le_bytes());
    }
    guest_write(out_ptr, &words);
    SyscallResult::ok(name, 0)
}

fn handle_regexec(args: SyscallArgs) -> SyscallResult {
    let name = "kh_regexec";
    let req_ptr = args.x0;
    if req_ptr == 0 || !registry_check_range(req_ptr, 40, false) {
        return SyscallResult::ok(name, DARWIN_REG_INVARG);
    }
    let raw = guest_slice(req_ptr, 40);
    let mut words = [0_u64; 5];
    for (i, w) in words.iter_mut().enumerate() {
        let off = i.saturating_mul(8);
        if let Some(chunk) = raw.get(off..off.saturating_add(8)) {
            let mut b = [0_u8; 8];
            b.copy_from_slice(chunk);
            *w = u64::from_le_bytes(b);
        }
    }
    let handle = words.first().copied().unwrap_or(0);
    let string_va = words.get(1).copied().unwrap_or(0);
    let nmatch = usize::try_from(words.get(2).copied().unwrap_or(0)).unwrap_or(0);
    let pmatch_va = words.get(3).copied().unwrap_or(0);
    let eflags = i32::try_from(words.get(4).copied().unwrap_or(0).cast_signed()).unwrap_or(0);

    if handle == 0 || string_va == 0 || !registry_check_range(string_va, 1, false) {
        return SyscallResult::ok(name, DARWIN_REG_INVARG);
    }
    let Some(hay_owned) = crate::bottle::read_c_string(string_va, 1 << 20) else {
        return SyscallResult::ok(name, DARWIN_REG_INVARG);
    };

    let Ok(table) = regex_table().lock() else {
        return SyscallResult::ok(name, DARWIN_REG_ESPACE);
    };
    let idx = usize::try_from(handle.saturating_sub(1)).unwrap_or(usize::MAX);
    let Some(Some(host)) = table.get(idx) else {
        return SyscallResult::ok(name, DARWIN_REG_INVARG);
    };

    // REG_STARTEND: search window in pmatch[0] (byte offsets into string).
    let (hay, base_off) = if eflags & DARWIN_REG_STARTEND != 0 {
        if pmatch_va == 0 || !registry_check_range(pmatch_va, 16, true) {
            return SyscallResult::ok(name, DARWIN_REG_INVARG);
        }
        let pm = guest_slice(pmatch_va, 16);
        let so = i64::from_le_bytes(
            pm.get(..8)
                .and_then(|c| c.try_into().ok())
                .unwrap_or([0; 8]),
        );
        let eo = i64::from_le_bytes(
            pm.get(8..16)
                .and_then(|c| c.try_into().ok())
                .unwrap_or([0; 8]),
        );
        if so < 0 || eo < so {
            return SyscallResult::ok(name, DARWIN_REG_INVARG);
        }
        let so_u = usize::try_from(so).unwrap_or(0);
        let eo_u = usize::try_from(eo).unwrap_or(0);
        if eo_u > hay_owned.len() {
            return SyscallResult::ok(name, DARWIN_REG_INVARG);
        }
        (hay_owned.get(so_u..eo_u).unwrap_or("").to_owned(), so)
    } else {
        (hay_owned, 0_i64)
    };

    let Some(caps) = host.re.captures(&hay) else {
        return SyscallResult::ok(name, DARWIN_REG_NOMATCH);
    };

    if !host.nosub && nmatch > 0 && pmatch_va != 0 {
        let bytes_need = nmatch.saturating_mul(16);
        if registry_check_range(pmatch_va, bytes_need, true) {
            let mut buf = vec![0_u8; bytes_need];
            for i in 0..nmatch {
                let (so, eo) = if let Some(m) = caps.get(i) {
                    (
                        base_off.saturating_add(i64::try_from(m.start()).unwrap_or(0)),
                        base_off.saturating_add(i64::try_from(m.end()).unwrap_or(0)),
                    )
                } else {
                    (-1_i64, -1_i64)
                };
                let off = i.saturating_mul(16);
                if let Some(dst) = buf.get_mut(off..off.saturating_add(16)) {
                    if let Some(lo) = dst.get_mut(..8) {
                        lo.copy_from_slice(&so.to_le_bytes());
                    }
                    if let Some(hi) = dst.get_mut(8..) {
                        hi.copy_from_slice(&eo.to_le_bytes());
                    }
                }
            }
            guest_write(pmatch_va, &buf);
        }
    }
    SyscallResult::ok(name, 0)
}

fn handle_regfree(args: SyscallArgs) -> SyscallResult {
    let name = "kh_regfree";
    let handle = args.x0;
    if handle == 0 {
        return SyscallResult::ok(name, 0);
    }
    if let Ok(mut table) = regex_table().lock() {
        let idx = usize::try_from(handle.saturating_sub(1)).unwrap_or(usize::MAX);
        if let Some(slot) = table.get_mut(idx) {
            *slot = None;
        }
    }
    SyscallResult::ok(name, 0)
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
        assert!(is_helper(KH_HELPER_GUEST_HOME));
        assert!(is_helper(KH_HELPER_HEAP_STATS_ON));
        assert!(!is_helper(4)); // write
        assert!(!is_helper(1)); // exit
    }
}
