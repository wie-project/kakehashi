//! Security.framework soft surface + real cert verify via host helper.

#![allow(unused_imports)]

use core::ffi::{c_char, c_int, c_void};
use core::sync::atomic::{AtomicUsize, Ordering};

use crate::kh_core::heap::{free, malloc};
use crate::kh_core::sys;
use crate::kh_core::trace;

use crate::frameworks::corefoundation::{
    HDR_WORDS, KIND_ARR, KIND_CERT, KIND_DATA, KIND_POLICY, KIND_STR, KIND_TRUST, MAX_ARR,
    MAX_VERIFY_BUF, alloc_raw, obj_kind, obj_len, obj_write_hdr, payload_bytes, payload_words,
};
use crate::kh_core::helpers::KH_HELPER_VERIFY_CERT;

static TRUST_NOTE: AtomicUsize = AtomicUsize::new(0);

#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn SecCertificateCreateWithData(
    _alloc: *mut c_void,
    data: *mut c_void,
) -> *mut c_void {
    let bytes = HDR_WORDS
        .saturating_mul(core::mem::size_of::<usize>())
        .saturating_add(core::mem::size_of::<usize>());
    let p = alloc_raw(bytes);
    if p.is_null() {
        return core::ptr::null_mut();
    }
    obj_write_hdr(p, KIND_CERT, 0);
    unsafe {
        payload_words(p).write(data.addr());
    }
    p
}

#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn SecPolicyCreateRevocation(_flags: u64) -> *mut c_void {
    // Soft policy object (no hostname).
    let bytes = HDR_WORDS
        .saturating_mul(core::mem::size_of::<usize>())
        .saturating_add(core::mem::size_of::<usize>());
    let p = alloc_raw(bytes);
    if p.is_null() {
        return core::ptr::null_mut();
    }
    obj_write_hdr(p, KIND_POLICY, 0);
    p
}

#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn SecPolicyCreateSSL(
    _server: u8,
    hostname: *mut c_void,
) -> *mut c_void {
    let bytes = HDR_WORDS
        .saturating_mul(core::mem::size_of::<usize>())
        .saturating_add(core::mem::size_of::<usize>());
    let p = alloc_raw(bytes);
    if p.is_null() {
        return core::ptr::null_mut();
    }
    obj_write_hdr(p, KIND_POLICY, 0);
    unsafe {
        payload_words(p).write(hostname.addr());
    }
    p
}

/// `errSecSuccess` = 0.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn SecTrustCreateWithCertificates(
    certs: *mut c_void,
    policies: *mut c_void,
    trust: *mut *mut c_void,
) -> i32 {
    if trust.is_null() {
        return -1;
    }
    let bytes = HDR_WORDS
        .saturating_mul(core::mem::size_of::<usize>())
        .saturating_add(2_usize.saturating_mul(core::mem::size_of::<usize>()));
    let p = alloc_raw(bytes);
    if p.is_null() {
        return -1;
    }
    obj_write_hdr(p, KIND_TRUST, 0);
    unsafe {
        let pl = payload_words(p);
        pl.write(certs.addr());
        pl.add(1).write(policies.addr());
        trust.write(p);
    }
    0
}

/// Real verify via host CA bundle (Boolean true/false).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn SecTrustEvaluateWithError(
    trust: *mut c_void,
    error: *mut *mut c_void,
) -> u8 {
    if !error.is_null() {
        unsafe {
            error.write(core::ptr::null_mut());
        }
    }
    if obj_kind(trust) != Some(KIND_TRUST) {
        return 0;
    }

    // Pack on the heap — stack limit forbids 256 KiB locals under pedantic clippy.
    let pack = unsafe { malloc(MAX_VERIFY_BUF) };
    if pack.is_null() {
        return 0;
    }
    unsafe {
        core::ptr::write_bytes(pack.cast::<u8>(), 0, MAX_VERIFY_BUF);
    }
    let pack_slice = unsafe { core::slice::from_raw_parts_mut(pack.cast::<u8>(), MAX_VERIFY_BUF) };
    let mut off = 0_usize;

    let (hostname, certs) = unsafe {
        let pl = payload_words(trust);
        let certs = core::ptr::with_exposed_provenance_mut::<c_void>(pl.read());
        let policies = core::ptr::with_exposed_provenance_mut::<c_void>(pl.add(1).read());
        let host = extract_hostname(policies);
        (host, certs)
    };

    // hostname_len + bytes
    let host_bytes = hostname.as_bytes();
    let host_len = u32::try_from(host_bytes.len()).unwrap_or(0);
    if !write_u32(pack_slice, &mut off, host_len) {
        unsafe {
            free(pack);
        }
        return 0;
    }
    if !write_bytes(pack_slice, &mut off, host_bytes) {
        unsafe {
            free(pack);
        }
        return 0;
    }

    // Gather DER certs (leaf first).
    let mut der_list: [Option<(*const u8, usize)>; MAX_ARR] = [None; MAX_ARR];
    let n_certs = collect_certs(certs, &mut der_list);
    if n_certs == 0 {
        unsafe {
            free(pack);
        }
        return 0;
    }
    if !write_u32(pack_slice, &mut off, u32::try_from(n_certs).unwrap_or(0)) {
        unsafe {
            free(pack);
        }
        return 0;
    }
    for i in 0..n_certs {
        let Some((ptr, len)) = der_list.get(i).copied().flatten() else {
            unsafe {
                free(pack);
            }
            return 0;
        };
        if !write_u32(pack_slice, &mut off, u32::try_from(len).unwrap_or(0)) {
            unsafe {
                free(pack);
            }
            return 0;
        }
        if len > 0 {
            let slice = unsafe { core::slice::from_raw_parts(ptr, len) };
            if !write_bytes(pack_slice, &mut off, slice) {
                unsafe {
                    free(pack);
                }
                return 0;
            }
        }
    }

    let buf_ptr = pack.addr();
    let ret = unsafe {
        sys::helper2(
            crate::kh_core::helpers::KH_HELPER_VERIFY_CERT,
            u64::try_from(buf_ptr).unwrap_or(0),
            u64::try_from(off).unwrap_or(0),
        )
    };
    unsafe {
        free(pack);
    }

    // Verbose only: force_note would spam every HTTPS guest on first verify.
    if TRUST_NOTE.fetch_add(1, Ordering::Relaxed) == 0 {
        if ret == 0 {
            trace::note(b"[kh-libsystem] SecTrust: host CA verify ok\n");
        } else {
            trace::note(b"[kh-libsystem] SecTrust: host CA verify failed\n");
        }
    }

    u8::from(ret == 0)
}

fn extract_hostname(policies: *mut c_void) -> HeaplessHost {
    // Policy object or array of policies; first KIND_POLICY wins.
    if obj_kind(policies) == Some(KIND_POLICY) {
        return hostname_from_policy(policies);
    }
    if obj_kind(policies) == Some(KIND_ARR) {
        let n = usize::try_from(obj_len(policies)).unwrap_or(0);
        let slots = payload_words(policies);
        for i in 0..n.min(MAX_ARR) {
            let addr = unsafe { slots.add(i).read() };
            let p = core::ptr::with_exposed_provenance_mut::<c_void>(addr);
            if obj_kind(p) == Some(KIND_POLICY) {
                return hostname_from_policy(p);
            }
        }
    }
    HeaplessHost::empty()
}

fn hostname_from_policy(policy: *mut c_void) -> HeaplessHost {
    let addr = unsafe { payload_words(policy).read() };
    let host_obj = core::ptr::with_exposed_provenance_mut::<c_void>(addr);
    if obj_kind(host_obj) != Some(KIND_STR) {
        return HeaplessHost::empty();
    }
    let n = usize::try_from(obj_len(host_obj)).unwrap_or(0);
    let mut h = HeaplessHost::empty();
    let copy = n.min(HeaplessHost::CAP);
    unsafe {
        core::ptr::copy_nonoverlapping(payload_bytes(host_obj), h.buf.as_mut_ptr(), copy);
    }
    h.len = copy;
    h
}

fn collect_certs(certs: *mut c_void, out: &mut [Option<(*const u8, usize)>; MAX_ARR]) -> usize {
    let mut n = 0_usize;
    if obj_kind(certs) == Some(KIND_CERT) {
        if let Some(d) = cert_der(certs)
            && let Some(slot) = out.get_mut(0)
        {
            *slot = Some(d);
            n = 1;
        }
        return n;
    }
    if obj_kind(certs) == Some(KIND_ARR) {
        let count = usize::try_from(obj_len(certs)).unwrap_or(0);
        let slots = payload_words(certs);
        for i in 0..count.min(MAX_ARR) {
            let addr = unsafe { slots.add(i).read() };
            let c = core::ptr::with_exposed_provenance_mut::<c_void>(addr);
            if obj_kind(c) == Some(KIND_CERT)
                && let Some(d) = cert_der(c)
                && let Some(slot) = out.get_mut(n)
            {
                *slot = Some(d);
                n = n.saturating_add(1);
            }
        }
    }
    n
}

fn cert_der(cert: *mut c_void) -> Option<(*const u8, usize)> {
    let addr = unsafe { payload_words(cert).read() };
    let data = core::ptr::with_exposed_provenance_mut::<c_void>(addr);
    if obj_kind(data) != Some(KIND_DATA) {
        return None;
    }
    let n = usize::try_from(obj_len(data)).unwrap_or(0);
    if n == 0 {
        return None;
    }
    Some((payload_bytes(data).cast_const(), n))
}

fn write_u32(buf: &mut [u8], off: &mut usize, v: u32) -> bool {
    let start = *off;
    let end = start.saturating_add(4);
    if end > buf.len() {
        return false;
    }
    if let Some(dst) = buf.get_mut(start..end) {
        dst.copy_from_slice(&v.to_le_bytes());
        *off = end;
        true
    } else {
        false
    }
}

fn write_bytes(buf: &mut [u8], off: &mut usize, src: &[u8]) -> bool {
    let start = *off;
    let end = start.saturating_add(src.len());
    if end > buf.len() {
        return false;
    }
    if let Some(dst) = buf.get_mut(start..end) {
        dst.copy_from_slice(src);
        *off = end;
        true
    } else {
        false
    }
}

/// Small stack hostname (no heap).
struct HeaplessHost {
    buf: [u8; 256],
    len: usize,
}

impl HeaplessHost {
    const CAP: usize = 256;
    fn empty() -> Self {
        Self {
            buf: [0; 256],
            len: 0,
        }
    }
    fn as_bytes(&self) -> &[u8] {
        self.buf.get(..self.len).unwrap_or(&[])
    }
}

#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn SecTrustSetOCSPResponse(
    _trust: *mut c_void,
    _response: *mut c_void,
) -> i32 {
    0 // errSecSuccess
}

// ── SecureTransport (Darwin rustup / native-tls) ─────────────────────────────
//
// rustup links Security.framework. The bottle aliases that path to libSystem;
// these wrap the last `connect`'d guest fd with host rustls.

const SSL_OK: i32 = 0;
const SSL_PARAM: i32 = -50;
const SSL_CTX_BYTES: usize = 320;
const SSL_HOST_OFF: usize = 0;
const SSL_HOST_CAP: usize = 256;
const SSL_HOST_LEN_OFF: usize = 256;
const SSL_GFD_OFF: usize = 264;
const SSL_CONN_OFF: usize = 272;
const SSL_STATE_CONNECTED: i32 = 2;

fn ssl_ctx_ok(ctx: *mut c_void) -> bool {
    !ctx.is_null()
}

fn ssl_write_host(ctx: *mut u8, name: *const c_char, len: usize) {
    let n = len.min(SSL_HOST_CAP.saturating_sub(1));
    unsafe {
        if !name.is_null() && n > 0 {
            core::ptr::copy_nonoverlapping(name.cast::<u8>(), ctx.add(SSL_HOST_OFF), n);
        }
        ctx.add(SSL_HOST_OFF).add(n).write(0);
        let ln = u64::try_from(n).unwrap_or(0).to_ne_bytes();
        core::ptr::copy_nonoverlapping(ln.as_ptr(), ctx.add(SSL_HOST_LEN_OFF), 8);
    }
}

fn ssl_host_ptr(ctx: *mut u8) -> *const c_char {
    unsafe { ctx.add(SSL_HOST_OFF).cast() }
}

fn ssl_set_gfd(ctx: *mut u8, gfd: i32) {
    let b = i32::to_ne_bytes(gfd);
    unsafe {
        core::ptr::copy_nonoverlapping(b.as_ptr(), ctx.add(SSL_GFD_OFF), 4);
    }
}

fn ssl_gfd(ctx: *const u8) -> i32 {
    let mut b = [0_u8; 4];
    unsafe {
        core::ptr::copy_nonoverlapping(ctx.add(SSL_GFD_OFF), b.as_mut_ptr(), 4);
    }
    i32::from_ne_bytes(b)
}

/// `SSLCreateContext` → heap ctx (hostname + wrapped guest fd).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn SSLCreateContext(
    _alloc: *mut c_void,
    _side: i32,
    _ty: i32,
) -> *mut c_void {
    let p = unsafe { malloc(SSL_CTX_BYTES) };
    if p.is_null() {
        return core::ptr::null_mut();
    }
    unsafe {
        core::ptr::write_bytes(p.cast::<u8>(), 0, SSL_CTX_BYTES);
    }
    ssl_set_gfd(p.cast(), -1);
    p
}

/// `SSLSetPeerDomainName`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn SSLSetPeerDomainName(
    ctx: *mut c_void,
    name: *const c_char,
    len: usize,
) -> i32 {
    if !ssl_ctx_ok(ctx) {
        return SSL_PARAM;
    }
    ssl_write_host(ctx.cast(), name, len);
    SSL_OK
}

/// `SSLSetConnection` — stash rust's stream pointer; TCP fd is last `connect`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn SSLSetConnection(
    ctx: *mut c_void,
    connection: *mut c_void,
) -> i32 {
    if !ssl_ctx_ok(ctx) {
        return SSL_PARAM;
    }
    let addr = u64::try_from(connection.addr()).unwrap_or(0);
    unsafe {
        core::ptr::copy_nonoverlapping(
            addr.to_ne_bytes().as_ptr(),
            ctx.cast::<u8>().add(SSL_CONN_OFF),
            8,
        );
    }
    SSL_OK
}

/// `SSLSetIOFuncs` — unused; I/O is host rustls on the guest fd.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn SSLSetIOFuncs(
    _ctx: *mut c_void,
    _read: *mut c_void,
    _write: *mut c_void,
) -> i32 {
    SSL_OK
}

/// `SSLSetSessionOption` — soft success (BreakOnServerAuth etc.).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn SSLSetSessionOption(
    _ctx: *mut c_void,
    _option: i32,
    _value: u8,
) -> i32 {
    SSL_OK
}

/// `SSLHandshake` → rustls wrap on the last connected guest TCP fd.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn SSLHandshake(ctx: *mut c_void) -> i32 {
    if !ssl_ctx_ok(ctx) {
        return SSL_PARAM;
    }
    let base = ctx.cast::<u8>();
    let rc = unsafe {
        crate::kh_core::sys::helper2(
            crate::kh_core::helpers::KH_HELPER_TLS_WRAP,
            u64::from(ssl_gfd(base).cast_unsigned()),
            u64::try_from(ssl_host_ptr(base).addr()).unwrap_or(0),
        )
    };
    if rc < 0 {
        return -1;
    }
    // Helper returns the wrapped guest fd (never leave gfd=-1 for SSLRead).
    let wrapped = i32::try_from(rc).unwrap_or(-1);
    if wrapped >= 0 {
        ssl_set_gfd(base, wrapped);
    }
    SSL_OK
}

/// `SSLRead` — plaintext via tls-wrapped `read`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn SSLRead(
    ctx: *mut c_void,
    data: *mut c_void,
    data_len: usize,
    processed: *mut usize,
) -> i32 {
    if !ssl_ctx_ok(ctx) || data.is_null() {
        return SSL_PARAM;
    }
    let gfd = ssl_gfd(ctx.cast());
    if gfd < 0 {
        return SSL_PARAM;
    }
    let n = unsafe { crate::dylib::libsystem_c::posix::read(gfd, data, data_len) };
    if n < 0 {
        return -1;
    }
    if !processed.is_null() {
        unsafe {
            processed.write(usize::try_from(n).unwrap_or(0));
        }
    }
    SSL_OK
}

/// `SSLWrite` — plaintext via tls-wrapped `write`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn SSLWrite(
    ctx: *mut c_void,
    data: *const c_void,
    data_len: usize,
    processed: *mut usize,
) -> i32 {
    if !ssl_ctx_ok(ctx) || (data.is_null() && data_len > 0) {
        return SSL_PARAM;
    }
    let gfd = ssl_gfd(ctx.cast());
    if gfd < 0 {
        return SSL_PARAM;
    }
    let n = unsafe { crate::dylib::libsystem_c::stdio::write(gfd, data, data_len) };
    if n < 0 {
        return -1;
    }
    if !processed.is_null() {
        unsafe {
            processed.write(usize::try_from(n).unwrap_or(0));
        }
    }
    SSL_OK
}

/// `SSLClose`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn SSLClose(_ctx: *mut c_void) -> i32 {
    SSL_OK
}

/// `SSLGetBufferedReadSize`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn SSLGetBufferedReadSize(
    _ctx: *mut c_void,
    buf_size: *mut usize,
) -> i32 {
    if !buf_size.is_null() {
        unsafe {
            buf_size.write(0);
        }
    }
    SSL_OK
}

/// `SSLCopyPeerTrust` — soft empty trust (verify already done in rustls).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn SSLCopyPeerTrust(
    _ctx: *mut c_void,
    trust: *mut *mut c_void,
) -> i32 {
    if !trust.is_null() {
        unsafe {
            trust.write(core::ptr::null_mut());
        }
    }
    SSL_OK
}

/// `SSLSetProtocolVersionMin` / max — soft.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn SSLSetProtocolVersionMin(
    _ctx: *mut c_void,
    _version: i32,
) -> i32 {
    SSL_OK
}

/// `SSLSetProtocolVersionMax`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn SSLSetProtocolVersionMax(
    _ctx: *mut c_void,
    _version: i32,
) -> i32 {
    SSL_OK
}

#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn SSLGetConnection(
    ctx: *mut c_void,
    connection: *mut *mut c_void,
) -> i32 {
    if !ssl_ctx_ok(ctx) || connection.is_null() {
        return SSL_PARAM;
    }
    let mut b = [0_u8; 8];
    unsafe {
        core::ptr::copy_nonoverlapping(ctx.cast::<u8>().add(SSL_CONN_OFF), b.as_mut_ptr(), 8);
        let addr = usize::try_from(u64::from_ne_bytes(b)).unwrap_or(0);
        connection.write(core::ptr::with_exposed_provenance_mut(addr));
    }
    SSL_OK
}

#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn SSLGetSessionState(ctx: *mut c_void, state: *mut i32) -> i32 {
    if !ssl_ctx_ok(ctx) || state.is_null() {
        return SSL_PARAM;
    }
    let st = if ssl_gfd(ctx.cast()) >= 0 {
        SSL_STATE_CONNECTED
    } else {
        0
    };
    unsafe {
        state.write(st);
    }
    SSL_OK
}

#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn SSLSetALPNProtocols(
    _ctx: *mut c_void,
    _protos: *mut c_void,
) -> i32 {
    SSL_OK
}

#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn SSLCopyALPNProtocols(
    _ctx: *mut c_void,
    _protos: *mut *mut c_void,
) -> i32 {
    SSL_OK
}

#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn SSLSetCertificate(_ctx: *mut c_void, _cert: *mut c_void) -> i32 {
    SSL_OK
}

#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn SSLSetEnabledCiphers(
    _ctx: *mut c_void,
    _ciphers: *const c_void,
    _n: usize,
) -> i32 {
    SSL_OK
}

#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn SSLGetNumberEnabledCiphers(
    _ctx: *mut c_void,
    n: *mut usize,
) -> i32 {
    if !n.is_null() {
        unsafe {
            n.write(0);
        }
    }
    SSL_OK
}

#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn SSLGetEnabledCiphers(
    _ctx: *mut c_void,
    _ciphers: *mut c_void,
    _n: usize,
) -> i32 {
    SSL_OK
}

#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn SSLSetPeerID(
    _ctx: *mut c_void,
    _peer_id: *const c_void,
    _len: usize,
) -> i32 {
    SSL_OK
}

#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn SSLSetSessionTicketsEnabled(
    _ctx: *mut c_void,
    _enabled: u8,
) -> i32 {
    SSL_OK
}
