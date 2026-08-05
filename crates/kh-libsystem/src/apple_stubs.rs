//! Minimal Apple-framework stubs for guests that still *link* CF/Security/CC
//! (default Darwin curl) when those frameworks are not in the bottle.
//!
//! Bind path: two-level ordinal → missing framework → flat lookup into this
//! dylib (`kh-loader`).
//!
//! **G4+ TLS trust:** CF/Security objects used by curl's AppleSecTrust path
//! store real DER + hostname in freestanding heap tags. `SecTrustEvaluateWithError`
//! packs them and calls host helper `KH_HELPER_VERIFY_CERT`, which verifies the
//! chain against the bottle CA bundle (`private/etc/ssl/cert.pem`) via host
//! OpenSSL. This is **not** Apple's Security.framework — it is real PKI verify
//! against a real CA file.

use core::ffi::{c_char, c_int, c_void};
use core::sync::atomic::{AtomicUsize, Ordering};

use crate::heap::{free, malloc};
use crate::sys;
use crate::trace;

/// Opaque object magic.
const CF_MAGIC: usize = 0x4346_5f4b_4801; // "CF_KH\1"

const KIND_DATA: u32 = 1;
const KIND_STR: u32 = 2;
const KIND_ARR: u32 = 3;
const KIND_CERT: u32 = 4;
const KIND_POLICY: u32 = 5;
const KIND_TRUST: u32 = 6;

const HDR_WORDS: usize = 2; // magic + (kind:u32 | len:u32) packed in usize on 64-bit
const MAX_ARR: usize = 16;
const MAX_VERIFY_BUF: usize = 256 * 1024;

#[inline]
fn hdr_kind_len(kind: u32, len: u32) -> usize {
    usize::try_from(u64::from(kind) | (u64::from(len) << 32)).unwrap_or(0)
}

#[inline]
fn kind_of(word: usize) -> u32 {
    u32::try_from(word & 0xFFFF_FFFF).unwrap_or(0)
}

#[inline]
fn len_of(word: usize) -> u32 {
    // High 32 bits of the packed kind|len word (64-bit guest).
    u32::try_from(word.checked_shr(32).unwrap_or(0)).unwrap_or(0)
}

fn alloc_raw(bytes: usize) -> *mut c_void {
    let p = unsafe { malloc(bytes) };
    if p.is_null() {
        return core::ptr::null_mut();
    }
    // Zero payload so unused array slots are null.
    unsafe {
        core::ptr::write_bytes(p.cast::<u8>(), 0, bytes);
    }
    p
}

fn obj_write_hdr(p: *mut c_void, kind: u32, len: u32) {
    unsafe {
        p.cast::<usize>().write(CF_MAGIC);
        p.cast::<usize>().add(1).write(hdr_kind_len(kind, len));
    }
}

fn is_obj(p: *mut c_void) -> bool {
    if p.is_null() {
        return false;
    }
    unsafe { p.cast::<usize>().read() == CF_MAGIC }
}

fn obj_kind(p: *mut c_void) -> Option<u32> {
    if !is_obj(p) {
        return None;
    }
    Some(kind_of(unsafe { p.cast::<usize>().add(1).read() }))
}

fn obj_len(p: *mut c_void) -> u32 {
    if !is_obj(p) {
        return 0;
    }
    len_of(unsafe { p.cast::<usize>().add(1).read() })
}

/// Byte payload after the 2-word header (aligned to `usize`).
fn payload_bytes(p: *mut c_void) -> *mut u8 {
    // SAFETY: header is 2 usizes; result is still usize-aligned.
    unsafe { p.cast::<usize>().add(HDR_WORDS).cast::<u8>() }
}

/// Word-sized payload slots after the header (CFArray / Sec* pointers).
fn payload_words(p: *mut c_void) -> *mut usize {
    // SAFETY: header is 2 usizes; remainder is usize-aligned storage.
    unsafe { p.cast::<usize>().add(HDR_WORDS) }
}

// ── CoreFoundation (data) ───────────────────────────────────────────────────

/// `kCFTypeArrayCallBacks` — opaque table; never read if CF paths unused.
#[unsafe(export_name = "kCFTypeArrayCallBacks")]
#[used]
static K_CF_TYPE_ARRAY_CALLBACKS: [usize; 8] = [0; 8];

// ── CoreFoundation (functions) ──────────────────────────────────────────────

#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn CFArrayAppendValue(arr: *mut c_void, value: *const c_void) {
    if obj_kind(arr) != Some(KIND_ARR) {
        return;
    }
    let n = usize::try_from(obj_len(arr)).unwrap_or(0);
    if n >= MAX_ARR {
        return;
    }
    let slots = payload_words(arr);
    unsafe {
        slots.add(n).write(value.addr());
        // bump len in header
        arr.cast::<usize>()
            .add(1)
            .write(hdr_kind_len(KIND_ARR, u32::try_from(n.saturating_add(1)).unwrap_or(0)));
    }
}

#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn CFArrayCreateMutable(
    _alloc: *mut c_void,
    _cap: isize,
    _cbs: *const c_void,
) -> *mut c_void {
    let bytes = HDR_WORDS
        .saturating_mul(core::mem::size_of::<usize>())
        .saturating_add(MAX_ARR.saturating_mul(core::mem::size_of::<usize>()));
    let p = alloc_raw(bytes);
    if p.is_null() {
        return core::ptr::null_mut();
    }
    obj_write_hdr(p, KIND_ARR, 0);
    p
}

#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn CFDataCreate(
    _alloc: *mut c_void,
    bytes: *const u8,
    len: isize,
) -> *mut c_void {
    if bytes.is_null() || len <= 0 {
        // Empty CFData still used as a tag by some callers.
        let p = alloc_raw(HDR_WORDS.saturating_mul(core::mem::size_of::<usize>()));
        if p.is_null() {
            return core::ptr::null_mut();
        }
        obj_write_hdr(p, KIND_DATA, 0);
        return p;
    }
    let n = usize::try_from(len).unwrap_or(0);
    let bytes_total = HDR_WORDS
        .saturating_mul(core::mem::size_of::<usize>())
        .saturating_add(n);
    let p = alloc_raw(bytes_total);
    if p.is_null() {
        return core::ptr::null_mut();
    }
    obj_write_hdr(p, KIND_DATA, u32::try_from(n).unwrap_or(0));
    unsafe {
        core::ptr::copy_nonoverlapping(bytes, payload_bytes(p), n);
    }
    p
}

#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn CFErrorCopyDescription(_err: *mut c_void) -> *mut c_void {
    core::ptr::null_mut()
}

#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn CFErrorGetCode(_err: *mut c_void) -> isize {
    0
}

#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn CFRelease(cf: *mut c_void) {
    if is_obj(cf) {
        unsafe {
            free(cf);
        }
    }
}

#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn CFStringCreateWithCString(
    _alloc: *mut c_void,
    c_str: *const c_char,
    _encoding: u32,
) -> *mut c_void {
    if c_str.is_null() {
        let p = alloc_raw(HDR_WORDS.saturating_mul(core::mem::size_of::<usize>()).saturating_add(1));
        if p.is_null() {
            return core::ptr::null_mut();
        }
        obj_write_hdr(p, KIND_STR, 0);
        unsafe {
            payload_bytes(p).write(0);
        }
        return p;
    }
    // strlen
    let mut n = 0_usize;
    while unsafe { c_str.add(n).read() } != 0 {
        n = n.saturating_add(1);
        if n > 1024 {
            break;
        }
    }
    let bytes_total = HDR_WORDS
        .saturating_mul(core::mem::size_of::<usize>())
        .saturating_add(n)
        .saturating_add(1);
    let p = alloc_raw(bytes_total);
    if p.is_null() {
        return core::ptr::null_mut();
    }
    obj_write_hdr(p, KIND_STR, u32::try_from(n).unwrap_or(0));
    unsafe {
        core::ptr::copy_nonoverlapping(c_str.cast::<u8>(), payload_bytes(p), n);
        payload_bytes(p).add(n).write(0);
    }
    p
}

#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn CFStringGetCString(
    s: *mut c_void,
    buf: *mut c_char,
    buf_size: isize,
    _encoding: u32,
) -> u8 {
    if s.is_null() || buf.is_null() || buf_size <= 0 {
        return 0;
    }
    let max = usize::try_from(buf_size).unwrap_or(0).saturating_sub(1);
    if obj_kind(s) == Some(KIND_STR) {
        let n = usize::try_from(obj_len(s)).unwrap_or(0);
        let copy = n.min(max);
        unsafe {
            core::ptr::copy_nonoverlapping(payload_bytes(s), buf.cast::<u8>(), copy);
            buf.add(copy).write(0);
        }
        return 1;
    }
    unsafe {
        buf.write(0);
    }
    1
}

#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn CFStringGetLength(s: *mut c_void) -> isize {
    if obj_kind(s) == Some(KIND_STR) {
        isize::try_from(obj_len(s)).unwrap_or(0)
    } else {
        0
    }
}

#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn CFStringGetMaximumSizeForEncoding(
    len: isize,
    _encoding: u32,
) -> isize {
    len.saturating_mul(4).saturating_add(1)
}

// ── Security.framework ──────────────────────────────────────────────────────

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
            crate::KH_HELPER_VERIFY_CERT,
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

// ── CommonCrypto ────────────────────────────────────────────────────────────

/// `CCRandomGenerateBytes` → nlist `_CCRandomGenerateBytes` (fill with zeros).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn CCRandomGenerateBytes(bytes: *mut c_void, count: usize) -> c_int {
    if bytes.is_null() || count == 0 {
        return 0;
    }
    // SAFETY: caller buffer; deterministic zero fill (not crypto-grade).
    unsafe {
        let p = bytes.cast::<u8>();
        let mut i = 0_usize;
        while i < count {
            p.add(i).write(0);
            i = i.saturating_add(1);
        }
    }
    0
}
