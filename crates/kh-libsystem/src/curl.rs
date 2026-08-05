//! Freestanding libcurl surface for Apple `git-remote-http` (G4).
//!
//! Bottle install name `/usr/lib/libcurl.4.dylib` is a **symlink** to freestanding
//! `libSystem.B.dylib` (same pattern as `libc++.1.dylib`). Symbols live here;
//! HTTP(S) is performed via host [`crate::KH_HELPER_HTTP`] (host `curl` + bottle CA).
//!
//! Clean-room: public curl man-page contracts + observed git usage.

#![allow(
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    clippy::cast_lossless,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss,
    clippy::indexing_slicing,
    clippy::large_stack_arrays,
    clippy::manual_c_str_literals,
    clippy::match_same_arms,
    clippy::struct_excessive_bools,
    clippy::too_many_lines,
    clippy::undocumented_unsafe_blocks,
    clippy::unnecessary_cast,
    clippy::useless_conversion
)]

use core::ffi::{c_char, c_int, c_long, c_void};
use core::ptr;
use core::sync::atomic::{AtomicI32, Ordering};

use crate::KH_HELPER_HTTP;
use crate::heap::{free, malloc, realloc};
use crate::stdio::{memcpy, strlen};
use crate::sys;

// ── result codes ─────────────────────────────────────────────────────────────

const CURLE_OK: c_int = 0;
const CURLE_FAILED_INIT: c_int = 2;
const CURLE_URL_MALFORMAT: c_int = 3;
const CURLE_COULDNT_CONNECT: c_int = 7;
const CURLE_HTTP_RETURNED_ERROR: c_int = 22;
const CURLE_WRITE_ERROR: c_int = 23;
const CURLE_OUT_OF_MEMORY: c_int = 27;
const CURLE_OPERATION_TIMEDOUT: c_int = 28;
const CURLE_SSL_CONNECT_ERROR: c_int = 35;
const CURLE_BAD_FUNCTION_ARGUMENT: c_int = 43;

const CURLM_OK: c_int = 0;
const CURLM_BAD_HANDLE: c_int = 1;
const CURLM_BAD_EASY_HANDLE: c_int = 2;
const CURLM_OUT_OF_MEMORY: c_int = 3;
const CURLM_INTERNAL_ERROR: c_int = 4;
const CURLM_BAD_FUNCTION_ARGUMENT: c_int = 6;

const CURLMSG_DONE: c_int = 1;
const CURLSSLSET_OK: c_int = 0;
const CURLVERSION_NOW: c_int = 11;

// Common CURLOPT numbers used by git-remote-http.
const CURLOPT_WRITEDATA: c_int = 10_001;
const CURLOPT_URL: c_int = 10_002;
const CURLOPT_READDATA: c_int = 10_009;
const CURLOPT_ERRORBUFFER: c_int = 10_010;
const CURLOPT_POSTFIELDS: c_int = 10_015;
const CURLOPT_USERAGENT: c_int = 10_018;
const CURLOPT_HTTPHEADER: c_int = 10_023;
const CURLOPT_CUSTOMREQUEST: c_int = 10_036;
const CURLOPT_NOBODY: c_int = 44;
const CURLOPT_FAILONERROR: c_int = 45;
const CURLOPT_UPLOAD: c_int = 46;
const CURLOPT_POST: c_int = 47;
const CURLOPT_PUT: c_int = 54;
const CURLOPT_POSTFIELDSIZE: c_int = 60;
const CURLOPT_SSL_VERIFYPEER: c_int = 64;
const CURLOPT_CAINFO: c_int = 10_065;
const CURLOPT_HTTPGET: c_int = 80;
const CURLOPT_WRITEFUNCTION: c_int = 20_011;
const CURLOPT_READFUNCTION: c_int = 20_012;
const CURLOPT_POSTFIELDSIZE_LARGE: c_int = 30_120;
const CURLOPT_COPYPOSTFIELDS: c_int = 10_165;

const CURLINFO_STRING: c_int = 0x100_000;
const CURLINFO_LONG: c_int = 0x200_000;
const CURLINFO_DOUBLE: c_int = 0x300_000;
const CURLINFO_OFF_T: c_int = 0x600_000;
const CURLINFO_EFFECTIVE_URL: c_int = CURLINFO_STRING + 1;
const CURLINFO_RESPONSE_CODE: c_int = CURLINFO_LONG + 2;
const CURLINFO_SIZE_DOWNLOAD: c_int = CURLINFO_DOUBLE + 8;
const CURLINFO_CONTENT_TYPE: c_int = CURLINFO_STRING + 18;
const CURLINFO_SIZE_DOWNLOAD_T: c_int = CURLINFO_OFF_T + 8;

type WriteCb = unsafe extern "C" fn(*mut c_char, usize, usize, *mut c_void) -> usize;
type ReadCb = unsafe extern "C" fn(*mut c_char, usize, usize, *mut c_void) -> usize;

const MAGIC_EASY: u32 = 0x4B48_4359; // KHCY
const MAGIC_MULTI: u32 = 0x4B48_434D; // KHCM
const MAGIC_SLIST: u32 = 0x4B48_4353; // KHCS
const KHHTTP_MAGIC: u32 = 0x4B48_4854; // KHHT
const KHHTTP_FLAG_SSL_VERIFY: u32 = 1;

const MAX_HDR_BLOB: usize = 8 * 1024;
/// Cap for one host-fetched response body (G4 shallow packs fit; grow later).
const MAX_BODY_OUT: usize = 4 * 1024 * 1024;
const ERRBUF_LEN: usize = 256;

/// Guest↔host HTTP request (must match `kh-runtime` helpers).
///
/// Layout: 4×u32 + 14×u64 = 128 bytes (v2 adds content-type out slot).
#[repr(C)]
struct KhHttpReq {
    magic: u32,
    version: u32,
    method: u32,
    flags: u32,
    url: u64,
    headers: u64,
    headers_len: u64,
    body: u64,
    body_len: u64,
    ca_path: u64,
    out_body: u64,
    out_body_cap: u64,
    out_body_len: u64,
    out_code: u64,
    errbuf: u64,
    errbuf_cap: u64,
    /// Guest buffer for NUL-terminated `Content-Type` value (no header name).
    out_ctype: u64,
    out_ctype_cap: u64,
}

#[repr(C)]
struct Slist {
    magic: u32,
    data: *mut c_char,
    next: *mut Slist,
}

const EF_POST: u32 = 1;
const EF_PUT: u32 = 2;
const EF_NOBODY: u32 = 4;
const EF_UPLOAD: u32 = 8;
const EF_FAIL: u32 = 16;
const EF_SSL_VERIFY: u32 = 32;
const EF_DONE: u32 = 64;

/// Guest easy handle (`#[repr(C)]` so magic stays at offset 0).
#[repr(C)]
struct Easy {
    magic: u32,
    _pad: u32,
    url: *mut c_char,
    custom_request: *mut c_char,
    user_agent: *mut c_char,
    ca_info: *mut c_char,
    post_fields: *const c_void,
    post_field_size: i64,
    headers: *mut Slist,
    write_fn: Option<WriteCb>,
    write_data: *mut c_void,
    read_fn: Option<ReadCb>,
    read_data: *mut c_void,
    error_buffer: *mut c_char,
    flags: u32,
    response_code: c_long,
    result: c_int,
    download_size: i64,
    effective_url: *mut c_char,
    content_type: *mut c_char,
}

struct MultiEntry {
    easy: *mut Easy,
    done: bool,
    result: c_int,
    msg_delivered: bool,
}

struct Multi {
    magic: u32,
    entries: *mut MultiEntry,
    n_entries: usize,
    cap_entries: usize,
    last_msg: CurlMsg,
}

/// Layout matches libcurl `CURLMsg` on LP64 (msg + pad, easy*, data union).
#[repr(C)]
struct CurlMsg {
    msg: c_int,
    _pad: c_int,
    easy_handle: *mut c_void,
    /// `CURLMsg.data.result` (`CURLcode`) in the low bits of the union.
    data_result: u64,
}

static GLOBAL_INITS: AtomicI32 = AtomicI32::new(0);

static VERSION_STR: &[u8] = b"8.21.0-kakehashi\0";
static HOST_STR: &[u8] = b"aarch64-apple-darwin-kakehashi\0";
static SSL_STR: &[u8] = b"OpenSSL/host\0";
static LIBZ_STR: &[u8] = b"1.2.11-kh\0";
static PROTO_HTTP: &[u8] = b"http\0";
static PROTO_HTTPS: &[u8] = b"https\0";
static mut PROTOCOLS: [*const c_char; 3] = [ptr::null(), ptr::null(), ptr::null()];
static mut VERSION_INFO: CurlVersionInfo = CurlVersionInfo {
    age: CURLVERSION_NOW,
    version: ptr::null(),
    version_num: 0x0008_1500,
    host: ptr::null(),
    features: (1 << 0) | (1 << 2),
    ssl_version: ptr::null(),
    ssl_version_num: 0,
    libz_version: ptr::null(),
    protocols: ptr::null(),
    ares: ptr::null(),
    ares_num: 0,
    libidn: ptr::null(),
    iconv_ver_num: 0,
    libssh_version: ptr::null(),
    brotli_ver_num: 0,
    brotli_version: ptr::null(),
    nghttp2_ver_num: 0,
    nghttp2_version: ptr::null(),
    quic_version: ptr::null(),
    cainfo: ptr::null(),
    capath: ptr::null(),
    zstd_ver_num: 0,
    zstd_version: ptr::null(),
    hyper_version: ptr::null(),
    gsasl_version: ptr::null(),
    feature_names: ptr::null(),
};

#[repr(C)]
struct CurlVersionInfo {
    age: c_int,
    version: *const c_char,
    version_num: u32,
    host: *const c_char,
    features: c_int,
    ssl_version: *const c_char,
    ssl_version_num: c_long,
    libz_version: *const c_char,
    protocols: *const *const c_char,
    ares: *const c_char,
    ares_num: c_int,
    libidn: *const c_char,
    iconv_ver_num: c_int,
    libssh_version: *const c_char,
    brotli_ver_num: u32,
    brotli_version: *const c_char,
    nghttp2_ver_num: u32,
    nghttp2_version: *const c_char,
    quic_version: *const c_char,
    cainfo: *const c_char,
    capath: *const c_char,
    zstd_ver_num: u32,
    zstd_version: *const c_char,
    hyper_version: *const c_char,
    gsasl_version: *const c_char,
    feature_names: *const *const c_char,
}

fn ensure_version_info() {
    // SAFETY: freestanding process-global init; guest is single-threaded here.
    unsafe {
        let vi = &mut *core::ptr::addr_of_mut!(VERSION_INFO);
        if !vi.version.is_null() {
            return;
        }
        vi.version = VERSION_STR.as_ptr().cast();
        vi.host = HOST_STR.as_ptr().cast();
        vi.ssl_version = SSL_STR.as_ptr().cast();
        vi.libz_version = LIBZ_STR.as_ptr().cast();
        let protos = &mut *core::ptr::addr_of_mut!(PROTOCOLS);
        protos[0] = PROTO_HTTP.as_ptr().cast();
        protos[1] = PROTO_HTTPS.as_ptr().cast();
        protos[2] = ptr::null();
        vi.protocols = protos.as_ptr();
    }
}

fn easy_from(p: *mut c_void) -> Option<&'static mut Easy> {
    // Reject PAGEZERO / unrebased pointers before deref.
    let addr = p.addr();
    if addr < crate::stdio::PAGEZERO_END {
        return None;
    }
    let e = unsafe { &mut *p.cast::<Easy>() };
    if e.magic != MAGIC_EASY {
        return None;
    }
    Some(e)
}

fn multi_from(p: *mut c_void) -> Option<&'static mut Multi> {
    if p.is_null() || p.addr() < crate::stdio::PAGEZERO_END {
        return None;
    }
    let m = unsafe { &mut *p.cast::<Multi>() };
    if m.magic != MAGIC_MULTI {
        return None;
    }
    Some(m)
}

#[inline]
fn ptr_live(p: *const c_void) -> bool {
    !p.is_null() && p.addr() >= crate::stdio::PAGEZERO_END
}

fn set_err(easy: &Easy, msg: &[u8]) {
    if easy.error_buffer.is_null() {
        return;
    }
    let n = msg.len().min(ERRBUF_LEN.saturating_sub(1));
    unsafe {
        memcpy(easy.error_buffer.cast(), msg.as_ptr().cast(), n);
        *easy.error_buffer.add(n) = 0;
    }
}

fn dup_cstr(src: *const c_char) -> Option<*mut c_char> {
    if src.is_null() {
        return Some(ptr::null_mut());
    }
    // PAGEZERO / unrebased guest pointers (seen as 0x4000_0000 in G4).
    if src.addr() < crate::stdio::PAGEZERO_END {
        return None;
    }
    let n = unsafe { strlen(src) };
    let p = unsafe { malloc(n.saturating_add(1)) }.cast::<c_char>();
    if p.is_null() {
        return None;
    }
    unsafe {
        memcpy(p.cast(), src.cast(), n.saturating_add(1));
    }
    Some(p)
}

fn free_cstr(p: *mut c_char) {
    if !p.is_null() {
        unsafe {
            free(p.cast());
        }
    }
}

fn headers_blob(list: *mut Slist, out: &mut [u8]) -> usize {
    let mut off = 0_usize;
    let mut cur = list;
    let mut guard = 0_usize;
    while ptr_live(cur.cast()) {
        let node = unsafe { &*cur };
        if node.magic != MAGIC_SLIST {
            break;
        }
        if ptr_live(node.data.cast()) {
            let n = unsafe { strlen(node.data) };
            if off.saturating_add(n).saturating_add(1) > out.len() {
                break;
            }
            unsafe {
                memcpy(out.as_mut_ptr().add(off).cast(), node.data.cast(), n);
            }
            off = off.saturating_add(n);
            if let Some(slot) = out.get_mut(off) {
                *slot = b'\n';
            }
            off = off.saturating_add(1);
        }
        cur = node.next;
        guard = guard.saturating_add(1);
        if guard > 10_000 {
            break;
        }
    }
    off
}

fn method_of(easy: &Easy) -> u32 {
    if easy.flags & EF_NOBODY != 0 {
        2
    } else if easy.flags & EF_POST != 0 || !easy.post_fields.is_null() {
        1
    } else if easy.flags & (EF_PUT | EF_UPLOAD) != 0 {
        3
    } else {
        0
    }
}

unsafe extern "C" fn default_write(
    _ptr: *mut c_char,
    size: usize,
    nmemb: usize,
    _userdata: *mut c_void,
) -> usize {
    size.saturating_mul(nmemb)
}

fn perform_easy(easy: &mut Easy) -> c_int {
    if easy.url.is_null() || !ptr_live(easy.url.cast()) {
        set_err(easy, b"no URL set\0");
        easy.result = CURLE_URL_MALFORMAT;
        easy.flags |= EF_DONE;
        return easy.result;
    }

    let body_cap = MAX_BODY_OUT;
    let body_buf = unsafe { malloc(body_cap) }.cast::<u8>();
    if body_buf.is_null() {
        set_err(easy, b"oom body\0");
        easy.result = CURLE_OUT_OF_MEMORY;
        easy.flags |= EF_DONE;
        return easy.result;
    }

    let mut hdr_storage = [0_u8; MAX_HDR_BLOB];
    let hdr_len = headers_blob(easy.headers, &mut hdr_storage);

    let mut out_len: u64 = 0;
    let mut http_code: u32 = 0;
    let mut err_local = [0_u8; ERRBUF_LEN];
    let mut ctype_local = [0_u8; 128];

    let post_len = if easy.post_field_size >= 0 {
        easy.post_field_size as u64
    } else if ptr_live(easy.post_fields) {
        unsafe { strlen(easy.post_fields.cast()) as u64 }
    } else {
        0
    };

    let mut flags = 0_u32;
    if easy.flags & EF_SSL_VERIFY != 0 {
        flags |= KHHTTP_FLAG_SSL_VERIFY;
    }

    let req = KhHttpReq {
        magic: KHHTTP_MAGIC,
        version: 2,
        method: method_of(easy),
        flags,
        url: easy.url as u64,
        headers: if hdr_len == 0 {
            0
        } else {
            hdr_storage.as_ptr() as u64
        },
        headers_len: hdr_len as u64,
        body: if post_len == 0 {
            0
        } else {
            easy.post_fields as u64
        },
        body_len: post_len,
        ca_path: if ptr_live(easy.ca_info.cast()) {
            easy.ca_info as u64
        } else {
            0
        },
        out_body: body_buf as u64,
        out_body_cap: body_cap as u64,
        out_body_len: core::ptr::from_mut(&mut out_len) as u64,
        out_code: core::ptr::from_mut(&mut http_code) as u64,
        errbuf: err_local.as_mut_ptr() as u64,
        errbuf_cap: ERRBUF_LEN as u64,
        out_ctype: ctype_local.as_mut_ptr() as u64,
        out_ctype_cap: ctype_local.len() as u64,
    };

    let rc = unsafe { sys::helper1(KH_HELPER_HTTP, core::ptr::from_ref(&req) as u64) };
    if rc < 0 {
        let msg: &[u8] = if err_local[0] != 0 {
            &err_local
        } else {
            b"http helper failed\0"
        };
        set_err(easy, msg);
        unsafe {
            free(body_buf.cast());
        }
        easy.result = match (-rc) as i32 {
            28 => CURLE_OPERATION_TIMEDOUT,
            35 => CURLE_SSL_CONNECT_ERROR,
            _ => CURLE_COULDNT_CONNECT,
        };
        easy.flags |= EF_DONE;
        return easy.result;
    }

    easy.response_code = c_long::from(http_code);
    easy.download_size = out_len as i64;
    free_cstr(easy.content_type);
    easy.content_type = if ctype_local[0] != 0 {
        dup_cstr(ctype_local.as_ptr().cast()).unwrap_or(ptr::null_mut())
    } else {
        ptr::null_mut()
    };

    if easy.flags & EF_FAIL != 0 && http_code >= 400 {
        set_err(easy, b"HTTP error\0");
        unsafe {
            free(body_buf.cast());
        }
        easy.result = CURLE_HTTP_RETURNED_ERROR;
        easy.flags |= EF_DONE;
        return easy.result;
    }

    let write = easy.write_fn.unwrap_or(default_write);
    let mut fed = 0_u64;
    while fed < out_len {
        let remain = (out_len - fed) as usize;
        let chunk = remain.min(16 * 1024);
        let p = unsafe { body_buf.add(fed as usize) };
        let n = unsafe { write(p.cast(), 1, chunk, easy.write_data) };
        if n != chunk {
            set_err(easy, b"write callback short\0");
            crate::trace::force_note(b"[kh] write short\n");
            unsafe {
                free(body_buf.cast());
            }
            easy.result = CURLE_WRITE_ERROR;
            easy.flags |= EF_DONE;
            return easy.result;
        }
        fed = fed.saturating_add(chunk as u64);
    }

    unsafe {
        free(body_buf.cast());
    }
    free_cstr(easy.effective_url);
    easy.effective_url = dup_cstr(easy.url).unwrap_or(ptr::null_mut());
    easy.result = CURLE_OK;
    easy.flags |= EF_DONE;
    CURLE_OK
}

// ── exports (no_mangle C ABI; `pub(crate)` like zlib.rs) ─────────────────────

/// C `curl_global_init`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn curl_global_init(_flags: c_long) -> c_int {
    GLOBAL_INITS.fetch_add(1, Ordering::Relaxed);
    ensure_version_info();
    CURLE_OK
}

/// C `curl_global_cleanup`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn curl_global_cleanup() {
    let _ = GLOBAL_INITS.fetch_sub(1, Ordering::Relaxed);
}

/// C `curl_global_sslset`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn curl_global_sslset(
    _id: c_int,
    _name: *const c_char,
    _avail: *mut *const c_void,
) -> c_int {
    CURLSSLSET_OK
}

/// C `curl_version_info`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn curl_version_info(_age: c_int) -> *const c_void {
    ensure_version_info();
    core::ptr::addr_of!(VERSION_INFO).cast()
}

/// C `curl_easy_init`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn curl_easy_init() -> *mut c_void {
    let p = unsafe { malloc(core::mem::size_of::<Easy>()) }.cast::<Easy>();
    if p.is_null() {
        return ptr::null_mut();
    }
    unsafe {
        ptr::write(
            p,
            Easy {
                magic: MAGIC_EASY,
                _pad: 0,
                url: ptr::null_mut(),
                custom_request: ptr::null_mut(),
                user_agent: ptr::null_mut(),
                ca_info: ptr::null_mut(),
                post_fields: ptr::null(),
                post_field_size: -1,
                headers: ptr::null_mut(),
                write_fn: None,
                write_data: ptr::null_mut(),
                read_fn: None,
                read_data: ptr::null_mut(),
                error_buffer: ptr::null_mut(),
                flags: EF_SSL_VERIFY,
                response_code: 0,
                result: CURLE_OK,
                download_size: 0,
                effective_url: ptr::null_mut(),
                content_type: ptr::null_mut(),
            },
        );
    }
    p.cast()
}

/// C `curl_easy_cleanup`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn curl_easy_cleanup(curl: *mut c_void) {
    let Some(easy) = easy_from(curl) else {
        return;
    };
    free_cstr(easy.url);
    free_cstr(easy.custom_request);
    free_cstr(easy.user_agent);
    free_cstr(easy.ca_info);
    free_cstr(easy.effective_url);
    free_cstr(easy.content_type);
    easy.magic = 0;
    unsafe {
        free(curl.cast());
    }
}

/// C `curl_easy_duphandle`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn curl_easy_duphandle(curl: *mut c_void) -> *mut c_void {
    let Some(src) = easy_from(curl) else {
        return ptr::null_mut();
    };
    let dst = unsafe { curl_easy_init() };
    let Some(d) = easy_from(dst) else {
        return ptr::null_mut();
    };
    d.url = dup_cstr(src.url).unwrap_or(ptr::null_mut());
    d.custom_request = dup_cstr(src.custom_request).unwrap_or(ptr::null_mut());
    d.user_agent = dup_cstr(src.user_agent).unwrap_or(ptr::null_mut());
    d.ca_info = dup_cstr(src.ca_info).unwrap_or(ptr::null_mut());
    d.post_fields = src.post_fields;
    d.post_field_size = src.post_field_size;
    d.headers = src.headers;
    d.write_fn = src.write_fn;
    d.write_data = src.write_data;
    d.read_fn = src.read_fn;
    d.read_data = src.read_data;
    d.error_buffer = src.error_buffer;
    d.flags = src.flags & !EF_DONE;
    dst
}

/// Impl for C `curl_easy_setopt` (see `curl_varargs.c` — Apple arm64 stacks the value).
///
/// # Safety
///
/// `param` is the first variadic slot: pointer, `long`, or function pointer.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn kh_curl_easy_setopt_impl(
    curl: *mut c_void,
    option: c_int,
    param: u64,
) -> c_int {
    let Some(easy) = easy_from(curl) else {
        return CURLE_BAD_FUNCTION_ARGUMENT;
    };
    let as_ptr = param as *mut c_void;
    let as_long = param as c_long;
    match option {
        CURLOPT_URL => {
            free_cstr(easy.url);
            easy.url = match dup_cstr(as_ptr.cast()) {
                Some(p) => p,
                None => return CURLE_OUT_OF_MEMORY,
            };
        }
        CURLOPT_WRITEDATA => easy.write_data = as_ptr,
        CURLOPT_WRITEFUNCTION => {
            easy.write_fn = if param == 0 {
                None
            } else {
                // SAFETY: guest passes a C function pointer matching WriteCb.
                Some(unsafe { core::mem::transmute::<u64, WriteCb>(param) })
            };
        }
        CURLOPT_READDATA => easy.read_data = as_ptr,
        CURLOPT_READFUNCTION => {
            easy.read_fn = if param == 0 {
                None
            } else {
                Some(unsafe { core::mem::transmute::<u64, ReadCb>(param) })
            };
        }
        CURLOPT_ERRORBUFFER => {
            easy.error_buffer = if ptr_live(as_ptr.cast_const()) {
                as_ptr.cast()
            } else {
                ptr::null_mut()
            };
        }
        CURLOPT_HTTPHEADER => {
            // Reject PAGEZERO / garbage from a broken caller; null clears.
            easy.headers = if param == 0 || !ptr_live(as_ptr.cast_const()) {
                ptr::null_mut()
            } else {
                as_ptr.cast()
            };
        }
        CURLOPT_POSTFIELDS | CURLOPT_COPYPOSTFIELDS => {
            easy.post_fields = if param == 0 || !ptr_live(as_ptr.cast_const()) {
                ptr::null()
            } else {
                as_ptr.cast_const()
            };
            easy.flags |= EF_POST;
        }
        CURLOPT_POSTFIELDSIZE => easy.post_field_size = as_long,
        CURLOPT_POSTFIELDSIZE_LARGE => easy.post_field_size = param as i64,
        CURLOPT_POST => {
            if as_long != 0 {
                easy.flags |= EF_POST;
            } else {
                easy.flags &= !EF_POST;
            }
        }
        CURLOPT_HTTPGET => {
            if as_long != 0 {
                easy.flags &= !(EF_POST | EF_PUT | EF_UPLOAD);
            }
        }
        CURLOPT_NOBODY => {
            if as_long != 0 {
                easy.flags |= EF_NOBODY;
            } else {
                easy.flags &= !EF_NOBODY;
            }
        }
        CURLOPT_PUT => {
            if as_long != 0 {
                easy.flags |= EF_PUT;
            } else {
                easy.flags &= !EF_PUT;
            }
        }
        CURLOPT_UPLOAD => {
            if as_long != 0 {
                easy.flags |= EF_UPLOAD;
            } else {
                easy.flags &= !EF_UPLOAD;
            }
        }
        CURLOPT_FAILONERROR => {
            if as_long != 0 {
                easy.flags |= EF_FAIL;
            } else {
                easy.flags &= !EF_FAIL;
            }
        }
        CURLOPT_SSL_VERIFYPEER => {
            if as_long != 0 {
                easy.flags |= EF_SSL_VERIFY;
            } else {
                easy.flags &= !EF_SSL_VERIFY;
            }
        }
        CURLOPT_CAINFO => {
            free_cstr(easy.ca_info);
            easy.ca_info = match dup_cstr(as_ptr.cast()) {
                Some(p) => p,
                None => return CURLE_OUT_OF_MEMORY,
            };
        }
        CURLOPT_USERAGENT => {
            free_cstr(easy.user_agent);
            easy.user_agent = match dup_cstr(as_ptr.cast()) {
                Some(p) => p,
                None => return CURLE_OUT_OF_MEMORY,
            };
        }
        CURLOPT_CUSTOMREQUEST => {
            free_cstr(easy.custom_request);
            easy.custom_request = match dup_cstr(as_ptr.cast()) {
                Some(p) => p,
                None => return CURLE_OUT_OF_MEMORY,
            };
        }
        // Soft-accept FOLLOWLOCATION and all other options (newer git).
        _ => {}
    }
    CURLE_OK
}

/// Impl for C `curl_easy_getinfo` (see `curl_varargs.c`).
///
/// # Safety
///
/// `param` is a guest pointer to the out-slot for the requested info type.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn kh_curl_easy_getinfo_impl(
    curl: *mut c_void,
    info: c_int,
    param: u64,
) -> c_int {
    let Some(easy) = easy_from(curl) else {
        return CURLE_BAD_FUNCTION_ARGUMENT;
    };
    if param == 0 || !ptr_live(param as *const c_void) {
        return CURLE_BAD_FUNCTION_ARGUMENT;
    }
    match info {
        CURLINFO_RESPONSE_CODE => unsafe {
            *(param as *mut c_long) = easy.response_code;
        },
        CURLINFO_EFFECTIVE_URL => {
            let url = if easy.effective_url.is_null() {
                easy.url
            } else {
                easy.effective_url
            };
            unsafe {
                *(param as *mut *mut c_char) = url;
            }
        }
        CURLINFO_CONTENT_TYPE => unsafe {
            *(param as *mut *mut c_char) = easy.content_type;
        },
        CURLINFO_SIZE_DOWNLOAD => unsafe {
            *(param as *mut f64) = easy.download_size as f64;
        },
        CURLINFO_SIZE_DOWNLOAD_T => unsafe {
            *(param as *mut i64) = easy.download_size;
        },
        _ => {
            // Soft zeros for unused infos.
            if (info & CURLINFO_DOUBLE) == CURLINFO_DOUBLE {
                unsafe {
                    *(param as *mut f64) = 0.0;
                }
            } else if (info & CURLINFO_LONG) == CURLINFO_LONG {
                unsafe {
                    *(param as *mut c_long) = 0;
                }
            } else if (info & CURLINFO_OFF_T) == CURLINFO_OFF_T {
                unsafe {
                    *(param as *mut i64) = 0;
                }
            } else if (info & CURLINFO_STRING) == CURLINFO_STRING {
                unsafe {
                    *(param as *mut *mut c_void) = ptr::null_mut();
                }
            }
        }
    }
    CURLE_OK
}

/// C `curl_easy_perform`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn curl_easy_perform(curl: *mut c_void) -> c_int {
    let Some(easy) = easy_from(curl) else {
        return CURLE_BAD_FUNCTION_ARGUMENT;
    };
    easy.flags &= !EF_DONE;
    perform_easy(easy)
}

/// C `curl_easy_strerror`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn curl_easy_strerror(code: c_int) -> *const c_char {
    match code {
        CURLE_OK => b"No error\0".as_ptr().cast(),
        CURLE_URL_MALFORMAT => b"URL malformed\0".as_ptr().cast(),
        CURLE_COULDNT_CONNECT => b"Could not connect\0".as_ptr().cast(),
        CURLE_HTTP_RETURNED_ERROR => b"HTTP response code said error\0".as_ptr().cast(),
        CURLE_WRITE_ERROR => b"Failed writing received data\0".as_ptr().cast(),
        CURLE_OUT_OF_MEMORY => b"Out of memory\0".as_ptr().cast(),
        CURLE_OPERATION_TIMEDOUT => b"Timeout\0".as_ptr().cast(),
        CURLE_SSL_CONNECT_ERROR => b"SSL connect error\0".as_ptr().cast(),
        _ => b"curl error\0".as_ptr().cast(),
    }
}

/// C `curl_slist_append`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn curl_slist_append(
    list: *mut c_void,
    data: *const c_char,
) -> *mut c_void {
    let node = unsafe { malloc(core::mem::size_of::<Slist>()) }.cast::<Slist>();
    if node.is_null() {
        return ptr::null_mut();
    }
    let Some(dup) = dup_cstr(data) else {
        unsafe {
            free(node.cast());
        }
        return ptr::null_mut();
    };
    unsafe {
        ptr::write(
            node,
            Slist {
                magic: MAGIC_SLIST,
                data: dup,
                next: ptr::null_mut(),
            },
        );
    }
    if list.is_null() || list.addr() < crate::stdio::PAGEZERO_END {
        return node.cast();
    }
    let mut cur = list.cast::<Slist>();
    let mut guard = 0_usize;
    loop {
        if !ptr_live(cur.cast()) {
            break;
        }
        let n = unsafe { &mut *cur };
        if n.magic != MAGIC_SLIST {
            break;
        }
        if n.next.is_null() {
            n.next = node;
            break;
        }
        if !ptr_live(n.next.cast()) {
            n.next = node;
            break;
        }
        cur = n.next;
        guard = guard.saturating_add(1);
        if guard > 10_000 {
            break;
        }
    }
    list
}

/// C `curl_slist_free_all`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn curl_slist_free_all(list: *mut c_void) {
    let mut cur = list.cast::<Slist>();
    let mut guard = 0_usize;
    while ptr_live(cur.cast()) {
        let node = unsafe { &mut *cur };
        if node.magic != MAGIC_SLIST {
            break;
        }
        let next = node.next;
        free_cstr(node.data);
        node.magic = 0;
        unsafe {
            free(cur.cast());
        }
        cur = next;
        guard = guard.saturating_add(1);
        if guard > 10_000 {
            break;
        }
    }
}

/// C `curl_multi_init`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn curl_multi_init() -> *mut c_void {
    let p = unsafe { malloc(core::mem::size_of::<Multi>()) }.cast::<Multi>();
    if p.is_null() {
        return ptr::null_mut();
    }
    unsafe {
        ptr::write(
            p,
            Multi {
                magic: MAGIC_MULTI,
                entries: ptr::null_mut(),
                n_entries: 0,
                cap_entries: 0,
                last_msg: CurlMsg {
                    msg: 0,
                    _pad: 0,
                    easy_handle: ptr::null_mut(),
                    data_result: 0,
                },
            },
        );
    }
    p.cast()
}

/// C `curl_multi_cleanup`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn curl_multi_cleanup(multi: *mut c_void) -> c_int {
    let Some(m) = multi_from(multi) else {
        return CURLM_BAD_HANDLE;
    };
    if !m.entries.is_null() {
        unsafe {
            free(m.entries.cast());
        }
    }
    m.magic = 0;
    unsafe {
        free(multi.cast());
    }
    CURLM_OK
}

/// C `curl_multi_add_handle`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn curl_multi_add_handle(
    multi: *mut c_void,
    easy: *mut c_void,
) -> c_int {
    let Some(m) = multi_from(multi) else {
        return CURLM_BAD_HANDLE;
    };
    let Some(e) = easy_from(easy) else {
        return CURLM_BAD_EASY_HANDLE;
    };
    e.flags &= !EF_DONE;
    e.result = CURLE_OK;
    if m.n_entries == m.cap_entries {
        let new_cap = if m.cap_entries == 0 {
            4
        } else {
            m.cap_entries.saturating_mul(2)
        };
        let nbytes = new_cap.saturating_mul(core::mem::size_of::<MultiEntry>());
        let p = if m.entries.is_null() {
            unsafe { malloc(nbytes) }
        } else {
            unsafe { realloc(m.entries.cast(), nbytes) }
        }
        .cast::<MultiEntry>();
        if p.is_null() {
            return CURLM_OUT_OF_MEMORY;
        }
        m.entries = p;
        m.cap_entries = new_cap;
    }
    unsafe {
        ptr::write(
            m.entries.add(m.n_entries),
            MultiEntry {
                easy: core::ptr::from_mut(e),
                done: false,
                result: CURLE_OK,
                msg_delivered: false,
            },
        );
    }
    m.n_entries = m.n_entries.saturating_add(1);
    CURLM_OK
}

/// C `curl_multi_remove_handle`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn curl_multi_remove_handle(
    multi: *mut c_void,
    easy: *mut c_void,
) -> c_int {
    let Some(m) = multi_from(multi) else {
        return CURLM_BAD_HANDLE;
    };
    let mut i = 0_usize;
    while i < m.n_entries {
        let ent = unsafe { &mut *m.entries.add(i) };
        if ent.easy.cast::<c_void>() == easy {
            let mut j = i;
            while j.saturating_add(1) < m.n_entries {
                unsafe {
                    let next = ptr::read(m.entries.add(j.saturating_add(1)));
                    ptr::write(m.entries.add(j), next);
                }
                j = j.saturating_add(1);
            }
            m.n_entries = m.n_entries.saturating_sub(1);
            return CURLM_OK;
        }
        i = i.saturating_add(1);
    }
    let _ = CURLM_INTERNAL_ERROR;
    CURLM_OK
}

/// C `curl_multi_perform` — runs unfinished easy handles to completion.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn curl_multi_perform(
    multi: *mut c_void,
    running: *mut c_int,
) -> c_int {
    let Some(m) = multi_from(multi) else {
        return CURLM_BAD_HANDLE;
    };
    let mut i = 0_usize;
    while i < m.n_entries {
        let ent = unsafe { &mut *m.entries.add(i) };
        if !ent.done {
            if let Some(easy) = easy_from(ent.easy.cast()) {
                ent.result = perform_easy(easy);
            } else {
                ent.result = CURLE_FAILED_INIT;
            }
            ent.done = true;
            ent.msg_delivered = false;
        }
        i = i.saturating_add(1);
    }
    if !running.is_null() {
        unsafe {
            *running = 0;
        }
    }
    CURLM_OK
}

/// C `curl_multi_fdset` — no host sockets; work already finished in perform.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn curl_multi_fdset(
    multi: *mut c_void,
    _r: *mut c_void,
    _w: *mut c_void,
    _e: *mut c_void,
    max_fd: *mut c_int,
) -> c_int {
    if multi_from(multi).is_none() {
        return CURLM_BAD_HANDLE;
    }
    if !max_fd.is_null() {
        unsafe {
            *max_fd = -1;
        }
    }
    CURLM_OK
}

/// C `curl_multi_timeout`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn curl_multi_timeout(multi: *mut c_void, ms: *mut c_long) -> c_int {
    if multi_from(multi).is_none() {
        return CURLM_BAD_HANDLE;
    }
    if !ms.is_null() {
        unsafe {
            *ms = 0;
        }
    }
    CURLM_OK
}

/// C `curl_multi_info_read`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn curl_multi_info_read(
    multi: *mut c_void,
    msgs_in_queue: *mut c_int,
) -> *mut c_void {
    let Some(m) = multi_from(multi) else {
        return ptr::null_mut();
    };
    let mut i = 0_usize;
    while i < m.n_entries {
        let ent = unsafe { &mut *m.entries.add(i) };
        if ent.done && !ent.msg_delivered {
            ent.msg_delivered = true;
            m.last_msg = CurlMsg {
                msg: CURLMSG_DONE,
                _pad: 0,
                easy_handle: ent.easy.cast(),
                data_result: ent.result as u64,
            };
            let mut left = 0_i32;
            let mut j = 0_usize;
            while j < m.n_entries {
                let e2 = unsafe { &*m.entries.add(j) };
                if e2.done && !e2.msg_delivered {
                    left = left.saturating_add(1);
                }
                j = j.saturating_add(1);
            }
            if !msgs_in_queue.is_null() {
                unsafe {
                    *msgs_in_queue = left;
                }
            }
            return core::ptr::from_mut(&mut m.last_msg).cast();
        }
        i = i.saturating_add(1);
    }
    if !msgs_in_queue.is_null() {
        unsafe {
            *msgs_in_queue = 0;
        }
    }
    let _ = CURLM_BAD_FUNCTION_ARGUMENT;
    ptr::null_mut()
}

/// C `curl_multi_strerror`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn curl_multi_strerror(code: c_int) -> *const c_char {
    match code {
        CURLM_OK => b"No error\0".as_ptr().cast(),
        CURLM_BAD_HANDLE => b"Invalid multi handle\0".as_ptr().cast(),
        CURLM_BAD_EASY_HANDLE => b"Invalid easy handle\0".as_ptr().cast(),
        CURLM_OUT_OF_MEMORY => b"Out of memory\0".as_ptr().cast(),
        _ => b"curl multi error\0".as_ptr().cast(),
    }
}
