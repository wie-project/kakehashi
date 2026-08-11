//! Soft libc++ iostream surface for modern Apple `ld` (clang G5).
//!
//! Observed SEGV in `ld::Options::parse`: inlined construction of
//! `std::basic_stringstream` via Itanium **VTT/ZTV** loaded from GOT. Missing
//! symbols bound to trampolines; `ldur [vptr,#-0x18]` then read code as an
//! offset → wild store.
//!
//! Soft plan (clean-room, ABI-observed from host libc++ layouts only):
//! - Export ZTV/ZTT with correct **offset immediates** and soft virtfns
//! - Absolute self-pointers filled on first `malloc` / soft entry (not
//!   `__mod_init_func` — Rust ctor section + slide was SEGV under kh)
//! - Soft `ios_base::init` / `locale` / filebuf/ifstream open
//!
//! Not a real iostream: no locale facets, minimal buffering.

#![allow(
    non_snake_case,
    non_upper_case_globals,
    static_mut_refs,
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_ptr_alignment,
    clippy::cast_sign_loss,
    clippy::indexing_slicing,
    clippy::items_after_statements,
    clippy::missing_safety_doc,
    clippy::not_unsafe_ptr_arg_deref,
    clippy::ptr_as_ptr,
    clippy::too_many_arguments,
    clippy::used_underscore_binding,
    function_casts_as_integer,
    // Rust 2024: soft ZTV fill is one big unsafe body; avoid noisy nested blocks.
    unsafe_op_in_unsafe_fn
)]

use core::ffi::{c_char, c_int, c_void};
use core::sync::atomic::{AtomicBool, Ordering};

use crate::dylib::libsystem_c::posix::{close, kh_open_impl};

// ── Soft virtual functions ──────────────────────────────────────────────────

/// Soft complete/deleting dtor: no-op (stack objects; heap rare).
unsafe extern "C" fn soft_dtor(_this: *mut c_void) {}

/// Soft deleting dtor: free if non-null (rare for stream objects on stack).
unsafe extern "C" fn soft_deleting_dtor(this: *mut c_void) {
    if !this.is_null() {
        // Do not free stack storage — soft: no-op same as soft_dtor.
        // Real deleting dtor only for heap; ld uses stack stringstream.
        let _ = this;
    }
}

/// Soft virt returning 0 / null.
unsafe extern "C" fn soft_virt0(_this: *mut c_void) -> usize {
    0
}

/// Soft 1-arg virt: return the arg (legacy).
unsafe extern "C" fn soft_virt_ret1(_this: *mut c_void, a: usize) -> usize {
    a
}

// ── stringbuf / streambuf layout (Apple arm64 libc++, observed) ─────────────
//
//   +0x00 vptr
//   +0x08 locale
//   +0x10 eback  +0x18 gptr  +0x20 egptr
//   +0x28 pbase  +0x30 pptr  +0x38 epptr
//   +0x40 basic_string (24 B, alternate SSO)
//   +0x58 __hm_   (high-water put pointer for str())
//   +0x60 mode    (ios_base openmode; out=0x10, in=0x08)
//
// Modern `ld` inlines `stringstream::str()` as `return string(pbase, hm-pbase)`
// (after hm = max(hm, pptr)). Soft xsputn that only wrote stderr left hm==pbase
// → empty message body → sparse `ld: ` on exit 1.

const SB_PBASE: usize = 0x28;
const SB_PPTR: usize = 0x30;
const SB_EPPTR: usize = 0x38;
const SB_STRING: usize = 0x40;
const SB_HM: usize = 0x58;
const SB_MODE: usize = 0x60;
const MODE_OUT: u32 = 0x10;
const MODE_IN: u32 = 0x08;

#[inline]
unsafe fn sb_load_ptr(this: *mut c_void, off: usize) -> *mut u8 {
    unsafe { this.cast::<u8>().add(off).cast::<*mut u8>().read() }
}

#[inline]
unsafe fn sb_store_ptr(this: *mut c_void, off: usize, p: *mut u8) {
    unsafe {
        this.cast::<u8>().add(off).cast::<*mut u8>().write(p);
    }
}

/// Re-point get/put areas into the embedded `basic_string` (out-mode soft).
///
/// Mirrors ld's local `__init_buf_ptrs` for the common `in|out` case used by
/// stringstream diagnostics — enough for `str()` length = hm − pbase.
unsafe fn soft_init_buf_ptrs(this: *mut c_void) {
    if this.is_null() {
        return;
    }
    let s = unsafe { this.cast::<u8>().add(SB_STRING).cast::<c_void>() };
    let data = crate::dylib::libcxx::string::string_data(s).cast_mut();
    let len = crate::dylib::libcxx::string::string_len(s);
    if data.is_null() {
        return;
    }
    // Short SSO put end at +22; long: one past payload (next overflow grows).
    let room = if len < 22 { 22 } else { len.saturating_add(1) };
    let epptr = unsafe { data.add(room) };
    let pptr = unsafe { data.add(len) };
    unsafe {
        sb_store_ptr(this, 0x10, data); // eback
        sb_store_ptr(this, 0x18, pptr); // gptr
        sb_store_ptr(this, 0x20, pptr); // egptr
        sb_store_ptr(this, SB_PBASE, data);
        sb_store_ptr(this, SB_PPTR, pptr);
        sb_store_ptr(this, SB_EPPTR, epptr);
        let hm = sb_load_ptr(this, SB_HM);
        if hm.is_null() || hm < pptr {
            sb_store_ptr(this, SB_HM, pptr);
        }
        let mode_p = this.cast::<u8>().add(SB_MODE).cast::<u32>();
        let m = mode_p.read();
        if m & MODE_OUT == 0 {
            mode_p.write(m | MODE_OUT | MODE_IN);
        }
    }
}

/// Soft `overflow(int)` — append one char into the embedded string and re-init.
///
/// traits::eof() is typically -1; return that on failure, else the char.
unsafe extern "C" fn soft_overflow(this: *mut c_void, ch: isize) -> isize {
    if this.is_null() {
        return -1;
    }
    // eof
    if ch == -1 {
        return -1;
    }
    let c = (ch as u8) as core::ffi::c_char;
    let s = unsafe { this.cast::<u8>().add(SB_STRING).cast::<c_void>() };
    unsafe {
        let pbase = sb_load_ptr(this, SB_PBASE);
        let pptr = sb_load_ptr(this, SB_PPTR);
        if !pbase.is_null() && !pptr.is_null() && pptr >= pbase {
            // Prefer put-area content (ld `str()` / host size-byte quirks).
            soft_sync_string_from_put(this);
        } else {
            // No put area yet — ignore host short-size quirks; soft empty.
            crate::dylib::libcxx::string::string_clear(s);
        }
        crate::dylib::libcxx::string::string_push_back(s, c);
        soft_init_buf_ptrs(this);
    }
    ch
}

/// If pbase/pptr point into the string buffer, set string length to pptr−pbase.
unsafe fn soft_sync_string_from_put(this: *mut c_void) {
    let pbase = unsafe { sb_load_ptr(this, SB_PBASE) };
    let pptr = unsafe { sb_load_ptr(this, SB_PPTR) };
    if pbase.is_null() || pptr.is_null() || pptr < pbase {
        return;
    }
    let n = unsafe { pptr.offset_from(pbase) as usize };
    if n > (1 << 20) {
        return;
    }
    let s = unsafe { this.cast::<u8>().add(SB_STRING).cast::<c_void>() };
    // Only assign when put area is the string's data (SSO or long heap).
    let data = crate::dylib::libcxx::string::string_data(s);
    if data.is_null() {
        // Empty freestanding string — treat put area as content source.
        crate::dylib::libcxx::string::string_assign_bytes(s, pbase, n);
        return;
    }
    if core::ptr::eq(data, pbase.cast_const()) || n != crate::dylib::libcxx::string::string_len(s) {
        crate::dylib::libcxx::string::string_assign_bytes(s, pbase, n);
    }
}

/// Soft `xsputn` — write into put area / grow string; update `__hm_`.
///
/// Also mirrors bytes to guest stderr so partial diagnostics remain visible
/// even if a later `str()` path is wrong.
unsafe extern "C" fn soft_xsputn(this: *mut c_void, s: *const u8, n: usize) -> usize {
    if !s.is_null() && n > 0 {
        let _ = unsafe {
            crate::kh_core::sys::syscall3(
                crate::kh_core::sys::SYS_WRITE,
                2,
                u64::try_from(s.addr()).unwrap_or(0),
                u64::try_from(n).unwrap_or(0),
            )
        };
    }
    if this.is_null() || s.is_null() || n == 0 {
        return n;
    }
    unsafe {
        let pptr0 = sb_load_ptr(this, SB_PPTR);
        let epptr0 = sb_load_ptr(this, SB_EPPTR);
        if pptr0.is_null() || epptr0.is_null() {
            // No put area: append the whole slice into the freestanding string.
            let str_p = this.cast::<u8>().add(SB_STRING).cast::<c_void>();
            // Host empty short may encode size_byte=22; clear if no put area.
            crate::dylib::libcxx::string::string_clear(str_p);
            let _ = crate::dylib::libcxx::string::string_append_ptr_len(
                str_p,
                s.cast::<core::ffi::c_char>(),
                n,
            );
            soft_init_buf_ptrs(this);
            return n;
        }
    }
    let mut written = 0usize;
    while written < n {
        let mut pptr = unsafe { sb_load_ptr(this, SB_PPTR) };
        let epptr = unsafe { sb_load_ptr(this, SB_EPPTR) };
        if pptr.is_null() || epptr.is_null() || pptr >= epptr {
            // Full put area — grow with the next character, then continue.
            let ch = unsafe { *s.add(written) } as isize;
            let r = unsafe { soft_overflow(this, ch) };
            if r == -1 {
                break;
            }
            written = written.saturating_add(1);
            continue;
        }
        let room = unsafe { epptr.offset_from(pptr) as usize };
        let chunk = (n - written).min(room);
        if chunk == 0 {
            let ch = unsafe { *s.add(written) } as isize;
            if unsafe { soft_overflow(this, ch) } == -1 {
                break;
            }
            written = written.saturating_add(1);
            continue;
        }
        unsafe {
            core::ptr::copy_nonoverlapping(s.add(written), pptr, chunk);
            pptr = pptr.add(chunk);
            sb_store_ptr(this, SB_PPTR, pptr);
            let hm = sb_load_ptr(this, SB_HM);
            if hm.is_null() || hm < pptr {
                sb_store_ptr(this, SB_HM, pptr);
            }
        }
        written = written.saturating_add(chunk);
    }
    // Keep embedded string size in sync for later __init_buf_ptrs / appends.
    unsafe {
        soft_sync_string_from_put(this);
    }
    written
}

/// Soft `xsgetn` for stringbuf — no input side for diagnostics.
unsafe extern "C" fn soft_xsgetn(_this: *mut c_void, _s: *mut u8, _n: usize) -> usize {
    0
}

/// `basic_stringbuf::str() const` → nlist
/// `_ZNKSt3__115basic_stringbufIcNS_11char_traitsIcEENS_9allocatorIcEEE3strEv`
///
/// **libLTO imports this** (not only inlined ld). Without the export, bind
/// lands on `_kh_missing_symbol` and LTO diagnostic / materialize paths that
/// snapshot the stream see garbage/empty error strings (`materialize …: ''`).
///
/// Layout (see module comment): return bytes `[pbase, max(hm, pptr))`, falling
/// back to the embedded `basic_string` when put pointers are unset.
#[unsafe(export_name = "_ZNKSt3__115basic_stringbufIcNS_11char_traitsIcEENS_9allocatorIcEEE3strEv")]
pub(crate) unsafe extern "C" fn stringbuf_str(
    this: *const c_void,
) -> crate::dylib::libcxx::string::StringRep {
    if this.is_null() {
        return crate::dylib::libcxx::string::StringRep::empty();
    }
    let this_mut = this.cast_mut();
    // SAFETY: freestanding stringbuf soft layout; put pointers are either null
    // or point into the embedded string / prior overflow buffer.
    unsafe {
        let pbase = sb_load_ptr(this_mut, SB_PBASE);
        let pptr = sb_load_ptr(this_mut, SB_PPTR);
        let mut hm = sb_load_ptr(this_mut, SB_HM);
        if !pbase.is_null() && !pptr.is_null() && pptr >= pbase {
            if hm.is_null() || hm < pptr {
                hm = pptr;
                sb_store_ptr(this_mut, SB_HM, hm);
            }
            if !hm.is_null() && hm >= pbase {
                let n = hm.offset_from(pbase) as usize;
                if n <= (1 << 20) {
                    return crate::dylib::libcxx::string::StringRep::from_ptr_len(pbase, n);
                }
            }
        }
        // Fallback: copy embedded string (may be empty SSO).
        let s = this_mut.cast::<u8>().add(SB_STRING).cast::<c_void>();
        let data = crate::dylib::libcxx::string::string_data(s);
        let len = crate::dylib::libcxx::string::string_len(s);
        crate::dylib::libcxx::string::StringRep::from_ptr_len(data, len)
    }
}

// Soft filebuf layout (owned by our ctor/open; not host libc++ layout):
//   +0x00 vptr
//   +0x08 unused/locale
//   +0x10..0x38 get/put ptrs (streambuf)
//   +0x40 fd: i32  (-1 closed)
//   +0x44 one-byte underflow hold
// Keep the soft object ≤ ~0x80 so it fits as an ifstream member at +0x18
// inside a ~0x200 fstream (host ifstream is large; we still stay compact).
const FB_FD: usize = 0x40;
const FB_HOLD: usize = 0x44;

#[inline]
unsafe fn filebuf_fd(this: *mut c_void) -> c_int {
    unsafe { this.cast::<u8>().add(FB_FD).cast::<c_int>().read() }
}

/// Soft filebuf `xsgetn` — `read(fd, s, n)`.
///
/// Modern `ld` / `libtapi` load TBDs via `ifstream` → freestanding `filebuf`.
/// Returning 0 left an empty buffer → `tapi error: EFAULT` on the path.
unsafe extern "C" fn file_xsgetn(this: *mut c_void, s: *mut u8, n: usize) -> usize {
    if this.is_null() || s.is_null() || n == 0 {
        return 0;
    }
    let fd = unsafe { filebuf_fd(this) };
    if fd < 0 {
        return 0;
    }
    let ret = unsafe {
        crate::kh_core::sys::syscall3(
            crate::kh_core::sys::SYS_READ,
            u64::from(fd.cast_unsigned()),
            u64::try_from(s.addr()).unwrap_or(0),
            u64::try_from(n).unwrap_or(0),
        )
    };
    if ret < 0 {
        0
    } else {
        usize::try_from(ret).unwrap_or(0)
    }
}

/// Soft filebuf `underflow` — read one byte into hold cell; set get area.
unsafe extern "C" fn file_underflow(this: *mut c_void) -> isize {
    if this.is_null() {
        return -1;
    }
    let hold = unsafe { this.cast::<u8>().add(FB_HOLD) };
    let n = unsafe { file_xsgetn(this, hold, 1) };
    if n == 0 {
        return -1; // EOF
    }
    // eback=gptr=hold, egptr=hold+1
    unsafe {
        sb_store_ptr(this, 0x10, hold);
        sb_store_ptr(this, 0x18, hold);
        sb_store_ptr(this, 0x20, hold.add(1));
    }
    isize::from(unsafe { hold.read() })
}

/// Soft filebuf `uflow` — underflow then advance gptr.
unsafe extern "C" fn file_uflow(this: *mut c_void) -> isize {
    let ch = unsafe { file_underflow(this) };
    if ch == -1 {
        return -1;
    }
    // consume the held byte
    unsafe {
        let gptr = sb_load_ptr(this, 0x18);
        let egptr = sb_load_ptr(this, 0x20);
        if !gptr.is_null() && gptr < egptr {
            sb_store_ptr(this, 0x18, gptr.add(1));
        }
    }
    ch
}

/// Soft filebuf `overflow` — write one byte to fd (out mode).
unsafe extern "C" fn file_overflow(this: *mut c_void, ch: isize) -> isize {
    if this.is_null() || ch == -1 {
        return ch;
    }
    let fd = unsafe { filebuf_fd(this) };
    if fd < 0 {
        return -1;
    }
    let b = ch as u8;
    let ret = unsafe {
        crate::kh_core::sys::syscall3(
            crate::kh_core::sys::SYS_WRITE,
            u64::from(fd.cast_unsigned()),
            u64::try_from(core::ptr::from_ref(&b).addr()).unwrap_or(0),
            1,
        )
    };
    if ret < 0 { -1 } else { ch }
}

/// Soft filebuf `xsputn` — write to fd.
unsafe extern "C" fn file_xsputn(this: *mut c_void, s: *const u8, n: usize) -> usize {
    if this.is_null() || s.is_null() || n == 0 {
        return 0;
    }
    let fd = unsafe { filebuf_fd(this) };
    if fd < 0 {
        return 0;
    }
    let ret = unsafe {
        crate::kh_core::sys::syscall3(
            crate::kh_core::sys::SYS_WRITE,
            u64::from(fd.cast_unsigned()),
            u64::try_from(s.addr()).unwrap_or(0),
            u64::try_from(n).unwrap_or(0),
        )
    };
    if ret < 0 {
        0
    } else {
        usize::try_from(ret).unwrap_or(0)
    }
}

#[inline]
fn fn_usize(f: unsafe extern "C" fn(*mut c_void)) -> usize {
    f as *const () as usize
}

#[inline]
fn fn_usize1(f: unsafe extern "C" fn(*mut c_void) -> usize) -> usize {
    f as *const () as usize
}

#[inline]
fn fn_usize2(f: unsafe extern "C" fn(*mut c_void, usize) -> usize) -> usize {
    f as *const () as usize
}

#[inline]
fn fn_xsputn(f: unsafe extern "C" fn(*mut c_void, *const u8, usize) -> usize) -> usize {
    f as *const () as usize
}

#[inline]
fn fn_overflow(f: unsafe extern "C" fn(*mut c_void, isize) -> isize) -> usize {
    f as *const () as usize
}

// ── stringstream ZTV / ZTT ──────────────────────────────────────────────────
//
// Offsets and slot layout observed from host libc++ (dlsym dump). Soft virt
// pointers replace Apple code. Absolute self-refs filled in mod_init.

const SS_ZTV_WORDS: usize = 64;
const SS_ZTT_WORDS: usize = 12;

#[unsafe(export_name = "_ZTVNSt3__118basic_stringstreamIcNS_11char_traitsIcEENS_9allocatorIcEEEE")]
#[used]
static mut ZTV_STRINGSTREAM: [usize; SS_ZTV_WORDS] = [0; SS_ZTV_WORDS];

#[unsafe(export_name = "_ZTTNSt3__118basic_stringstreamIcNS_11char_traitsIcEENS_9allocatorIcEEEE")]
#[used]
static mut ZTT_STRINGSTREAM: [usize; SS_ZTT_WORDS] = [0; SS_ZTT_WORDS];

/// `basic_ostringstream` — libLTO imports ZTV/ZTT (diag / path formatting).
/// Soft: same construction-vtable shape as stringstream (host sizeof 264).
#[unsafe(export_name = "_ZTVNSt3__119basic_ostringstreamIcNS_11char_traitsIcEENS_9allocatorIcEEEE")]
#[used]
static mut ZTV_OSTRINGSTREAM: [usize; SS_ZTV_WORDS] = [0; SS_ZTV_WORDS];

#[unsafe(export_name = "_ZTTNSt3__119basic_ostringstreamIcNS_11char_traitsIcEENS_9allocatorIcEEEE")]
#[used]
static mut ZTT_OSTRINGSTREAM: [usize; SS_ZTT_WORDS] = [0; SS_ZTT_WORDS];

// ── streambuf / stringbuf ZTV ───────────────────────────────────────────────

const SB_ZTV_WORDS: usize = 24;

#[unsafe(export_name = "_ZTVNSt3__115basic_streambufIcNS_11char_traitsIcEEEE")]
#[used]
static mut ZTV_STREAMBUF: [usize; SB_ZTV_WORDS] = [0; SB_ZTV_WORDS];

#[unsafe(export_name = "_ZTVNSt3__115basic_stringbufIcNS_11char_traitsIcEENS_9allocatorIcEEEE")]
#[used]
static mut ZTV_STRINGBUF: [usize; SB_ZTV_WORDS] = [0; SB_ZTV_WORDS];

/// Soft `basic_filebuf` vtable (not always a guest import — set by our ctor).
/// Separate from stringbuf so `xsgetn`/`underflow` **read the fd**.
#[used]
static mut ZTV_FILEBUF: [usize; SB_ZTV_WORDS] = [0; SB_ZTV_WORDS];

// ── ifstream / ofstream ZTV / ZTT ───────────────────────────────────────────

const IF_ZTV_WORDS: usize = 32;
const IF_ZTT_WORDS: usize = 8;

#[unsafe(export_name = "_ZTVNSt3__114basic_ifstreamIcNS_11char_traitsIcEEEE")]
#[used]
static mut ZTV_IFSTREAM: [usize; IF_ZTV_WORDS] = [0; IF_ZTV_WORDS];

#[unsafe(export_name = "_ZTTNSt3__114basic_ifstreamIcNS_11char_traitsIcEEEE")]
#[used]
static mut ZTT_IFSTREAM: [usize; IF_ZTT_WORDS] = [0; IF_ZTT_WORDS];

#[unsafe(export_name = "_ZTVNSt3__114basic_ofstreamIcNS_11char_traitsIcEEEE")]
#[used]
static mut ZTV_OFSTREAM: [usize; IF_ZTV_WORDS] = [0; IF_ZTV_WORDS];

#[unsafe(export_name = "_ZTTNSt3__114basic_ofstreamIcNS_11char_traitsIcEEEE")]
#[used]
static mut ZTT_OFSTREAM: [usize; IF_ZTT_WORDS] = [0; IF_ZTT_WORDS];

// ── ctype / collate facet ids + soft facet object ───────────────────────────

/// `std::ctype<char>::id` → nlist `__ZNSt3__15ctypeIcE2idE`.
#[unsafe(export_name = "_ZNSt3__15ctypeIcE2idE")]
#[used]
static mut CTYPE_CHAR_ID: [usize; 4] = [0; 4];

/// `std::collate<char>::id` — pulled by live `libLTO` under `-flto`.
#[unsafe(export_name = "_ZNSt3__17collateIcE2idE")]
#[used]
static mut COLLATE_CHAR_ID: [usize; 4] = [0; 4];

/// Soft facet blob: non-null `use_facet` return so live LLVM does not SEGV on
/// null. Layout: Itanium vptr + facet/refcount soft + **ctype `__tab_`**.
///
/// Observed `-flto` SEGV: `LDR W9, [X9, X8, LSL #2]` with `X9=0`, `X8=0x2e`
/// (ASCII `'.'`) → classic `table[c]` with **null table pointer** inside
/// soft facet. Fill pad slots with a real 256-entry mask table.
#[repr(C)]
struct SoftFacetObj {
    vptr: usize,
    /// Soft refcount / base padding; several words also hold `__tab_`-like
    /// pointers so layout skew still hits a valid table.
    pad: [usize; 15],
}

/// Apple `ctype_base::mask` / `_CTYPE_*` (see public `_ctype.h` + `__locale`).
/// Must match `locale.rs` runetype bits — libLTO embeds `std::regex` and uses
/// these masks via `__get_classname` + `ctype` table lookups.
const M_ALPHA: u32 = 0x0000_0100; // _CTYPE_A
const M_CNTRL: u32 = 0x0000_0200; // _CTYPE_C
const M_DIGIT: u32 = 0x0000_0400; // _CTYPE_D
const M_GRAPH: u32 = 0x0000_0800; // _CTYPE_G
const M_LOWER: u32 = 0x0000_1000; // _CTYPE_L
const M_PUNCT: u32 = 0x0000_2000; // _CTYPE_P
const M_SPACE: u32 = 0x0000_4000; // _CTYPE_S
const M_UPPER: u32 = 0x0000_8000; // _CTYPE_U
const M_XDIGIT: u32 = 0x0001_0000; // _CTYPE_X
const M_BLANK: u32 = 0x0002_0000; // _CTYPE_B
const M_PRINT: u32 = 0x0004_0000; // _CTYPE_R
/// libc++ Apple `ctype_base::__regex_word`.
const M_REGEX_WORD: u32 = 0x80;

const fn ascii_ctype_mask(c: u8) -> u32 {
    let mut m = 0_u32;
    if c < 0x20 || c == 0x7f {
        m |= M_CNTRL;
    }
    if c == b' ' || (c >= 0x09 && c <= 0x0d) {
        m |= M_SPACE;
    }
    if c == b' ' || c == b'\t' {
        m |= M_BLANK;
    }
    if c >= b'0' && c <= b'9' {
        m |= M_DIGIT | M_XDIGIT | M_GRAPH | M_PRINT;
    }
    if (c >= b'a' && c <= b'f') || (c >= b'A' && c <= b'F') {
        m |= M_XDIGIT;
    }
    if c >= b'a' && c <= b'z' {
        m |= M_LOWER | M_ALPHA | M_GRAPH | M_PRINT;
    }
    if c >= b'A' && c <= b'Z' {
        m |= M_UPPER | M_ALPHA | M_GRAPH | M_PRINT;
    }
    if c >= 0x21 && c <= 0x7e {
        m |= M_PRINT;
        let alnum =
            (c >= b'0' && c <= b'9') || (c >= b'a' && c <= b'z') || (c >= b'A' && c <= b'Z');
        if !alnum {
            m |= M_PUNCT | M_GRAPH;
        }
    }
    m
}
const fn build_classic_table() -> [u32; 256] {
    let mut t = [0_u32; 256];
    let mut i = 0_usize;
    while i < 256 {
        t[i] = ascii_ctype_mask(i as u8);
        i += 1;
    }
    t
}

/// Soft `ctype<char>::classic_table()` payload (256 masks).
static CLASSIC_CTYPE_TABLE: [u32; 256] = build_classic_table();

/// Itanium vtable: [offset_to_top, typeinfo, d1, d0, virt…] — vptr → slot 2.
static mut SOFT_FACET_VTABLE: [usize; 24] = [0; 24];
static mut SOFT_FACET_OBJ: SoftFacetObj = SoftFacetObj {
    vptr: 0,
    pad: [0; 15],
};
static FACET_READY: AtomicBool = AtomicBool::new(false);

/// Soft virt used for unknown facet methods (safe defaults / identity).
unsafe extern "C" fn soft_facet_virt(
    _this: *mut c_void,
    a: usize,
    _b: usize,
    _c: usize,
    _d: usize,
    _e: usize,
    _f: usize,
    _g: usize,
) -> usize {
    // Identity-ish: many ctype transforms return the input char in `a`/`x1`.
    a
}

/// Soft `do_is(mask, char)`-shaped: x1=mask, x2=char → nonzero if match.
unsafe extern "C" fn soft_ctype_do_is_char(
    _this: *mut c_void,
    mask: usize,
    ch: usize,
    _d: usize,
    _e: usize,
    _f: usize,
    _g: usize,
    _h: usize,
) -> usize {
    let c = (ch & 0xff) as u8;
    let m = CLASSIC_CTYPE_TABLE[c as usize] as usize;
    usize::from((m & mask) != 0)
}

fn ensure_soft_facet() {
    if FACET_READY.load(Ordering::Acquire) {
        return;
    }
    unsafe {
        let vt = &raw mut SOFT_FACET_VTABLE;
        let d1 = fn_usize(soft_dtor);
        let d0 = fn_usize(soft_deleting_dtor);
        let v = fn_usize_facet(soft_facet_virt);
        let vis = fn_usize_facet(soft_ctype_do_is_char);
        (*vt)[0] = 0; // offset_to_top
        (*vt)[1] = 0; // typeinfo soft null
        (*vt)[2] = d1;
        (*vt)[3] = d0;
        // First data virt often `do_is(mask,char)` on ctype — prefer real mask check.
        (*vt)[4] = vis;
        for i in 5..24 {
            (*vt)[i] = v;
        }
        // vptr points at first virtual (index 2).
        let vptr = core::ptr::addr_of!((*vt)[2]) as usize;
        SOFT_FACET_OBJ.vptr = vptr;
        let tab = CLASSIC_CTYPE_TABLE.as_ptr() as usize;
        // Soft refcount-ish + plant table pointer in every pad word so
        // `__tab_` at +8/+16/+… still resolves (layout not frozen to one ABI).
        SOFT_FACET_OBJ.pad[0] = 1;
        for i in 1..15 {
            SOFT_FACET_OBJ.pad[i] = tab;
        }
        // Common: first field after vptr is table on some builds.
        SOFT_FACET_OBJ.pad[0] = tab;
    }
    FACET_READY.store(true, Ordering::Release);
}

fn fn_usize_facet(
    f: unsafe extern "C" fn(*mut c_void, usize, usize, usize, usize, usize, usize, usize) -> usize,
) -> usize {
    f as usize
}

static INIT_DONE: AtomicBool = AtomicBool::new(false);

/// Fill ZTV/ZTT absolute pointers. Safe to call many times.
pub(crate) fn ensure_iostream_vtables() {
    if INIT_DONE.load(Ordering::Acquire) {
        return;
    }
    // Single-flight soft: double-fill is idempotent.
    unsafe {
        init_stringstream_vtables();
        init_ostringstream_vtables();
        init_buf_vtables();
        init_fstream_vtables();
    }
    INIT_DONE.store(true, Ordering::Release);
}

// NOTE: mod_init disabled — guest dylib constructors with Rust `link_section`
// need careful slide validation. Absolute ZTT/ZTV self-pointers are filled on
// first `malloc` / soft iostream entry (`ensure_iostream_vtables`).

unsafe fn init_stringstream_vtables() {
    let ztv = &raw mut ZTV_STRINGSTREAM;
    let ztt = &raw mut ZTT_STRINGSTREAM;
    let base = ztv as *mut usize as usize;
    let d1 = fn_usize(soft_dtor);
    let d0 = fn_usize(soft_deleting_dtor);
    let v0 = fn_usize1(soft_virt0);

    // Zero then place offset immediates (host ABI dump).
    for i in 0..SS_ZTV_WORDS {
        (*ztv)[i] = 0;
    }

    // Primary sub-object group (indices 0..14)
    (*ztv)[0] = 128;
    (*ztv)[1] = 0;
    (*ztv)[2] = 0; // typeinfo soft null
    (*ztv)[3] = d1;
    (*ztv)[4] = d0;
    (*ztv)[5] = 112;
    (*ztv)[6] = (-16_isize) as usize;
    (*ztv)[7] = 0;
    (*ztv)[8] = v0;
    (*ztv)[9] = v0;
    (*ztv)[10] = (-128_isize) as usize;
    (*ztv)[11] = (-128_isize) as usize;
    (*ztv)[12] = 0;
    (*ztv)[13] = v0;
    (*ztv)[14] = v0;

    // Construction-vtable groups used by VTT (offsets 64, 104, 224, 264, …)
    // ZTV+64 = index 8 already set
    // Group at index 25.. (ZTV+200 area for VTT[1] at +224)
    (*ztv)[25] = 128;
    (*ztv)[26] = 0;
    (*ztv)[27] = 0;
    (*ztv)[28] = d1;
    (*ztv)[29] = d0;
    (*ztv)[30] = 112;
    (*ztv)[31] = (-16_isize) as usize;
    (*ztv)[32] = 0;
    (*ztv)[33] = v0;
    (*ztv)[34] = v0;
    (*ztv)[35] = (-128_isize) as usize;
    (*ztv)[36] = (-128_isize) as usize;
    (*ztv)[37] = 0;
    (*ztv)[38] = v0;
    (*ztv)[39] = v0;

    // VTT[2] at ZTV+344 = index 43; preamble at 40..
    (*ztv)[40] = 128;
    (*ztv)[41] = 0;
    (*ztv)[42] = 0;
    (*ztv)[43] = d1;
    (*ztv)[44] = d0;
    (*ztv)[45] = (-128_isize) as usize;
    (*ztv)[46] = (-128_isize) as usize;
    (*ztv)[47] = 0;
    (*ztv)[48] = v0; // VTT[3] at +384 = index 48
    (*ztv)[49] = v0;

    // VTT[4] at +424 = index 53; preamble 50..
    (*ztv)[50] = 112;
    (*ztv)[51] = 0;
    (*ztv)[52] = 0;
    (*ztv)[53] = d1;
    (*ztv)[54] = d0;
    (*ztv)[55] = (-112_isize) as usize;
    (*ztv)[56] = (-112_isize) as usize;
    (*ztv)[57] = 0;
    (*ztv)[58] = v0; // VTT[5] at +464
    (*ztv)[59] = v0;

    // Fill remaining with soft virt
    for i in 15..25 {
        if (*ztv)[i] == 0 {
            (*ztv)[i] = v0;
        }
    }

    // VTT entries → absolute addresses into ZTV (host decode)
    // VTT[0] ZTV+24, [1]+224, [2]+344, [3]+384, [4]+424, [5]+464,
    // [6]+304, [7]+264, [8]+104, [9]+64
    let offs: [usize; 10] = [24, 224, 344, 384, 424, 464, 304, 264, 104, 64];
    for i in 0..SS_ZTT_WORDS {
        (*ztt)[i] = 0;
    }
    for (i, off) in offs.iter().enumerate() {
        (*ztt)[i] = base.wrapping_add(*off);
    }

    // Also embed VTT snapshot at ZTV[15..] like host (some code may scan ZTV)
    for (i, off) in offs.iter().enumerate() {
        let idx = 15usize.wrapping_add(i);
        if idx < SS_ZTV_WORDS {
            (*ztv)[idx] = base.wrapping_add(*off);
        }
    }

    let _ = base;
}

/// Same soft VTT/ZTV pattern as stringstream (libLTO uses ostringstream for
/// some LLVM diagnostic / path formatting under `-flto`).
unsafe fn init_ostringstream_vtables() {
    let ztv = &raw mut ZTV_OSTRINGSTREAM;
    let ztt = &raw mut ZTT_OSTRINGSTREAM;
    let base = ztv as *mut usize as usize;
    let d1 = fn_usize(soft_dtor);
    let d0 = fn_usize(soft_deleting_dtor);
    let v0 = fn_usize1(soft_virt0);

    for i in 0..SS_ZTV_WORDS {
        (*ztv)[i] = 0;
    }
    (*ztv)[0] = 128;
    (*ztv)[1] = 0;
    (*ztv)[2] = 0;
    (*ztv)[3] = d1;
    (*ztv)[4] = d0;
    (*ztv)[5] = 112;
    (*ztv)[6] = (-16_isize) as usize;
    (*ztv)[7] = 0;
    (*ztv)[8] = v0;
    (*ztv)[9] = v0;
    (*ztv)[10] = (-128_isize) as usize;
    (*ztv)[11] = (-128_isize) as usize;
    (*ztv)[12] = 0;
    (*ztv)[13] = v0;
    (*ztv)[14] = v0;
    for i in 15..SS_ZTV_WORDS {
        if (*ztv)[i] == 0 {
            (*ztv)[i] = v0;
        }
    }
    // Mirror the stringstream construction groups (ld / libLTO scan similar slots).
    for &idx in &[25_usize, 40, 50] {
        if idx + 4 < SS_ZTV_WORDS {
            (*ztv)[idx] = 128;
            (*ztv)[idx + 1] = 0;
            (*ztv)[idx + 2] = 0;
            (*ztv)[idx + 3] = d1;
            (*ztv)[idx + 4] = d0;
        }
    }
    let offs: [usize; 10] = [24, 224, 344, 384, 424, 464, 304, 264, 104, 64];
    for i in 0..SS_ZTT_WORDS {
        (*ztt)[i] = 0;
    }
    for (i, off) in offs.iter().enumerate() {
        if i < SS_ZTT_WORDS {
            (*ztt)[i] = base.wrapping_add(*off);
        }
    }
}

unsafe fn init_buf_vtables() {
    // Host libc++ basic_streambuf / basic_stringbuf primary vtable (vptr[-2]=0,
    // vptr[-1]=typeinfo, vptr[0]=D1…):
    //   0 D1, 1 D0, 2 imbue, 3 setbuf, 4 seekoff, 5 seekpos, 6 sync,
    //   7 showmanyc, 8 xsgetn, 9 underflow, 10 uflow, 11 pbackfail,
    //   12 xsputn, 13 overflow
    // Storage: ztv[0]=offset_to_top, ztv[1]=typeinfo, ztv[2+i]=vptr[i].
    let d1 = fn_usize(soft_dtor);
    let d0 = fn_usize(soft_deleting_dtor);
    let v0 = fn_usize1(soft_virt0);
    let v1 = fn_usize2(soft_virt_ret1);
    let v_xsputn = fn_xsputn(soft_xsputn);
    let v_xsgetn = soft_xsgetn as *const () as usize;
    let v_overflow = fn_overflow(soft_overflow);

    for ztv in [&raw mut ZTV_STREAMBUF, &raw mut ZTV_STRINGBUF] {
        for i in 0..SB_ZTV_WORDS {
            (*ztv)[i] = 0;
        }
        (*ztv)[0] = 0; // offset to top
        (*ztv)[1] = 0; // typeinfo soft null
        (*ztv)[2] = d1; // ~D1
        (*ztv)[3] = d0; // ~D0
        (*ztv)[4] = v0; // imbue
        (*ztv)[5] = v1; // setbuf — return arg
        (*ztv)[6] = v0; // seekoff soft
        (*ztv)[7] = v0; // seekpos soft
        (*ztv)[8] = v0; // sync → 0
        (*ztv)[9] = v0; // showmanyc → 0
        (*ztv)[10] = v_xsgetn; // xsgetn
        (*ztv)[11] = v0; // underflow
        (*ztv)[12] = v1; // uflow soft
        (*ztv)[13] = v1; // pbackfail soft
        (*ztv)[14] = v_xsputn; // xsputn ★
        (*ztv)[15] = v_overflow; // overflow ★
        for i in 16..SB_ZTV_WORDS {
            (*ztv)[i] = v0;
        }
    }

    // filebuf: real read/write against the soft fd.
    let v_fxsgetn = file_xsgetn as *const () as usize;
    let v_funder = file_underflow as *const () as usize;
    let v_fuflow = file_uflow as *const () as usize;
    let v_fxsputn = file_xsputn as *const () as usize;
    let v_fover = file_overflow as *const () as usize;
    {
        let ztv = &raw mut ZTV_FILEBUF;
        for i in 0..SB_ZTV_WORDS {
            (*ztv)[i] = 0;
        }
        (*ztv)[0] = 0;
        (*ztv)[1] = 0;
        (*ztv)[2] = d1;
        (*ztv)[3] = d0;
        (*ztv)[4] = v0;
        (*ztv)[5] = v1;
        (*ztv)[6] = v0;
        (*ztv)[7] = v0;
        (*ztv)[8] = v0;
        (*ztv)[9] = v0;
        (*ztv)[10] = v_fxsgetn; // xsgetn
        (*ztv)[11] = v_funder; // underflow
        (*ztv)[12] = v_fuflow; // uflow
        (*ztv)[13] = v1; // pbackfail
        (*ztv)[14] = v_fxsputn; // xsputn
        (*ztv)[15] = v_fover; // overflow
        for i in 16..SB_ZTV_WORDS {
            (*ztv)[i] = v0;
        }
    }
}

unsafe fn init_fstream_vtables() {
    let d1 = fn_usize(soft_dtor);
    let d0 = fn_usize(soft_deleting_dtor);
    let v0 = fn_usize1(soft_virt0);

    // ifstream: primary offset_to_top 424 (0x1a8)
    {
        let ztv = &raw mut ZTV_IFSTREAM;
        let ztt = &raw mut ZTT_IFSTREAM;
        let base = ztv as *mut usize as usize;
        for i in 0..IF_ZTV_WORDS {
            (*ztv)[i] = 0;
        }
        (*ztv)[0] = 424;
        (*ztv)[1] = 0;
        (*ztv)[2] = 0;
        (*ztv)[3] = d1;
        (*ztv)[4] = d0;
        (*ztv)[5] = (-424_isize) as usize;
        (*ztv)[6] = (-424_isize) as usize;
        (*ztv)[7] = 0;
        (*ztv)[8] = v0;
        (*ztv)[9] = v0;
        // more soft
        for i in 10..IF_ZTV_WORDS {
            (*ztv)[i] = v0;
        }
        // preambles for construction vptrs
        // VTT[0]+24, [1]+136, [2]+176, [3]+64
        // Ensure [-0x18] at those landings
        // VTT[0] at +24 = index 3: preamble [0]=424 already
        // VTT[1] at +136 = index 17: need [14]=424
        (*ztv)[14] = 424;
        (*ztv)[15] = 0;
        (*ztv)[16] = 0;
        (*ztv)[17] = d1;
        (*ztv)[18] = d0;
        (*ztv)[19] = (-424_isize) as usize;
        (*ztv)[20] = (-424_isize) as usize;
        // VTT[2] at +176 = index 22
        (*ztv)[21] = 0;
        (*ztv)[22] = v0;
        // VTT[3] at +64 = index 8 already has virt; preamble [5]=-424

        let offs = [24usize, 136, 176, 64];
        for i in 0..IF_ZTT_WORDS {
            (*ztt)[i] = 0;
        }
        for (i, off) in offs.iter().enumerate() {
            (*ztt)[i] = base.wrapping_add(*off);
        }
    }

    // ofstream: offset_to_top 416 (0x1a0)
    {
        let ztv = &raw mut ZTV_OFSTREAM;
        let ztt = &raw mut ZTT_OFSTREAM;
        let base = ztv as *mut usize as usize;
        for i in 0..IF_ZTV_WORDS {
            (*ztv)[i] = 0;
        }
        (*ztv)[0] = 416;
        (*ztv)[1] = 0;
        (*ztv)[2] = 0;
        (*ztv)[3] = d1;
        (*ztv)[4] = d0;
        (*ztv)[5] = (-416_isize) as usize;
        (*ztv)[6] = (-416_isize) as usize;
        (*ztv)[7] = 0;
        (*ztv)[8] = v0;
        (*ztv)[9] = v0;
        for i in 10..IF_ZTV_WORDS {
            (*ztv)[i] = v0;
        }
        (*ztv)[14] = 416;
        (*ztv)[15] = 0;
        (*ztv)[16] = 0;
        (*ztv)[17] = d1;
        (*ztv)[18] = d0;
        (*ztv)[19] = (-416_isize) as usize;
        (*ztv)[20] = (-416_isize) as usize;

        let offs = [24usize, 136, 176, 64];
        for i in 0..IF_ZTT_WORDS {
            (*ztt)[i] = 0;
        }
        for (i, off) in offs.iter().enumerate() {
            (*ztt)[i] = base.wrapping_add(*off);
        }
    }
}

// ── ios_base / locale ───────────────────────────────────────────────────────

/// Soft locale — host `sizeof(std::locale)==8` (shared body pointer).
const LOCALE_SOFT_BODY: usize = 0x0000_4C4F_435F_4B48; // "KH_LOC" tag in low bits

/// `std::locale::locale()` default ctor C1.
#[unsafe(export_name = "_ZNSt3__16localeC1Ev")]
pub(crate) unsafe extern "C" fn locale_ctor(this: *mut c_void) {
    ensure_iostream_vtables();
    if this.is_null() {
        return;
    }
    unsafe {
        // Non-null fake shared body so null checks pass.
        this.cast::<usize>().write(LOCALE_SOFT_BODY);
    }
}

/// `std::locale::locale(locale const&)` copy ctor C1.
///
/// Observed: modern `ld` under `-flto` enters live `libLTO` which copies
/// locales; missing symbol exited with freestanding code 127.
#[unsafe(export_name = "_ZNSt3__16localeC1ERKS0_")]
pub(crate) unsafe extern "C" fn locale_copy_ctor(this: *mut c_void, other: *const c_void) {
    ensure_iostream_vtables();
    if this.is_null() {
        return;
    }
    let body = if other.is_null() {
        LOCALE_SOFT_BODY
    } else {
        unsafe { other.cast::<usize>().read() }
    };
    let body = if body == 0 { LOCALE_SOFT_BODY } else { body };
    unsafe {
        this.cast::<usize>().write(body);
    }
}

/// Complete-object copy ctor (same soft body model).
#[unsafe(export_name = "_ZNSt3__16localeC2ERKS0_")]
pub(crate) unsafe extern "C" fn locale_copy_ctor_c2(this: *mut c_void, other: *const c_void) {
    unsafe { locale_copy_ctor(this, other) }
}

/// `std::locale::~locale()` D1.
#[unsafe(export_name = "_ZNSt3__16localeD1Ev")]
pub(crate) unsafe extern "C" fn locale_dtor(this: *mut c_void) {
    if this.is_null() {
        return;
    }
    unsafe {
        this.cast::<usize>().write(0);
    }
}

/// `locale::use_facet(id const&)` → soft facet object (never null).
///
/// Observed: `-flto` link enters live `libLTO`, which copies locales and calls
/// `use_facet`; returning null SEGVd at `addr=0`. One soft facet + soft vtable
/// is enough to pass trivial non-bitcode paths; real facets still on demand.
#[unsafe(export_name = "_ZNKSt3__16locale9use_facetERNS0_2idE")]
pub(crate) unsafe extern "C" fn locale_use_facet(
    _this: *const c_void,
    _id: *const c_void,
) -> *mut c_void {
    ensure_iostream_vtables();
    ensure_soft_facet();
    core::ptr::addr_of_mut!(SOFT_FACET_OBJ).cast::<c_void>()
}

/// `locale::has_facet(id const&) const` → true (pairs with soft `use_facet`).
#[unsafe(export_name = "_ZNKSt3__16locale9has_facetERKNS0_2idE")]
pub(crate) unsafe extern "C" fn locale_has_facet(_this: *const c_void, _id: *const c_void) -> bool {
    true
}

/// `locale::name() const` → empty soft string ("C" / `*` not modeled).
///
/// libLTO pulls this; return empty `basic_string` by value (AArch64 sret).
#[unsafe(export_name = "_ZNKSt3__16locale4nameEv")]
pub(crate) unsafe extern "C" fn locale_name(
    _this: *const c_void,
) -> crate::dylib::libcxx::string::StringRep {
    crate::dylib::libcxx::string::StringRep::empty()
}

/// `std::__1::__get_classname(char const*, bool)` → `ctype_base::mask` (`uint32_t`).
///
/// Public libc++ (`regex`): character-class name → Apple `_CTYPE_*` mask used by
/// embedded `std::basic_regex` inside live `libLTO`. Returning a pointer (old soft
/// demangle stub) made `[[:digit:]]` never match →
/// `Invalid bitcode version (Producer: 'APPLE_1_…' Reader: '…')`.
///
/// Spec: MacOSX.sdk `c++/v1/regex` + native `std::__get_classname` values.
#[unsafe(export_name = "_ZNSt3__115__get_classnameEPKcb")]
pub(crate) unsafe extern "C" fn get_classname(name: *const c_char, icase: bool) -> u32 {
    if name.is_null() {
        return 0;
    }
    // Read up to 16 bytes of class name (longest std names are short).
    let mut buf = [0_u8; 16];
    let mut n = 0_usize;
    unsafe {
        while n < buf.len() {
            let b = *name.add(n) as u8;
            if b == 0 {
                break;
            }
            // Fold ASCII upper for case-insensitive names.
            buf[n] = if b.is_ascii_uppercase() { b + 32 } else { b };
            n += 1;
        }
    }
    let s = core::str::from_utf8(&buf[..n]).unwrap_or("");
    let mut m = match s {
        "d" | "digit" => M_DIGIT,
        "xdigit" => M_XDIGIT,
        "a" | "alpha" => M_ALPHA,
        "alnum" => M_ALPHA | M_DIGIT,
        "s" | "space" => M_SPACE,
        "blank" => M_BLANK,
        "c" | "cntrl" => M_CNTRL,
        "g" | "graph" => M_GRAPH,
        "l" | "lower" => M_LOWER,
        "u" | "upper" => M_UPPER,
        "p" | "print" => M_PRINT,
        "punct" => M_PUNCT,
        // Apple libc++: "w" → alnum | __regex_word; bare "word" falls through (0).
        "w" => M_ALPHA | M_DIGIT | M_REGEX_WORD,
        _ => 0,
    };
    // When icase, alpha classes include both cases (host libc++ does this).
    if icase && m != 0 && m & (M_LOWER | M_UPPER | M_ALPHA) != 0 {
        m |= M_LOWER | M_UPPER | M_ALPHA;
    }
    m
}

/// `std::__1::__get_collation_name(char const*)` — collate facet name helper.
///
/// Soft: return `"C"` (POSIX default collate) or the input when non-null.
#[unsafe(export_name = "_ZNSt3__120__get_collation_nameEPKc")]
pub(crate) unsafe extern "C" fn get_collation_name(name: *const c_char) -> *const c_char {
    if name.is_null() {
        static C_LOCALE: &[u8] = b"C\0";
        return C_LOCALE.as_ptr().cast();
    }
    name
}

/// `ios_base::init(void* sb)`.
///
/// Soft: install the streambuf and clear a few known `ios_base` / `basic_ios`
/// fields. **Do not bulk-zero a large region** — modern Apple `ld`
/// `checkUndefines` builds a stack `stringstream` whose virtual-base `this`
/// can sit near (or at) a local `vector` of undefined symbols. A `memset` of
/// 0x100 (or even 0x90) from that `this` stomps the vector begin/end and yields
/// empty undef diagnostics:
/// ```text
/// Undefined symbols for architecture arm64:
/// ld: symbol(s) not found for architecture
/// ```
/// Field offsets are ABI-observed for Apple arm64 libc++ (not a paste of headers).
#[unsafe(export_name = "_ZNSt3__18ios_base4initEPv")]
pub(crate) unsafe extern "C" fn ios_base_init(this: *mut c_void, sb: *mut c_void) {
    ensure_iostream_vtables();
    if this.is_null() {
        return;
    }
    unsafe {
        let base = this.cast::<u8>();
        // rdbuf: common placements at +0x00 (some subobjects) and +0x20 (basic_ios).
        base.cast::<*mut c_void>().write(sb);
        base.add(0x20).cast::<*mut c_void>().write(sb);
        // iostate at +0x20.. also used as flags word in some layouts — set goodbit=0
        // only if not the same slot we just used for rdbuf; use +0x28 for state.
        base.add(0x28).cast::<u32>().write(0); // rdstate goodbit
        base.add(0x2c).cast::<u32>().write(0); // exceptions
        // precision / width (isize pair around +0x30)
        base.add(0x30).cast::<usize>().write(6); // precision default
        base.add(0x38).cast::<isize>().write(0); // width
        // fmtflags at +0x40-ish
        base.add(0x40).cast::<u32>().write(0x1000); // skipws|dec-ish soft default
        // clear small tail used by post-init stores (+0x88..+0x90) without a bulk wipe.
        base.add(0x88).cast::<u64>().write(0);
    }
}

/// `ios_base::clear(iostate)`.
#[unsafe(export_name = "_ZNSt3__18ios_base5clearEj")]
pub(crate) unsafe extern "C" fn ios_base_clear(this: *mut c_void, state: u32) {
    if this.is_null() {
        return;
    }
    // Soft: store state at +0x20
    unsafe {
        this.cast::<u32>().add(8).write(state);
    }
}

/// Soft locale return (8 B → x0 on AArch64).
#[repr(C)]
pub(crate) struct SoftLocale {
    ptr: usize,
}

/// `ios_base::getloc() const` → default locale by value.
#[unsafe(export_name = "_ZNKSt3__18ios_base6getlocEv")]
pub(crate) unsafe extern "C" fn ios_base_getloc(_this: *const c_void) -> SoftLocale {
    SoftLocale {
        ptr: 0x0000_4C4F_435F_4B48,
    }
}

// ── stream dtors / operators ────────────────────────────────────────────────

/// `basic_ostream::~basic_ostream()` D2.
#[unsafe(export_name = "_ZNSt3__113basic_ostreamIcNS_11char_traitsIcEEED2Ev")]
pub(crate) unsafe extern "C" fn ostream_dtor_d2(_this: *mut c_void) {}

/// `basic_istream::~basic_istream()` D2.
#[unsafe(export_name = "_ZNSt3__113basic_istreamIcNS_11char_traitsIcEEED2Ev")]
pub(crate) unsafe extern "C" fn istream_dtor_d2(_this: *mut c_void) {}

/// `basic_iostream::~basic_iostream()` D2.
#[unsafe(export_name = "_ZNSt3__114basic_iostreamIcNS_11char_traitsIcEEED2Ev")]
pub(crate) unsafe extern "C" fn iostream_dtor_d2(_this: *mut c_void) {}

/// `basic_ios::~basic_ios()` D2.
#[unsafe(export_name = "_ZNSt3__19basic_iosIcNS_11char_traitsIcEEED2Ev")]
pub(crate) unsafe extern "C" fn basic_ios_dtor_d2(_this: *mut c_void) {}

/// `basic_ostream::sentry::sentry(ostream&)`.
#[unsafe(export_name = "_ZNSt3__113basic_ostreamIcNS_11char_traitsIcEEE6sentryC1ERS3_")]
pub(crate) unsafe extern "C" fn ostream_sentry_ctor(this: *mut c_void, os: *mut c_void) {
    if this.is_null() {
        return;
    }
    unsafe {
        // layout: { ostream*, ok bool }
        this.cast::<usize>().write(os as usize);
        this.cast::<u8>().add(8).write(1);
    }
}

/// `basic_ostream::sentry::~sentry()`.
#[unsafe(export_name = "_ZNSt3__113basic_ostreamIcNS_11char_traitsIcEEE6sentryD1Ev")]
pub(crate) unsafe extern "C" fn ostream_sentry_dtor(_this: *mut c_void) {}

/// `basic_istream::sentry::sentry(istream&, bool)`.
#[unsafe(export_name = "_ZNSt3__113basic_istreamIcNS_11char_traitsIcEEE6sentryC1ERS3_b")]
pub(crate) unsafe extern "C" fn istream_sentry_ctor(
    this: *mut c_void,
    is: *mut c_void,
    _noskip: bool,
) {
    if this.is_null() {
        return;
    }
    unsafe {
        this.cast::<usize>().write(is as usize);
        this.cast::<u8>().add(8).write(1);
    }
}

/// Soft: write decimal digits into the stream's rdbuf via `xsputn`.
unsafe fn ostream_put_decimal(this: *mut c_void, mut v: u64, neg: bool) {
    if this.is_null() {
        return;
    }
    let mut buf = [0u8; 24];
    let mut i = buf.len();
    if v == 0 {
        i -= 1;
        buf[i] = b'0';
    } else {
        while v > 0 && i > 1 {
            i -= 1;
            buf[i] = b'0' + (v % 10) as u8;
            v /= 10;
        }
    }
    if neg && i > 0 {
        i -= 1;
        buf[i] = b'-';
    }
    let digs = &buf[i..];
    // Mirror to stderr for sparse-diagnostic recovery.
    let _ = unsafe {
        crate::kh_core::sys::syscall3(
            crate::kh_core::sys::SYS_WRITE,
            2,
            u64::try_from(digs.as_ptr().addr()).unwrap_or(0),
            u64::try_from(digs.len()).unwrap_or(0),
        )
    };
    // rdbuf offsets observed for stringstream/ostream (basic_ios +0x28, etc.).
    for off in [0x28usize, 0x98, 0x20, 0x0, 0x18] {
        let cand = unsafe { this.cast::<u8>().add(off).cast::<*mut c_void>().read() };
        if cand.is_null() {
            continue;
        }
        // Heuristic: candidate looks like a streambuf if first word is a code/data ptr.
        let vptr = unsafe { cand.cast::<usize>().read() };
        if vptr < 0x1000 {
            continue;
        }
        let _ = unsafe { soft_xsputn(cand, digs.as_ptr(), digs.len()) };
        break;
    }
}

/// `operator<<(ostream&, int)`.
#[unsafe(export_name = "_ZNSt3__113basic_ostreamIcNS_11char_traitsIcEEElsEi")]
pub(crate) unsafe extern "C" fn ostream_insert_int(this: *mut c_void, v: c_int) -> *mut c_void {
    ensure_iostream_vtables();
    if v < 0 {
        unsafe {
            ostream_put_decimal(this, (-i64::from(v)) as u64, true);
        }
    } else {
        unsafe {
            ostream_put_decimal(this, v as u64, false);
        }
    }
    this
}

/// `operator<<(ostream&, unsigned long long)`.
#[unsafe(export_name = "_ZNSt3__113basic_ostreamIcNS_11char_traitsIcEEElsEy")]
pub(crate) unsafe extern "C" fn ostream_insert_ull(this: *mut c_void, v: u64) -> *mut c_void {
    ensure_iostream_vtables();
    unsafe {
        ostream_put_decimal(this, v, false);
    }
    this
}

/// `operator<<(ostream&, unsigned int)`.
#[unsafe(export_name = "_ZNSt3__113basic_ostreamIcNS_11char_traitsIcEEElsEj")]
pub(crate) unsafe extern "C" fn ostream_insert_uint(this: *mut c_void, v: u32) -> *mut c_void {
    ensure_iostream_vtables();
    unsafe {
        ostream_put_decimal(this, u64::from(v), false);
    }
    this
}

/// `operator<<(ostream&, unsigned long)` (LP64 = u64).
#[unsafe(export_name = "_ZNSt3__113basic_ostreamIcNS_11char_traitsIcEEElsEm")]
pub(crate) unsafe extern "C" fn ostream_insert_ulong(this: *mut c_void, v: u64) -> *mut c_void {
    unsafe { ostream_insert_ull(this, v) }
}

/// `operator<<(ostream&, unsigned short)`.
#[unsafe(export_name = "_ZNSt3__113basic_ostreamIcNS_11char_traitsIcEEElsEt")]
pub(crate) unsafe extern "C" fn ostream_insert_ushort(this: *mut c_void, v: u16) -> *mut c_void {
    ensure_iostream_vtables();
    unsafe {
        ostream_put_decimal(this, u64::from(v), false);
    }
    this
}

/// `operator<<(ostream&, void const*)` — hex-ish soft decimal of address.
#[unsafe(export_name = "_ZNSt3__113basic_ostreamIcNS_11char_traitsIcEEElsEPKv")]
pub(crate) unsafe extern "C" fn ostream_insert_ptr(
    this: *mut c_void,
    p: *const c_void,
) -> *mut c_void {
    ensure_iostream_vtables();
    unsafe {
        ostream_put_decimal(this, p.addr() as u64, false);
    }
    this
}

/// `operator<<(ostream&, double)` — soft fixed-ish decimal (no full printf).
#[unsafe(export_name = "_ZNSt3__113basic_ostreamIcNS_11char_traitsIcEEElsEd")]
pub(crate) unsafe extern "C" fn ostream_insert_double(this: *mut c_void, v: f64) -> *mut c_void {
    ensure_iostream_vtables();
    // Soft: truncate toward zero to integer part only (enough for version-ish dumps).
    // `1.844…e19` ≈ u64::MAX without `u64 as f64` (mantissa cannot hold all u64).
    let neg = v < 0.0;
    let abs = if neg { -v } else { v };
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let whole = if abs >= 1.844_674_407_370_955_2e19 {
        u64::MAX
    } else {
        abs as u64
    };
    unsafe {
        ostream_put_decimal(this, whole, neg);
    }
    this
}

// ── filebuf / ifstream / ofstream ───────────────────────────────────────────

/// Soft filebuf: streambuf ptrs + fd + hold (must fit as ifstream member).
const FILEBUF_BYTES: usize = 0x80;
const FSTREAM_BYTES: usize = 0x200;

/// `basic_filebuf::basic_filebuf()` C1.
#[unsafe(export_name = "_ZNSt3__113basic_filebufIcNS_11char_traitsIcEEEC1Ev")]
pub(crate) unsafe extern "C" fn filebuf_ctor(this: *mut c_void) {
    ensure_iostream_vtables();
    if this.is_null() {
        return;
    }
    unsafe {
        core::ptr::write_bytes(this.cast::<u8>(), 0, FILEBUF_BYTES);
        // vptr = ZTV_FILEBUF + 0x10 (first virtfn)
        let v = (&raw const ZTV_FILEBUF as *const usize as usize).wrapping_add(0x10);
        this.cast::<usize>().write(v);
        // fd = -1
        this.cast::<u8>().add(FB_FD).cast::<c_int>().write(-1);
    }
}

/// `basic_filebuf::~basic_filebuf()` D1.
#[unsafe(export_name = "_ZNSt3__113basic_filebufIcNS_11char_traitsIcEEED1Ev")]
pub(crate) unsafe extern "C" fn filebuf_dtor(this: *mut c_void) {
    if this.is_null() {
        return;
    }
    unsafe {
        let fd = filebuf_fd(this);
        if fd >= 0 {
            close(fd);
            this.cast::<u8>().add(FB_FD).cast::<c_int>().write(-1);
        }
    }
}

/// `basic_filebuf::open(char const*, openmode)` → this or null.
#[unsafe(export_name = "_ZNSt3__113basic_filebufIcNS_11char_traitsIcEEE4openEPKcj")]
pub(crate) unsafe extern "C" fn filebuf_open(
    this: *mut c_void,
    path: *const c_char,
    mode: u32,
) -> *mut c_void {
    if this.is_null() || path.is_null() {
        return core::ptr::null_mut();
    }
    // openmode bits (libc++): app=0x01, ate=0x02, binary=0x04, in=0x08, out=0x10, trunc=0x20
    let inn = mode & 0x08 != 0;
    let out = mode & 0x10 != 0;
    let trunc = mode & 0x20 != 0;
    let app = mode & 0x01 != 0;
    // Darwin open flags (same as stdio.rs).
    let mut flags: c_int = match (inn, out) {
        (true, true) => 2,  // O_RDWR
        (false, true) => 1, // O_WRONLY
        _ => 0,             // O_RDONLY
    };
    if out {
        flags |= 0x200; // O_CREAT
    }
    if trunc {
        flags |= 0x400; // O_TRUNC
    }
    if app {
        flags |= 0x8; // O_APPEND
    }
    let fd = unsafe { kh_open_impl(path, flags, 0o666) };
    if fd < 0 {
        return core::ptr::null_mut();
    }
    unsafe {
        // Ensure filebuf vtable (may open without going through our C1).
        let v = (&raw const ZTV_FILEBUF as *const usize as usize).wrapping_add(0x10);
        this.cast::<usize>().write(v);
        this.cast::<u8>().add(FB_FD).cast::<c_int>().write(fd);
    }
    this
}

/// `basic_ifstream::open(char const*, openmode)`.
#[unsafe(export_name = "_ZNSt3__114basic_ifstreamIcNS_11char_traitsIcEEE4openEPKcj")]
pub(crate) unsafe extern "C" fn ifstream_open(
    this: *mut c_void,
    path: *const c_char,
    mode: u32,
) -> *mut c_void {
    ensure_iostream_vtables();
    if this.is_null() {
        return core::ptr::null_mut();
    }
    // Host arm64: `ifstream::rdbuf()` is at +0x10 (observed); sizeof(filebuf)=408.
    let fb = unsafe { this.cast::<u8>().add(0x10).cast::<c_void>() };
    let r = unsafe { filebuf_open(fb, path, mode | 0x08) };
    if r.is_null() {
        return core::ptr::null_mut();
    }
    this
}

/// Soft helpers used if ifstream/ofstream constructors are out-of-line (some TUs).
#[unsafe(export_name = "_ZNSt3__114basic_ifstreamIcNS_11char_traitsIcEEEC1Ev")]
pub(crate) unsafe extern "C" fn ifstream_ctor(this: *mut c_void) {
    ensure_iostream_vtables();
    if this.is_null() {
        return;
    }
    unsafe {
        core::ptr::write_bytes(this.cast::<u8>(), 0, FSTREAM_BYTES);
        let base = &raw const ZTV_IFSTREAM as *const usize as usize;
        this.cast::<usize>().write(base.wrapping_add(24));
    }
}

#[unsafe(export_name = "_ZNSt3__114basic_ofstreamIcNS_11char_traitsIcEEEC1Ev")]
pub(crate) unsafe extern "C" fn ofstream_ctor(this: *mut c_void) {
    ensure_iostream_vtables();
    if this.is_null() {
        return;
    }
    unsafe {
        core::ptr::write_bytes(this.cast::<u8>(), 0, FSTREAM_BYTES);
        let base = &raw const ZTV_OFSTREAM as *const usize as usize;
        this.cast::<usize>().write(base.wrapping_add(24));
    }
}
