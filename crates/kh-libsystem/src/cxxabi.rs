//! Minimal C++ / Itanium ABI stubs so C++ guests (e.g. `7zz`) can bind.
//!
//! These are **not** a real libc++abi / libunwind. Unwind and exception paths
//! abort via `_exit`. Operators `new`/`delete` forward to the bump heap.
//!
//! Darwin nlist names (as shown by `nm`) use an extra leading underscore; we set
//! [`export_name`] so the linker emits the exact strings guests import from
//! `libc++.1.dylib` (aliased to this dylib in the bottle).

use core::ffi::{c_int, c_void};

use crate::heap::{free, malloc};
use crate::process::exit_now;
use crate::trace;

// ── operators new / delete ──────────────────────────────────────────────────

/// `void* operator new(size_t)` → nlist `__Znwm`.
#[unsafe(export_name = "_Znwm")]
pub(crate) unsafe extern "C" fn op_new(size: usize) -> *mut c_void {
    trace::note_size(b"operator new", size);
    // SAFETY: bump malloc.
    let p = unsafe { malloc(size.max(1)) };
    if p.is_null() {
        // Match common freestanding behavior: abort on OOM (no exceptions yet).
        trace::note(b"[kh-libsystem] operator new OOM\n");
        unsafe {
            exit_now(1);
        }
    }
    p
}

/// `void* operator new[](size_t)` → nlist `__Znam`.
#[unsafe(export_name = "_Znam")]
pub(crate) unsafe extern "C" fn op_new_array(size: usize) -> *mut c_void {
    trace::note_size(b"operator new[]", size);
    // SAFETY: same as new.
    unsafe { op_new(size) }
}

/// `void operator delete(void*)` → nlist `__ZdlPv`.
#[unsafe(export_name = "_ZdlPv")]
pub(crate) unsafe extern "C" fn op_delete(ptr: *mut c_void) {
    trace::note_ptr(b"operator delete", ptr.addr());
    // SAFETY: bump free.
    unsafe {
        free(ptr);
    }
}

/// `void operator delete[](void*)` → nlist `__ZdaPv`.
#[unsafe(export_name = "_ZdaPv")]
pub(crate) unsafe extern "C" fn op_delete_array(ptr: *mut c_void) {
    trace::note_ptr(b"operator delete[]", ptr.addr());
    // SAFETY: bump free.
    unsafe {
        free(ptr);
    }
}

/// `void* operator new(size_t, nothrow_t const&)` → nlist `__ZnwmRKSt9nothrow_t`.
#[unsafe(export_name = "_ZnwmRKSt9nothrow_t")]
pub(crate) unsafe extern "C" fn op_new_nothrow(size: usize, _nt: *const c_void) -> *mut c_void {
    // SAFETY: freestanding malloc; nothrow returns null on OOM.
    let p = unsafe { malloc(size.max(1)) };
    if p.is_null() {
        trace::note(b"[kh-libsystem] operator new(nothrow) OOM\n");
    }
    p
}

/// `void* operator new(size_t, align_val_t, nothrow_t const&)` →
/// nlist `__ZnwmSt11align_val_tRKSt9nothrow_t`.
///
/// Freestanding heap is already well-aligned for typical `align_val_t`; we
/// over-allocate when `align > 16` and return an aligned address (original
/// base is not recovered — aligned `delete` below still calls `free` on the
/// pointer the guest was given; heap tolerates free of interior pointers only
/// if we stash the base. Soft path: over-alloc + store base immediately before
/// the returned pointer.
#[unsafe(export_name = "_ZnwmSt11align_val_tRKSt9nothrow_t")]
pub(crate) unsafe extern "C" fn op_new_aligned_nothrow(
    size: usize,
    align: usize,
    _nt: *const c_void,
) -> *mut c_void {
    let align = align.max(1).next_power_of_two().max(8);
    let size = size.max(1);
    // header (base ptr) + padding + payload
    let total = size.saturating_add(align).saturating_add(8);
    let raw = unsafe { malloc(total) };
    if raw.is_null() {
        trace::note(b"[kh-libsystem] operator new(align,nothrow) OOM\n");
        return core::ptr::null_mut();
    }
    let raw_addr = raw.addr();
    let payload = raw_addr
        .saturating_add(8)
        .saturating_add(align.saturating_sub(1))
        & !(align.saturating_sub(1));
    // SAFETY: payload is within [raw+8, raw+total).
    let out = core::ptr::with_exposed_provenance_mut::<c_void>(payload);
    // Stash original base immediately before payload for aligned delete.
    let stash_addr = payload.saturating_sub(8);
    let stash = core::ptr::with_exposed_provenance_mut::<*mut c_void>(stash_addr);
    unsafe {
        stash.write(raw);
    }
    out
}

/// `std::set_new_handler` → nlist `__ZSt15set_new_handlerPFvvE` (returns old).
#[unsafe(export_name = "_ZSt15set_new_handlerPFvvE")]
pub(crate) unsafe extern "C" fn set_new_handler(
    _new_p: Option<unsafe extern "C" fn()>,
) -> Option<unsafe extern "C" fn()> {
    // Soft: no handler chain yet.
    None
}

/// `std::get_new_handler` → nlist `__ZSt15get_new_handlerv`.
#[unsafe(export_name = "_ZSt15get_new_handlerv")]
pub(crate) unsafe extern "C" fn get_new_handler() -> Option<unsafe extern "C" fn()> {
    None
}

/// `void operator delete(void*, align_val_t)` → nlist `__ZdlPvSt11align_val_t`.
#[unsafe(export_name = "_ZdlPvSt11align_val_t")]
pub(crate) unsafe extern "C" fn op_delete_aligned(ptr: *mut c_void, _align: usize) {
    if ptr.is_null() {
        return;
    }
    // Prefer stashed base from aligned new; if missing, free ptr as-is.
    // SAFETY: aligned-new wrote base at ptr-8.
    let stash_addr = ptr.addr().saturating_sub(8);
    let stash = core::ptr::with_exposed_provenance_mut::<*mut c_void>(stash_addr);
    let base = unsafe { stash.read() };
    if !base.is_null() && base.addr() < ptr.addr() {
        unsafe {
            free(base);
        }
    } else {
        unsafe {
            free(ptr);
        }
    }
}

// ── Darwin TLV (thread-local variables) ─────────────────────────────────────
//
// Guests import `__tlv_bootstrap` from libSystem. On first TLS access the
// compiler leaves a `tlv_descriptor*` in `x0` and calls this; return is the
// address of that variable's storage.
//
// Real dyld: one per-image TLV template; `key` groups descriptors, `offset`
// is into that image block (can be tens of KiB for clang). Soft model:
// one growable zeroed block **per key** (fallback: per-descriptor address).
// Observed: 4 KiB clamp + per-descriptor blocks SEGV'd `SemaPPCallbacks::
// FileChanged` (TLS pointer null / alias).

#[repr(C)]
struct TlvDescriptor {
    /// Rewritten by real dyld to `tlv_get_addr`; we leave as-is.
    _thunk: *mut c_void,
    /// Image / section key — shared by all TLVs in one image.
    key: u64,
    /// Byte offset into that image's TLV block.
    offset: u64,
}

/// Soft per-key block size (covers large clang TLS templates).
const TLV_BLOCK: usize = 1024 * 1024;
const TLV_SLOTS: usize = 128;

#[derive(Clone, Copy)]
struct TlvSlot {
    /// Grouping key (`descriptor.key`, or desc VA when key is 0).
    key: u64,
    base: *mut u8,
    /// Allocated size of `base`.
    size: usize,
}

// SAFETY: freestanding single-writer soft table for soft TLS.
static mut TLV_TABLE: [TlvSlot; TLV_SLOTS] = [TlvSlot {
    key: 0,
    base: core::ptr::null_mut(),
    size: 0,
}; TLV_SLOTS];
static mut TLV_USED: usize = 0;

/// Real work for TLV; called from a register-preserving trampoline.
///
/// # Safety
/// `desc` must be a guest `tlv_descriptor*`.
/// Called only from the `__tlv_bootstrap` asm trampoline (`no_mangle` for `bl`).
#[unsafe(no_mangle)]
#[allow(unreachable_pub)]
pub unsafe extern "C" fn kh_tlv_bootstrap_impl(desc: *mut c_void) -> *mut c_void {
    if desc.is_null() {
        return core::ptr::null_mut();
    }
    // SAFETY: guest passes a live tlv_descriptor.
    let desc_s = unsafe { desc.cast::<TlvDescriptor>().as_ref() };
    let Some(d) = desc_s else {
        return core::ptr::null_mut();
    };
    let off = usize::try_from(d.offset).unwrap_or(0);
    if off.saturating_add(64) > TLV_BLOCK {
        trace::force_note(b"[kh-libsystem] tlv_bootstrap offset beyond soft block\n");
        return core::ptr::null_mut();
    }
    let group = if d.key != 0 {
        d.key
    } else {
        u64::try_from(desc.addr()).unwrap_or(0)
    };

    let used = unsafe { TLV_USED }.min(TLV_SLOTS);
    let table = core::ptr::addr_of!(TLV_TABLE);
    for slot in unsafe { (*table).iter().take(used) } {
        if slot.key == group && !slot.base.is_null() && off < slot.size {
            let addr = slot.base.addr().saturating_add(off);
            return core::ptr::with_exposed_provenance_mut(addr);
        }
    }

    // One large zeroed block per image key (offsets share the template).
    let base = unsafe { malloc(TLV_BLOCK) }.cast::<u8>();
    if base.is_null() {
        trace::force_note(b"[kh-libsystem] tlv_bootstrap OOM\n");
        return core::ptr::null_mut();
    }
    unsafe {
        core::ptr::write_bytes(base, 0, TLV_BLOCK);
    }
    let idx = unsafe { TLV_USED };
    if idx < TLV_SLOTS {
        unsafe {
            if let Some(slot) = (*core::ptr::addr_of_mut!(TLV_TABLE)).get_mut(idx) {
                *slot = TlvSlot {
                    key: group,
                    base,
                    size: TLV_BLOCK,
                };
            }
            TLV_USED = idx.saturating_add(1);
        }
    }
    let addr = base.addr().saturating_add(off);
    core::ptr::with_exposed_provenance_mut(addr)
}

// Darwin TLV thunks are **not** standard C ABI: Apple clang codegen keeps
// caller-saved GPRs (e.g. `w9`) live across the `blr` and only expects `x0`
// to change (address of the TLS cell). A normal Rust `extern "C"` clobbers
// `x9` → SEGV in `SemaPPCallbacks::FileChanged` after soft TLV.
//
// Naked trampoline (export nlist `__tlv_bootstrap`): save x1–x18 + lr, call
// impl, restore. `export_name` matches guest imports (same as prior soft stub).
#[unsafe(export_name = "_tlv_bootstrap")]
#[unsafe(naked)]
#[allow(unreachable_pub)]
pub unsafe extern "C" fn tlv_bootstrap_entry() {
    core::arch::naked_asm!(
        // Save caller-saved GPRs we might clobber (keep x0 = desc).
        "sub sp, sp, #160",
        "stp x1, x2, [sp, #0]",
        "stp x3, x4, [sp, #16]",
        "stp x5, x6, [sp, #32]",
        "stp x7, x8, [sp, #48]",
        "stp x9, x10, [sp, #64]",
        "stp x11, x12, [sp, #80]",
        "stp x13, x14, [sp, #96]",
        "stp x15, x16, [sp, #112]",
        "stp x17, x18, [sp, #128]",
        "str x30, [sp, #144]",
        "bl {impl_}",
        "ldr x30, [sp, #144]",
        "ldp x17, x18, [sp, #128]",
        "ldp x15, x16, [sp, #112]",
        "ldp x13, x14, [sp, #96]",
        "ldp x11, x12, [sp, #80]",
        "ldp x9, x10, [sp, #64]",
        "ldp x7, x8, [sp, #48]",
        "ldp x5, x6, [sp, #32]",
        "ldp x3, x4, [sp, #16]",
        "ldp x1, x2, [sp, #0]",
        "add sp, sp, #160",
        "ret",
        impl_ = sym kh_tlv_bootstrap_impl,
    );
}

// ── libunwind ───────────────────────────────────────────────────────────────

/// `_Unwind_Resume` → nlist `__Unwind_Resume` (never returns).
#[unsafe(export_name = "_Unwind_Resume")]
pub(crate) unsafe extern "C" fn unwind_resume(_exception_object: *mut c_void) -> ! {
    trace::note(b"[kh-libsystem] __Unwind_Resume (stub abort)\n");
    unsafe {
        exit_now(1);
    }
}

// ── libc++abi exception surface (stubs) ─────────────────────────────────────

// ── static local / guard variables (Itanium C++ ABI) ────────────────────────
//
// Spec: https://itanium-cxx-abi.github.io/cxx-abi/abi.html#once-ctor
// Compiler emits (pseudo):
//   if ((guard & 1) == 0) {
//     if (__cxa_guard_acquire(&guard)) {
//       /* run initializer */
//       __cxa_guard_release(&guard);
//     }
//   }
// On Darwin arm64 the object is 64-bit; bit 0 set ⇒ complete. We do not
// implement a real recursive mutex yet — enough for single-threaded static
// init (clang --version); concurrent init of the same guard is undefined here.

const GUARD_COMPLETE: u64 = 1;
const GUARD_PENDING: u64 = 1 << 8;

/// `___cxa_guard_acquire` → nlist `___cxa_guard_acquire`.
///
/// Returns 1 if the caller must run the initializer, 0 if already complete.
#[unsafe(export_name = "__cxa_guard_acquire")]
pub(crate) unsafe extern "C" fn cxa_guard_acquire(guard: *mut u64) -> c_int {
    if guard.is_null() {
        return 0;
    }
    // SAFETY: guest passes a valid static guard object.
    let g = unsafe { &mut *guard };
    if (*g & GUARD_COMPLETE) != 0 {
        return 0;
    }
    // Mark pending so a nested re-enter of the same guard is visible in traces.
    *g |= GUARD_PENDING;
    trace::note(b"[kh-libsystem] ___cxa_guard_acquire\n");
    1
}

/// `___cxa_guard_release` → nlist `___cxa_guard_release`.
#[unsafe(export_name = "__cxa_guard_release")]
pub(crate) unsafe extern "C" fn cxa_guard_release(guard: *mut u64) {
    if guard.is_null() {
        return;
    }
    // SAFETY: same guard object as acquire.
    let g = unsafe { &mut *guard };
    *g = GUARD_COMPLETE;
    trace::note(b"[kh-libsystem] ___cxa_guard_release\n");
}

/// `___cxa_guard_abort` → nlist `___cxa_guard_abort` (init threw / failed).
#[unsafe(export_name = "__cxa_guard_abort")]
pub(crate) unsafe extern "C" fn cxa_guard_abort(guard: *mut u64) {
    if guard.is_null() {
        return;
    }
    // SAFETY: clear pending so a later thread may retry.
    let g = unsafe { &mut *guard };
    *g = 0;
    trace::note(b"[kh-libsystem] ___cxa_guard_abort\n");
}

/// `___cxa_atexit` → nlist `___cxa_atexit` (no dtor registration yet).
#[unsafe(export_name = "__cxa_atexit")]
pub(crate) unsafe extern "C" fn cxa_atexit(
    _func: Option<unsafe extern "C" fn(*mut c_void)>,
    _arg: *mut c_void,
    _dso_handle: *mut c_void,
) -> c_int {
    trace::note(b"[kh-libsystem] ___cxa_atexit (no-op)\n");
    0
}

// ── libc++ chrono (Apple period = micro for system_clock) ────────────────────
//
// Freestanding stand-ins for symbols clang imports from `libc++.1.dylib`.
// ABI: `time_point` / `duration` with `rep = long long` is a single `i64`
// field returned in `x0` on Darwin arm64. Spec: public chrono contracts +
// observed mangles (ratio `1/1000000` on `to_time_t`).

/// Read wall time as `(sec, usec)` via Darwin `gettimeofday`.
fn wall_time_us() -> (i64, i32) {
    let mut tv = [0_u8; 16];
    let p = tv.as_mut_ptr();
    // SAFETY: 16-byte stack timeval; timezone unused.
    let ret = unsafe {
        crate::sys::syscall2(
            crate::sys::SYS_GETTIMEOFDAY,
            u64::try_from(p.addr()).unwrap_or(0),
            0,
        )
    };
    if ret < 0 {
        return (0, 0);
    }
    let sec = i64::from_le_bytes([tv[0], tv[1], tv[2], tv[3], tv[4], tv[5], tv[6], tv[7]]);
    let usec = i32::from_le_bytes([tv[8], tv[9], tv[10], tv[11]]);
    (sec, usec)
}

/// `std::chrono::system_clock::now()` → nlist
/// `__ZNSt3__16chrono12system_clock3nowEv`.
///
/// Returns `time_point` as microseconds since Unix epoch (`i64` in `x0`).
#[unsafe(export_name = "_ZNSt3__16chrono12system_clock3nowEv")]
pub(crate) unsafe extern "C" fn chrono_system_clock_now() -> i64 {
    let (sec, usec) = wall_time_us();
    sec.saturating_mul(1_000_000)
        .saturating_add(i64::from(usec))
}

/// `std::chrono::system_clock::to_time_t(const time_point&)` → nlist
/// `__ZNSt3__16chrono12system_clock9to_time_tERKNS0_10time_pointIS1_NS0_8durationIxNS_5ratioILl1ELl1000000EEEEEEE`.
#[unsafe(export_name = "_ZNSt3__16chrono12system_clock9to_time_tERKNS0_10time_pointIS1_NS0_8durationIxNS_5ratioILl1ELl1000000EEEEEEE")]
pub(crate) unsafe extern "C" fn chrono_system_clock_to_time_t(tp: *const i64) -> i64 {
    if tp.is_null() {
        return 0;
    }
    // SAFETY: guest passes a live `time_point` (single `i64` count of µs).
    let us = unsafe { tp.read() };
    us.saturating_div(1_000_000)
}

/// `std::chrono::system_clock::from_time_t(time_t)` → nlist
/// `__ZNSt3__16chrono12system_clock11from_time_tEl`.
#[unsafe(export_name = "_ZNSt3__16chrono12system_clock11from_time_tEl")]
pub(crate) unsafe extern "C" fn chrono_system_clock_from_time_t(t: i64) -> i64 {
    t.saturating_mul(1_000_000)
}

/// `std::chrono::steady_clock::now()` → nlist
/// `__ZNSt3__16chrono12steady_clock3nowEv`.
///
/// Apple libc++ uses nanoseconds for `steady_clock`. We approximate with wall
/// time (not boot monotonic); enough for timeouts that only need a progressing
/// clock until a real `CLOCK_MONOTONIC` path is wired.
#[unsafe(export_name = "_ZNSt3__16chrono12steady_clock3nowEv")]
pub(crate) unsafe extern "C" fn chrono_steady_clock_now() -> i64 {
    let (sec, usec) = wall_time_us();
    sec.saturating_mul(1_000_000_000)
        .saturating_add(i64::from(usec).saturating_mul(1_000))
}

/// `std::this_thread::sleep_for(const duration<long long, nano>&)` → nlist
/// `__ZNSt3__111this_thread9sleep_forERKNS_6chrono8durationIxNS_5ratioILl1ELl1000000000EEEEE`.
#[unsafe(export_name = "_ZNSt3__111this_thread9sleep_forERKNS_6chrono8durationIxNS_5ratioILl1ELl1000000000EEEEE")]
pub(crate) unsafe extern "C" fn this_thread_sleep_for_ns(dur: *const i64) {
    if dur.is_null() {
        return;
    }
    // SAFETY: duration is a single `i64` nanosecond count.
    let ns = unsafe { dur.read() };
    if ns <= 0 {
        return;
    }
    let sec = ns.saturating_div(1_000_000_000);
    let nsec = ns % 1_000_000_000;
    let mut ts = [0_i64; 2];
    ts[0] = sec;
    ts[1] = nsec;
    // SAFETY: stack timespec for freestanding nanosleep.
    unsafe {
        let _ = crate::posix::nanosleep(ts.as_ptr().cast(), core::ptr::null_mut());
    }
}

/// `___cxa_pure_virtual` → nlist `___cxa_pure_virtual`.
#[unsafe(export_name = "__cxa_pure_virtual")]
pub(crate) unsafe extern "C" fn cxa_pure_virtual() -> ! {
    trace::note(b"[kh-libsystem] ___cxa_pure_virtual\n");
    unsafe {
        exit_now(1);
    }
}

/// `___cxa_allocate_exception` → nlist `___cxa_allocate_exception`.
#[unsafe(export_name = "__cxa_allocate_exception")]
pub(crate) unsafe extern "C" fn cxa_allocate_exception(size: usize) -> *mut c_void {
    trace::note_size(b"___cxa_allocate_exception", size);
    // SAFETY: bump heap; real ABI needs a header — guests that only allocate
    // without throw can survive; throw path aborts.
    unsafe { malloc(size.saturating_add(64).max(64)) }
}

/// `___cxa_free_exception` → nlist `___cxa_free_exception`.
#[unsafe(export_name = "__cxa_free_exception")]
pub(crate) unsafe extern "C" fn cxa_free_exception(ptr: *mut c_void) {
    trace::note_ptr(b"___cxa_free_exception", ptr.addr());
    unsafe {
        free(ptr);
    }
}

/// `___cxa_throw` → nlist `___cxa_throw` (no unwind; abort).
#[unsafe(export_name = "__cxa_throw")]
pub(crate) unsafe extern "C" fn cxa_throw(
    _exception: *mut c_void,
    _tinfo: *mut c_void,
    _dest: Option<unsafe extern "C" fn(*mut c_void)>,
) -> ! {
    trace::note(b"[kh-libsystem] ___cxa_throw (stub abort)\n");
    unsafe {
        exit_now(1);
    }
}

/// `___cxa_begin_catch` → nlist `___cxa_begin_catch`.
#[unsafe(export_name = "__cxa_begin_catch")]
pub(crate) unsafe extern "C" fn cxa_begin_catch(exception: *mut c_void) -> *mut c_void {
    trace::note(b"[kh-libsystem] ___cxa_begin_catch\n");
    exception
}

/// `___cxa_end_catch` → nlist `___cxa_end_catch`.
#[unsafe(export_name = "__cxa_end_catch")]
pub(crate) unsafe extern "C" fn cxa_end_catch() {
    trace::note(b"[kh-libsystem] ___cxa_end_catch\n");
}

/// `___cxa_rethrow` → nlist `___cxa_rethrow`.
#[unsafe(export_name = "__cxa_rethrow")]
pub(crate) unsafe extern "C" fn cxa_rethrow() -> ! {
    trace::note(b"[kh-libsystem] ___cxa_rethrow (stub abort)\n");
    unsafe {
        exit_now(1);
    }
}

/// `___cxa_call_unexpected` → nlist `___cxa_call_unexpected`.
#[unsafe(export_name = "__cxa_call_unexpected")]
pub(crate) unsafe extern "C" fn cxa_call_unexpected(_exception: *mut c_void) -> ! {
    trace::note(b"[kh-libsystem] ___cxa_call_unexpected\n");
    unsafe {
        exit_now(1);
    }
}

/// `___gxx_personality_v0` → nlist `___gxx_personality_v0`.
///
/// Returns `_URC_CONTINUE_UNWIND` (8) so a real unwind would keep going; we
/// never run a real unwinder.
#[unsafe(export_name = "__gxx_personality_v0")]
pub(crate) unsafe extern "C" fn gxx_personality_v0(
    _version: c_int,
    _actions: c_int,
    _exception_class: u64,
    _exception_object: *mut c_void,
    _context: *mut c_void,
) -> c_int {
    trace::note(b"[kh-libsystem] ___gxx_personality_v0\n");
    8
}

/// `std::terminate()` → nlist `__ZSt9terminatev`.
#[unsafe(export_name = "_ZSt9terminatev")]
pub(crate) unsafe extern "C" fn std_terminate() -> ! {
    trace::note(b"[kh-libsystem] std::terminate\n");
    unsafe {
        exit_now(1);
    }
}

// ── stack cookie / Darwin chkstk ────────────────────────────────────────────

/// Guard word for `-fstack-protector` → nlist `___stack_chk_guard`.
#[unsafe(export_name = "__stack_chk_guard")]
#[used]
static mut STACK_CHK_GUARD: usize = 0x4B48_5AFE;

/// `___stack_chk_fail` → nlist `___stack_chk_fail`.
#[unsafe(export_name = "__stack_chk_fail")]
pub(crate) unsafe extern "C" fn stack_chk_fail() -> ! {
    trace::note(b"[kh-libsystem] ___stack_chk_fail\n");
    unsafe {
        exit_now(127);
    }
}

/// `___chkstk_darwin` → nlist `___chkstk_darwin` (probe stack; no-op).
#[unsafe(export_name = "__chkstk_darwin")]
pub(crate) unsafe extern "C" fn chkstk_darwin() {
    // Called with stack growth in x9 on Darwin; we ignore.
}

/// Bottle export for guests that nlist-import `dyld_stub_binder`.
///
/// Darwin ld emits this as `_dyld_stub_binder`; `kh-loader` also registers the
/// unadorned `dyld_stub_binder` name in the export map (curl uses that spelling).
/// Eager bind should not call this; if it runs, abort.
#[unsafe(export_name = "dyld_stub_binder")]
pub(crate) unsafe extern "C" fn dyld_stub_binder_export() {
    trace::note(b"[kh-libsystem] dyld_stub_binder() unexpected\n");
    // SAFETY: never returns.
    unsafe {
        exit_now(127);
    }
}

/// Catch-all for strong binds that have no real definition yet.
///
/// `kh-loader` may point unresolved imports here (warn once per name) so large
/// guests like curl can finish load; the first call aborts with a note.
/// Prefer [`kh_missing_symbol_named`] via per-import trampolines so G1 logs
/// which import was first touched.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn kh_missing_symbol() -> ! {
    // Always print (trace is off by default); otherwise curl exits 127 silently.
    trace::force_note(b"[kh-libsystem] kh_missing_symbol() - bound missing import was called\n");
    // SAFETY: never returns.
    unsafe {
        exit_now(127);
    }
}

/// Named catch-all: `x0` = C string of the unresolved nlist name (e.g. `_fopen`).
///
/// Emitted by `kh-loader` missing-stub trampolines so the first *call* (not
/// just bind) surfaces which surface we still need for curl G1.
///
/// The name pointer often lives in the loader's trampoline pool (anonymous
/// host `mmap`), which is **not** registered in guest `AddressSpace`. Copying
/// onto this stack frame is required before `write` — otherwise the trap path
/// returns `EFAULT` and we lose the symbol name.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn kh_missing_symbol_named(name: *const core::ffi::c_char) -> ! {
    trace::force_note(b"[kh-libsystem] missing symbol called: ");
    // Stack is registered guest memory; trampoline-pool strings are not.
    // Sized for long libc++ mangles (loader `MAX_NAME` is 256).
    let mut on_stack = [0_u8; 256];
    if name.is_null() {
        on_stack[..6].copy_from_slice(b"<null>");
        trace::force_note(&on_stack[..6]);
    } else {
        let mut len = 0_usize;
        while len < on_stack.len().saturating_sub(1) {
            // SAFETY: trampoline embeds a NUL-terminated name; stop before last byte.
            let b = unsafe { (*name.add(len)).cast_unsigned() };
            if b == 0 {
                break;
            }
            if let Some(slot) = on_stack.get_mut(len) {
                *slot = b;
            }
            len = len.saturating_add(1);
        }
        if len == 0 {
            on_stack[..7].copy_from_slice(b"<empty>");
            trace::force_note(&on_stack[..7]);
        } else if let Some(slice) = on_stack.get(..len) {
            trace::force_note(slice);
        }
    }
    trace::force_note(b"\n");
    // SAFETY: never returns.
    unsafe {
        exit_now(127);
    }
}
