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
    let mut on_stack = [0_u8; 128];
    if name.is_null() {
        on_stack[..6].copy_from_slice(b"<null>");
        trace::force_note(&on_stack[..6]);
    } else {
        let mut len = 0_usize;
        while len < on_stack.len().saturating_sub(1) {
            // SAFETY: trampoline embeds a NUL-terminated name; we stop at 127.
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
