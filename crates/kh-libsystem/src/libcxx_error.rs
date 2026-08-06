//! Freestanding `std::error_category` / `error_code` surface (Apple libc++).
//!
//! Soft stubs so C++ guests (clang / LLVM) can resolve `system_category()` and
//! friends. Not a full `<system_error>` implementation.

#![allow(
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    clippy::cast_possible_truncation,
    clippy::cast_ptr_alignment,
    clippy::cast_sign_loss,
    clippy::indexing_slicing,
    clippy::ptr_as_ptr
)]

use core::ffi::{c_char, c_int, c_void};
use core::sync::atomic::{AtomicPtr, Ordering};

use crate::libcxx_string::StringRep;

// ── category object + soft vtable ───────────────────────────────────────────
//
// Itanium: object starts with vptr pointing at the first virtual function slot.
// Slots (libc++ `error_category`, approximate order):
//   0 complete dtor, 1 deleting dtor, 2 name, 3 default_error_condition,
//   4 equivalent(int,cond), 5 equivalent(code,int), 6 message(int).

type DtorFn = unsafe extern "C" fn(*mut c_void);
type NameFn = unsafe extern "C" fn(*mut c_void) -> *const c_char;
type DefCondFn = unsafe extern "C" fn(*mut c_void, c_int) -> ErrorCondition;
type EqIntCondFn = unsafe extern "C" fn(*mut c_void, c_int, *const c_void) -> c_int;
type EqCodeIntFn = unsafe extern "C" fn(*mut c_void, *const c_void, c_int) -> c_int;
type MessageFn = unsafe extern "C" fn(*mut c_void, c_int, *mut c_void);

/// `error_condition` — `{ int value; const error_category* cat; }` on arm64.
#[repr(C)]
pub(crate) struct ErrorCondition {
    val: c_int,
    _pad: c_int,
    cat: *const c_void,
}

unsafe extern "C" fn cat_dtor(_this: *mut c_void) {}

unsafe extern "C" fn cat_name_system(_this: *mut c_void) -> *const c_char {
    c"system".as_ptr()
}
unsafe extern "C" fn cat_name_generic(_this: *mut c_void) -> *const c_char {
    c"generic".as_ptr()
}
unsafe extern "C" fn cat_name_future(_this: *mut c_void) -> *const c_char {
    c"future".as_ptr()
}

unsafe extern "C" fn cat_default_error_condition(this: *mut c_void, ev: c_int) -> ErrorCondition {
    ErrorCondition {
        val: ev,
        _pad: 0,
        cat: this.cast_const(),
    }
}

unsafe extern "C" fn cat_equivalent_int_cond(
    _this: *mut c_void,
    _code: c_int,
    _cond: *const c_void,
) -> c_int {
    0
}

unsafe extern "C" fn cat_equivalent_code_int(
    _this: *mut c_void,
    _code: *const c_void,
    _cond: c_int,
) -> c_int {
    0
}

/// Soft `message(int)` — short static text into freestanding `basic_string` `out`.
///
/// Apple `libtapi` surfaces `error_code::message()` in `tapi error: %s in '…'`.
/// Empty soft strings left modern `ld` diagnostics blank after the colon.
unsafe extern "C" fn cat_message(_this: *mut c_void, ev: c_int, out: *mut c_void) {
    if out.is_null() {
        return;
    }
    // Keep messages static (no heap digit loops) — enough to identify errno-ish codes.
    let s: &[u8] = match ev {
        0 => b"success",
        1 => b"EPERM",
        2 => b"ENOENT",
        5 => b"EIO",
        9 => b"EBADF",
        12 => b"ENOMEM",
        13 => b"EACCES",
        14 => b"EFAULT",
        17 => b"EEXIST",
        20 => b"ENOTDIR",
        21 => b"EISDIR",
        22 => b"EINVAL",
        28 => b"ENOSPC",
        _ => b"system_error",
    };
    crate::libcxx_string::string_assign_bytes(out, s.as_ptr(), s.len());
}

#[repr(C)]
struct FnTable {
    dtor_complete: DtorFn,
    dtor_deleting: DtorFn,
    name: NameFn,
    default_error_condition: DefCondFn,
    equivalent_int_cond: EqIntCondFn,
    equivalent_code_int: EqCodeIntFn,
    message: MessageFn,
}

static FN_SYSTEM: FnTable = FnTable {
    dtor_complete: cat_dtor,
    dtor_deleting: cat_dtor,
    name: cat_name_system,
    default_error_condition: cat_default_error_condition,
    equivalent_int_cond: cat_equivalent_int_cond,
    equivalent_code_int: cat_equivalent_code_int,
    message: cat_message,
};
static FN_GENERIC: FnTable = FnTable {
    dtor_complete: cat_dtor,
    dtor_deleting: cat_dtor,
    name: cat_name_generic,
    default_error_condition: cat_default_error_condition,
    equivalent_int_cond: cat_equivalent_int_cond,
    equivalent_code_int: cat_equivalent_code_int,
    message: cat_message,
};
static FN_FUTURE: FnTable = FnTable {
    dtor_complete: cat_dtor,
    dtor_deleting: cat_dtor,
    name: cat_name_future,
    default_error_condition: cat_default_error_condition,
    equivalent_int_cond: cat_equivalent_int_cond,
    equivalent_code_int: cat_equivalent_code_int,
    message: cat_message,
};

#[repr(C)]
struct CategoryObj {
    /// Points at first virtual function slot (`FnTable.dtor_complete`).
    vptr: *const FnTable,
}

static SYSTEM_OBJ: AtomicPtr<CategoryObj> = AtomicPtr::new(core::ptr::null_mut());
static GENERIC_OBJ: AtomicPtr<CategoryObj> = AtomicPtr::new(core::ptr::null_mut());
static FUTURE_OBJ: AtomicPtr<CategoryObj> = AtomicPtr::new(core::ptr::null_mut());

// SAFETY: written once under CAS-like store; only freestanding soft data.
static mut SYSTEM_STORAGE: CategoryObj = CategoryObj {
    vptr: core::ptr::null(),
};
static mut GENERIC_STORAGE: CategoryObj = CategoryObj {
    vptr: core::ptr::null(),
};
static mut FUTURE_STORAGE: CategoryObj = CategoryObj {
    vptr: core::ptr::null(),
};

fn ensure(
    storage: &AtomicPtr<CategoryObj>,
    slot: *mut CategoryObj,
    table: &'static FnTable,
) -> *const c_void {
    let p = storage.load(Ordering::Acquire);
    if !p.is_null() {
        return p.cast();
    }
    unsafe {
        (*slot).vptr = core::ptr::addr_of!(table.dtor_complete).cast();
    }
    storage.store(slot, Ordering::Release);
    slot.cast()
}

/// `std::system_category()`
#[unsafe(export_name = "_ZNSt3__115system_categoryEv")]
pub(crate) unsafe extern "C" fn system_category() -> *const c_void {
    ensure(
        &SYSTEM_OBJ,
        core::ptr::addr_of_mut!(SYSTEM_STORAGE),
        &FN_SYSTEM,
    )
}

/// `std::generic_category()`
#[unsafe(export_name = "_ZNSt3__116generic_categoryEv")]
pub(crate) unsafe extern "C" fn generic_category() -> *const c_void {
    ensure(
        &GENERIC_OBJ,
        core::ptr::addr_of_mut!(GENERIC_STORAGE),
        &FN_GENERIC,
    )
}

/// `std::future_category()`
#[unsafe(export_name = "_ZNSt3__115future_categoryEv")]
pub(crate) unsafe extern "C" fn future_category() -> *const c_void {
    ensure(
        &FUTURE_OBJ,
        core::ptr::addr_of_mut!(FUTURE_STORAGE),
        &FN_FUTURE,
    )
}

/// `error_category::default_error_condition(int) const`
#[unsafe(export_name = "_ZNKSt3__114error_category23default_error_conditionEi")]
pub(crate) unsafe extern "C" fn error_category_default_error_condition(
    this: *mut c_void,
    ev: c_int,
) -> ErrorCondition {
    unsafe { cat_default_error_condition(this, ev) }
}

/// `error_category::equivalent(int, error_condition const&) const`
#[unsafe(export_name = "_ZNKSt3__114error_category10equivalentEiRKNS_15error_conditionE")]
pub(crate) unsafe extern "C" fn error_category_equivalent_int_cond(
    this: *mut c_void,
    code: c_int,
    cond: *const c_void,
) -> c_int {
    unsafe { cat_equivalent_int_cond(this, code, cond) }
}

/// `error_category::equivalent(error_code const&, int) const`
#[unsafe(export_name = "_ZNKSt3__114error_category10equivalentERKNS_10error_codeEi")]
pub(crate) unsafe extern "C" fn error_category_equivalent_code_int(
    this: *mut c_void,
    code: *const c_void,
    cond: c_int,
) -> c_int {
    unsafe { cat_equivalent_code_int(this, code, cond) }
}

/// `error_category::~error_category()` (complete object dtor D1).
#[unsafe(export_name = "_ZNSt3__114error_categoryD1Ev")]
pub(crate) unsafe extern "C" fn error_category_dtor(_this: *mut c_void) {}

/// `error_category::~error_category()` base object dtor D2 (same soft no-op).
/// Observed: Apple `libtapi` (G4).
#[unsafe(export_name = "_ZNSt3__114error_categoryD2Ev")]
pub(crate) unsafe extern "C" fn error_category_dtor_base(_this: *mut c_void) {}

/// `error_code::message() const` — soft string from `value` (AArch64 sret).
///
/// Layout (Apple arm64 libc++): `{ int32 value; int32 pad; const error_category* cat }`.
/// Observed: `libtapi` → modern `ld` `tapi error: %s in '…'` (G5).
#[unsafe(export_name = "_ZNKSt3__110error_code7messageEv")]
pub(crate) unsafe extern "C" fn error_code_message(this: *const c_void) -> StringRep {
    let mut out = StringRep::empty();
    if this.is_null() {
        return out;
    }
    let ev = unsafe { this.cast::<c_int>().read() };
    let out_p = core::ptr::from_mut(&mut out).cast::<c_void>();
    // arm64 layout: value@0, pad@4, cat@8.
    let cat = unsafe { this.cast::<u8>().add(8).cast::<*mut c_void>().read() };
    if !cat.is_null() {
        // Soft FnTable: slot 6 = message(int) writing into out pointer.
        let vptr = unsafe { cat.cast::<*const MessageFn>().read() };
        if !vptr.is_null() {
            let msg_fn = unsafe { vptr.add(6).read() };
            unsafe {
                msg_fn(cat, ev, out_p);
            }
            return out;
        }
    }
    unsafe {
        cat_message(core::ptr::null_mut(), ev, out_p);
    }
    out
}
