//! Minimal Itanium RTTI / typeinfo surface for C++ guests.
//!
//! Exports cxxabi class-type-info vtables (bind targets for guest typeinfo
//! objects) and a freestanding [`dynamic_cast`] walk used by `___dynamic_cast`.
//!
//! Spec: Itanium C++ ABI §2.9 (type_info layout). Not a full libc++abi.

#![allow(
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_ptr_alignment,
    clippy::cast_sign_loss,
    clippy::ptr_as_ptr
)]

use core::ffi::c_void;
use core::ptr;

/// Enough space for a fake `std::type_info` object.
/// Layout: vptr + name pointer + padding (all usize for `Sync`).
#[repr(C)]
struct TypeInfoStub {
    vtable: usize,
    /// Intentionally 0: guests that only bind the symbol / compare addresses
    /// of typeinfo objects still resolve; name-based RTTI is not supported.
    name: usize,
    _pad: [usize; 4],
}

// ── vtables for cxxabi type_info classes ────────────────────────────────────
//
// Guest typeinfo objects (in ld-classic, libtapi, …) hold a vptr into one of
// these. Contents are zero (no virtual methods); address ranges identify the
// kind for [`dynamic_cast`].

/// `__cxxabiv1::__class_type_info` vtable → nlist `__ZTVN10__cxxabiv117__class_type_infoE`.
#[unsafe(export_name = "_ZTVN10__cxxabiv117__class_type_infoE")]
#[used]
static VTABLE_CLASS_TYPE_INFO: [usize; 8] = [0; 8];

/// `__cxxabiv1::__si_class_type_info` vtable.
#[unsafe(export_name = "_ZTVN10__cxxabiv120__si_class_type_infoE")]
#[used]
static VTABLE_SI_CLASS_TYPE_INFO: [usize; 8] = [0; 8];

/// `__cxxabiv1::__vmi_class_type_info` vtable.
#[unsafe(export_name = "_ZTVN10__cxxabiv121__vmi_class_type_infoE")]
#[used]
static VTABLE_VMI_CLASS_TYPE_INFO: [usize; 8] = [0; 8];

/// `__cxxabiv1::__enum_type_info` vtable.
#[unsafe(export_name = "_ZTVN10__cxxabiv116__enum_type_infoE")]
#[used]
static VTABLE_ENUM_TYPE_INFO: [usize; 8] = [0; 8];

const _: &[usize; 8] = &VTABLE_CLASS_TYPE_INFO;
const _: &[usize; 8] = &VTABLE_SI_CLASS_TYPE_INFO;
const _: &[usize; 8] = &VTABLE_VMI_CLASS_TYPE_INFO;
const _: &[usize; 8] = &VTABLE_ENUM_TYPE_INFO;

// ── typeinfo objects ────────────────────────────────────────────────────────

const EMPTY_TI: TypeInfoStub = TypeInfoStub {
    vtable: 0,
    name: 0,
    _pad: [0; 4],
};

/// `typeinfo for char const*` → nlist `__ZTIPKc`.
#[unsafe(export_name = "_ZTIPKc")]
#[used]
static TI_PKC: TypeInfoStub = EMPTY_TI;

/// `typeinfo for wchar_t const*` → nlist `__ZTIPKw`.
#[unsafe(export_name = "_ZTIPKw")]
#[used]
static TI_PKW: TypeInfoStub = EMPTY_TI;

/// `typeinfo for int` → nlist `__ZTIi`.
#[unsafe(export_name = "_ZTIi")]
#[used]
static TI_I: TypeInfoStub = EMPTY_TI;

/// `typeinfo for std::bad_alloc` → nlist `__ZTISt9bad_alloc`.
#[unsafe(export_name = "_ZTISt9bad_alloc")]
#[used]
static TI_BAD_ALLOC: TypeInfoStub = EMPTY_TI;

/// `typeinfo for std::__1::__shared_weak_count`
#[unsafe(export_name = "_ZTINSt3__119__shared_weak_countE")]
#[used]
static TI_SHARED_WEAK_COUNT: TypeInfoStub = EMPTY_TI;

const _: &TypeInfoStub = &TI_PKC;
const _: &TypeInfoStub = &TI_PKW;
const _: &TypeInfoStub = &TI_I;
const _: &TypeInfoStub = &TI_BAD_ALLOC;
const _: &TypeInfoStub = &TI_SHARED_WEAK_COUNT;

// ── dynamic_cast walk ───────────────────────────────────────────────────────

#[derive(Clone, Copy, PartialEq, Eq)]
enum TiKind {
    /// Leaf `__class_type_info` (no recorded bases).
    Class,
    /// Single non-virtual inheritance.
    Si,
    /// Multiple / virtual inheritance.
    Vmi,
    /// Unknown / not a class typeinfo we understand.
    Other,
}

#[inline]
fn ptr_in_vtable(vptr: *const c_void, table: &[usize; 8]) -> bool {
    let base = table.as_ptr() as usize;
    let p = vptr as usize;
    p >= base && p < base.saturating_add(core::mem::size_of_val(table))
}

fn ti_kind(type_info: *const c_void) -> TiKind {
    if type_info.is_null() {
        return TiKind::Other;
    }
    // SAFETY: typeinfo objects start with a vptr into one of our ZTV symbols.
    let vptr = unsafe { type_info.cast::<*const c_void>().read() };
    if ptr_in_vtable(vptr, &VTABLE_SI_CLASS_TYPE_INFO) {
        TiKind::Si
    } else if ptr_in_vtable(vptr, &VTABLE_VMI_CLASS_TYPE_INFO) {
        TiKind::Vmi
    } else if ptr_in_vtable(vptr, &VTABLE_CLASS_TYPE_INFO) {
        TiKind::Class
    } else {
        TiKind::Other
    }
}

/// Search whether `dst_type` is `type_info` or a public non-virtual base of it.
/// On success returns a pointer to the `dst_type` subobject at `obj`.
///
/// Depth is bounded to avoid infinite loops on corrupt RTTI.
fn search_dst(
    type_info: *const c_void,
    dst_type: *const c_void,
    obj: *const u8,
    depth: u32,
) -> Option<*const u8> {
    if type_info.is_null() || dst_type.is_null() || depth > 32 {
        return None;
    }
    if type_info == dst_type {
        return Some(obj);
    }
    match ti_kind(type_info) {
        TiKind::Class | TiKind::Other => None,
        TiKind::Si => {
            // `__si_class_type_info`: { type_info; const __class_type_info* __base_type; }
            // Base is at offset 0 of the complete object for the usual SI layout.
            // SAFETY: SI typeinfo from a guest image (ld-classic); layout is ABI.
            let base_ti = unsafe { type_info.cast::<*const c_void>().add(2).read() };
            search_dst(base_ti, dst_type, obj, depth.saturating_add(1))
        }
        TiKind::Vmi => {
            // `__vmi_class_type_info`:
            //   type_info; unsigned __flags; unsigned __base_count;
            //   __base_class_type_info __base_info[];
            // `__base_class_type_info`: { base_type*; long __offset_flags }
            // offset_flags: low 8 bits flags (1=virtual, 2=public), rest = offset.
            // SAFETY: VMI typeinfo ABI layout on arm64.
            let base_count = unsafe { type_info.cast::<u32>().add(5).read() }; // after 2×usize + flags
            // Layout check: usize vptr, usize name, u32 flags, u32 count → offset 16+8=24 for array?
            // type_info = 16 bytes (vptr+name), then __flags u32 at 16, __base_count u32 at 20,
            // __base_info at 24.
            let bases = unsafe { type_info.cast::<u8>().add(24) };
            let n = base_count.min(64);
            for i in 0..n {
                let ent = unsafe { bases.add((i as usize).saturating_mul(16)).cast::<usize>() };
                let base_ti = unsafe { ent.read() } as *const c_void;
                let offset_flags = unsafe { ent.add(1).read() } as isize;
                let flags = (offset_flags as usize) & 0xff;
                // bit0 virtual, bit1 public
                if flags & 0x1 != 0 {
                    continue; // skip virtual bases (soft)
                }
                if flags & 0x2 == 0 {
                    continue; // non-public
                }
                let offset = offset_flags >> 8;
                let sub = unsafe { obj.offset(offset) };
                if let Some(p) = search_dst(base_ti, dst_type, sub, depth.saturating_add(1)) {
                    return Some(p);
                }
            }
            None
        }
    }
}

/// Itanium `__dynamic_cast` body (called from `cxxabi`).
///
/// Observed need (G4 / `ld-classic`):
/// * Always-null → `indirect dylib … is not a dylib` (reexport chain).
/// * Always-src → wrong branch in `Resolver::doFile` → SEGV on fake vector*.
///
/// Walk the object's dynamic typeinfo (vtable[-1]) and only succeed when
/// `dst_type` is that type or a public non-virtual base.
pub(crate) unsafe fn dynamic_cast(
    src_ptr: *const c_void,
    src_type: *const c_void,
    dst_type: *const c_void,
    src2dst: isize,
) -> *mut c_void {
    if src_ptr.is_null() || dst_type.is_null() {
        return ptr::null_mut();
    }
    // Same static type (unusual for dynamic_cast, but cheap).
    if !src_type.is_null() && src_type == dst_type {
        return src_ptr.cast_mut();
    }

    // Object vtable: vptr → first virtual; [-1]=typeinfo, [-2]=offset-to-top.
    // SAFETY: C++ object with polymorphic type; guest guarantees vptr.
    let vptr = unsafe { src_ptr.cast::<*const usize>().read() };
    if vptr.is_null() {
        return ptr::null_mut();
    }
    let offset_to_top = unsafe { vptr.sub(2).read() } as isize;
    let dynamic_type = unsafe { vptr.sub(1).read() } as *const c_void;
    if dynamic_type.is_null() {
        // No typeinfo in vtable — fall back carefully.
        if src2dst >= 0 {
            return unsafe { src_ptr.byte_offset(src2dst).cast_mut() };
        }
        return ptr::null_mut();
    }

    let complete = unsafe { src_ptr.cast::<u8>().offset(offset_to_top) };
    if let Some(p) = search_dst(dynamic_type, dst_type, complete, 0) {
        return p.cast_mut().cast();
    }

    // Optional: if compiler promised a unique public base at src2dst, still
    // require dynamic_type to be (or derive from) dst — already failed above.
    let _ = src2dst;
    ptr::null_mut()
}
