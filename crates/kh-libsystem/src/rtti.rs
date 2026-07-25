//! Minimal Itanium RTTI / typeinfo symbols for C++ guests (`7zz`).
//!
//! Real matching is not implemented; we only export stable addresses so
//! bind/lazy-bind of `typeinfo` / vtable symbols succeeds.

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

const _: &TypeInfoStub = &TI_PKC;
const _: &TypeInfoStub = &TI_PKW;
const _: &TypeInfoStub = &TI_I;
const _: &TypeInfoStub = &TI_BAD_ALLOC;
