//! `libsystem_malloc` — freestanding heap lives in [`crate::kh_core::heap`].
//! Tree slot mirrors Apple `/usr/lib/system/libsystem_malloc.dylib`.
//!
//! Darwin 14+ typed malloc (`malloc_type_*`) is used by `/bin/sh` / bash.
//! Type ids are ignored; pointers are the ordinary freestanding heap.

use core::ffi::c_void;

use crate::kh_core::heap::{allocate_aligned, calloc, free, malloc, realloc};

/// C `malloc_type_malloc` → nlist `_malloc_type_malloc`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn malloc_type_malloc(size: usize, _type_id: u64) -> *mut c_void {
    unsafe { malloc(size) }
}

/// C `malloc_type_calloc` → nlist `_malloc_type_calloc`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn malloc_type_calloc(
    count: usize,
    size: usize,
    _type_id: u64,
) -> *mut c_void {
    unsafe { calloc(count, size) }
}

/// C `malloc_type_realloc` → nlist `_malloc_type_realloc`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn malloc_type_realloc(
    ptr: *mut c_void,
    size: usize,
    _type_id: u64,
) -> *mut c_void {
    unsafe { realloc(ptr, size) }
}

/// C `malloc_type_free` → nlist `_malloc_type_free`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn malloc_type_free(ptr: *mut c_void, _type_id: u64) {
    unsafe { free(ptr) }
}

/// C `malloc_type_aligned_alloc` → nlist `_malloc_type_aligned_alloc`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn malloc_type_aligned_alloc(
    alignment: usize,
    size: usize,
    _type_id: u64,
) -> *mut c_void {
    allocate_aligned(size, alignment)
}

/// C `malloc_type_posix_memalign` → nlist `_malloc_type_posix_memalign`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn malloc_type_posix_memalign(
    memptr: *mut *mut c_void,
    alignment: usize,
    size: usize,
    _type_id: u64,
) -> i32 {
    if memptr.is_null() || alignment == 0 || !alignment.is_power_of_two() {
        return 22; // EINVAL
    }
    let p = allocate_aligned(size, alignment);
    if p.is_null() {
        return 12; // ENOMEM
    }
    unsafe {
        memptr.write(p);
    }
    0
}

/// C `malloc_type_valloc` → nlist `_malloc_type_valloc`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn malloc_type_valloc(size: usize, _type_id: u64) -> *mut c_void {
    allocate_aligned(size, 16_384)
}

/// C `malloc_type_zone_malloc` → nlist `_malloc_type_zone_malloc`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn malloc_type_zone_malloc(
    _zone: *mut c_void,
    size: usize,
    type_id: u64,
) -> *mut c_void {
    unsafe { malloc_type_malloc(size, type_id) }
}

/// C `malloc_type_zone_calloc` → nlist `_malloc_type_zone_calloc`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn malloc_type_zone_calloc(
    _zone: *mut c_void,
    count: usize,
    size: usize,
    type_id: u64,
) -> *mut c_void {
    unsafe { malloc_type_calloc(count, size, type_id) }
}

/// C `malloc_type_zone_realloc` → nlist `_malloc_type_zone_realloc`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn malloc_type_zone_realloc(
    _zone: *mut c_void,
    ptr: *mut c_void,
    size: usize,
    type_id: u64,
) -> *mut c_void {
    unsafe { malloc_type_realloc(ptr, size, type_id) }
}

/// C `malloc_type_zone_free` → nlist `_malloc_type_zone_free`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn malloc_type_zone_free(
    _zone: *mut c_void,
    ptr: *mut c_void,
    type_id: u64,
) {
    unsafe { malloc_type_free(ptr, type_id) }
}

/// C `malloc_type_zone_memalign` → nlist `_malloc_type_zone_memalign`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn malloc_type_zone_memalign(
    _zone: *mut c_void,
    alignment: usize,
    size: usize,
    type_id: u64,
) -> *mut c_void {
    unsafe { malloc_type_aligned_alloc(alignment, size, type_id) }
}

/// C `malloc_type_zone_valloc` → nlist `_malloc_type_zone_valloc`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn malloc_type_zone_valloc(
    _zone: *mut c_void,
    size: usize,
    type_id: u64,
) -> *mut c_void {
    unsafe { malloc_type_valloc(size, type_id) }
}
