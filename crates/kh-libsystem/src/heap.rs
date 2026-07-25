//! Freestanding bump heap: `malloc` / `free` / `calloc` / `realloc`.

use core::ffi::c_void;
use core::sync::atomic::{AtomicUsize, Ordering};

use crate::errno;
use crate::trace;

const HEAP_SIZE: usize = 256 * 1024;
const ALIGN: usize = 16;

struct Heap {
    buf: core::cell::UnsafeCell<[u8; HEAP_SIZE]>,
    off: AtomicUsize,
}

// SAFETY: atomic bump + single-guest use.
unsafe impl Sync for Heap {}

static HEAP: Heap = Heap {
    buf: core::cell::UnsafeCell::new([0; HEAP_SIZE]),
    off: AtomicUsize::new(0),
};

#[inline]
fn align_up(value: usize) -> usize {
    value.saturating_add(ALIGN - 1) & !(ALIGN - 1)
}

/// C `malloc` → nlist `_malloc`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn malloc(size: usize) -> *mut c_void {
    trace::note_size(b"malloc", size);
    allocate(size)
}

/// C `free` → nlist `_free` (bump: traced no-op).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn free(ptr: *mut c_void) {
    trace::note_ptr(b"free", ptr.addr());
    let _ = ptr;
}

/// C `calloc` → nlist `_calloc`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn calloc(count: usize, size: usize) -> *mut c_void {
    let Some(total) = count.checked_mul(size) else {
        errno::set_errno(12);
        trace::note(b"[kh-libsystem] calloc overflow\n");
        return core::ptr::null_mut();
    };
    trace::note_size(b"calloc", total);
    let p = allocate(total);
    if !p.is_null() && total > 0 {
        // SAFETY: `total` bytes from allocate.
        unsafe {
            crate::stdio::bzero(p, total);
        }
    }
    p
}

/// C `realloc` → nlist `_realloc`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn realloc(ptr: *mut c_void, size: usize) -> *mut c_void {
    trace::note_size(b"realloc", size);
    if ptr.is_null() {
        return allocate(size);
    }
    if size == 0 {
        // SAFETY: traced free.
        unsafe {
            free(ptr);
        }
        return core::ptr::null_mut();
    }
    let fresh = allocate(size);
    if fresh.is_null() {
        return core::ptr::null_mut();
    }
    // SAFETY: scaffold copies `size` bytes (old block size unknown).
    unsafe {
        let _ = crate::stdio::memcpy(fresh, ptr, size);
    }
    fresh
}

fn allocate(size: usize) -> *mut c_void {
    if size == 0 {
        return allocate(1);
    }
    let need = align_up(size);
    loop {
        let cur = HEAP.off.load(Ordering::Relaxed);
        let next = match cur.checked_add(need) {
            Some(n) if n <= HEAP_SIZE => n,
            _ => {
                errno::set_errno(12);
                trace::note(b"[kh-libsystem] malloc ENOMEM\n");
                return core::ptr::null_mut();
            }
        };
        if HEAP
            .off
            .compare_exchange(cur, next, Ordering::SeqCst, Ordering::Relaxed)
            .is_ok()
        {
            let base = HEAP.buf.get().cast::<u8>();
            // SAFETY: offset within HEAP_SIZE.
            let p = unsafe { base.add(cur) };
            return p.cast();
        }
    }
}
