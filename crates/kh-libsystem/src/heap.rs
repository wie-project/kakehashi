//! Freestanding heap: free-list arena + anonymous `mmap` for large blocks.
//!
//! Guests like `7zz` import `malloc`/`free`/`realloc` but **not** `mmap`, so all
//! working-set traffic goes through this module. A pure bump allocator with a
//! no-op `free` exhausts quickly under archive create; real free-list + mmap
//! keeps multi‑MiB allocate/free churn alive.

use core::ffi::c_void;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use crate::errno;
use crate::sys::{self, SYS_MMAP, SYS_MUNMAP};
use crate::trace;

const ALIGN: usize = 16;
/// Larger arena cuts mmap/munmap trap traffic for 7zz-class working sets.
const ARENA_SIZE: usize = 64 * 1024 * 1024;
/// Allocations ≥ this size go straight to anonymous `mmap` (and `munmap` on free).
const MMAP_THRESHOLD: usize = 256 * 1024;
const PAGE: usize = 16_384;
const MAGIC_ARENA: u32 = 0x4B48_4152; // "KHAR"
const MAGIC_MMAP: u32 = 0x4B48_4D4D; // "KHMM"
const FLAG_FREE: u32 = 1;

/// Header immediately before every user pointer.
#[repr(C, align(16))]
struct Hdr {
    magic: u32,
    flags: u32,
    /// Usable payload size in bytes (not including this header).
    size: usize,
    /// Next free chunk (only meaningful when `FLAG_FREE` is set).
    next: *mut Hdr,
}

const HDR_SIZE: usize = core::mem::size_of::<Hdr>();

struct Arena {
    buf: core::cell::UnsafeCell<[u8; ARENA_SIZE]>,
    /// Bump cursor for never-before-used arena bytes.
    bump: AtomicUsize,
    /// Singly-linked free list of arena chunks.
    free_head: core::cell::UnsafeCell<*mut Hdr>,
}

// SAFETY: guarded by [`HEAP_LOCK`].
unsafe impl Sync for Arena {}

static ARENA: Arena = Arena {
    buf: core::cell::UnsafeCell::new([0; ARENA_SIZE]),
    bump: AtomicUsize::new(0),
    free_head: core::cell::UnsafeCell::new(core::ptr::null_mut()),
};

static HEAP_LOCK: AtomicBool = AtomicBool::new(false);

#[inline]
fn lock() {
    while HEAP_LOCK
        .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        core::hint::spin_loop();
    }
}

#[inline]
fn unlock() {
    HEAP_LOCK.store(false, Ordering::Release);
}

#[inline]
fn align_up(value: usize, align: usize) -> usize {
    let a = align.max(1);
    let mask = a.saturating_sub(1);
    value.saturating_add(mask) & !mask
}

#[inline]
fn user_ptr(h: *mut Hdr) -> *mut c_void {
    // SAFETY: header is live; user area follows it.
    unsafe { h.add(1).cast() }
}

#[inline]
fn hdr_from_user(ptr: *mut c_void) -> *mut Hdr {
    // SAFETY: caller guarantees `ptr` came from our allocator.
    unsafe { ptr.cast::<Hdr>().sub(1) }
}

/// C `malloc` → nlist `_malloc`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn malloc(size: usize) -> *mut c_void {
    trace::note_size(b"malloc", size);
    allocate(size)
}

/// C `free` → nlist `_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn free(ptr: *mut c_void) {
    if ptr.is_null() {
        return;
    }
    trace::note_ptr(b"free", ptr.addr());
    // SAFETY: only valid for pointers from malloc/calloc/realloc/posix_memalign.
    unsafe {
        free_inner(ptr);
    }
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
        unsafe {
            free(ptr);
        }
        return core::ptr::null_mut();
    }

    let h = hdr_from_user(ptr);
    // SAFETY: owned header.
    let (magic, old_size) = unsafe { ((*h).magic, (*h).size) };
    if magic != MAGIC_ARENA && magic != MAGIC_MMAP {
        // Unknown pointer: fall back to fresh alloc (best-effort).
        return allocate(size);
    }
    if size <= old_size {
        return ptr;
    }
    let fresh = allocate(size);
    if fresh.is_null() {
        return core::ptr::null_mut();
    }
    // SAFETY: both regions live; copy old payload.
    unsafe {
        let _ = crate::stdio::memcpy(fresh, ptr, old_size.min(size));
        free(ptr);
    }
    fresh
}

fn allocate(size: usize) -> *mut c_void {
    let need = if size == 0 { 1 } else { size };
    let need = align_up(need, ALIGN);

    if need >= MMAP_THRESHOLD {
        return allocate_mmap(need);
    }

    lock();
    let p = allocate_arena(need);
    unlock();
    if p.is_null() {
        // Arena full / fragmented: try mmap for the small request too.
        return allocate_mmap(need);
    }
    p
}

fn allocate_arena(need: usize) -> *mut c_void {
    // First-fit free list.
    // SAFETY: free_head only touched under lock.
    let head = unsafe { *ARENA.free_head.get() };
    let mut prev: *mut Hdr = core::ptr::null_mut();
    let mut cur = head;
    while !cur.is_null() {
        // SAFETY: free-list nodes are arena headers we created.
        let (sz, next) = unsafe { ((*cur).size, (*cur).next) };
        if sz >= need {
            // Unlink.
            if prev.is_null() {
                unsafe {
                    *ARENA.free_head.get() = next;
                }
            } else {
                unsafe {
                    (*prev).next = next;
                }
            }
            unsafe {
                (*cur).flags = 0;
                (*cur).next = core::ptr::null_mut();
                // Optional split if leftover is large enough for another header+16.
                let leftover = sz.saturating_sub(need);
                if leftover >= HDR_SIZE.saturating_add(ALIGN) {
                    // Payload is 16-byte aligned; `need` is too → split header aligned.
                    let split_addr = user_ptr(cur).addr().saturating_add(need);
                    let split = core::ptr::with_exposed_provenance_mut::<Hdr>(split_addr);
                    (*split).magic = MAGIC_ARENA;
                    (*split).flags = FLAG_FREE;
                    (*split).size = leftover.saturating_sub(HDR_SIZE);
                    (*split).next = *ARENA.free_head.get();
                    *ARENA.free_head.get() = split;
                    (*cur).size = need;
                }
            }
            return user_ptr(cur);
        }
        prev = cur;
        cur = next;
    }

    // Bump allocate a fresh chunk.
    let total = HDR_SIZE.saturating_add(need);
    let total = align_up(total, ALIGN);
    loop {
        let cur_off = ARENA.bump.load(Ordering::Relaxed);
        let next = match cur_off.checked_add(total) {
            Some(n) if n <= ARENA_SIZE => n,
            _ => {
                errno::set_errno(12);
                trace::note(b"[kh-libsystem] malloc ENOMEM (arena)\n");
                return core::ptr::null_mut();
            }
        };
        if ARENA
            .bump
            .compare_exchange(cur_off, next, Ordering::SeqCst, Ordering::Relaxed)
            .is_ok()
        {
            // Arena base is 16-byte aligned; bump offsets are always multiples of ALIGN.
            let base_addr = ARENA.buf.get().addr();
            let h =
                core::ptr::with_exposed_provenance_mut::<Hdr>(base_addr.saturating_add(cur_off));
            unsafe {
                (*h).magic = MAGIC_ARENA;
                (*h).flags = 0;
                (*h).size = need;
                (*h).next = core::ptr::null_mut();
            }
            return user_ptr(h);
        }
    }
}

fn allocate_mmap(need: usize) -> *mut c_void {
    let total = align_up(HDR_SIZE.saturating_add(need), PAGE);
    let prot = 3_u64; // PROT_READ | PROT_WRITE
    let flags = 0x1000_u64 | 0x0002_u64; // MAP_ANON | MAP_PRIVATE
    // Darwin `fd = -1` for MAP_ANON (sign-extended in the register).
    let fd = !0_u64;
    // SAFETY: anonymous mmap via trap/host.
    let ret = unsafe {
        sys::syscall6(
            SYS_MMAP,
            0,
            u64::try_from(total).unwrap_or(0),
            prot,
            flags,
            fd,
            0,
        )
    };
    if ret < 0 {
        errno::set_errno(12);
        trace::note(b"[kh-libsystem] malloc ENOMEM (mmap)\n");
        return core::ptr::null_mut();
    }
    let base = usize::try_from(ret).unwrap_or(0);
    if base == 0 {
        errno::set_errno(12);
        return core::ptr::null_mut();
    }
    let h = core::ptr::with_exposed_provenance_mut::<Hdr>(base);
    unsafe {
        (*h).magic = MAGIC_MMAP;
        (*h).flags = 0;
        (*h).size = need;
        (*h).next = core::ptr::null_mut();
    }
    user_ptr(h)
}

unsafe fn free_inner(ptr: *mut c_void) {
    let h = hdr_from_user(ptr);
    // SAFETY: header just before user pointer.
    let magic = unsafe { (*h).magic };
    match magic {
        MAGIC_MMAP => {
            let size = unsafe { (*h).size };
            let total = align_up(HDR_SIZE.saturating_add(size), PAGE);
            let addr = u64::try_from(h.addr()).unwrap_or(0);
            // SAFETY: whole mapping from allocate_mmap.
            let _ = unsafe { sys::syscall2(SYS_MUNMAP, addr, u64::try_from(total).unwrap_or(0)) };
        }
        MAGIC_ARENA => {
            lock();
            unsafe {
                if (*h).flags & FLAG_FREE != 0 {
                    // Double-free: ignore.
                    unlock();
                    return;
                }
                (*h).flags = FLAG_FREE;
                (*h).next = *ARENA.free_head.get();
                *ARENA.free_head.get() = h;
            }
            unlock();
        }
        _ => {
            // Not ours; ignore (matches soft freestanding behavior).
            trace::note(b"[kh-libsystem] free: unknown pointer\n");
        }
    }
}
