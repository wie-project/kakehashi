//! Freestanding heap: size-class arena free lists + anonymous `mmap` for large blocks.
//!
//! Guests like `7zz` import `malloc`/`free`/`realloc` but **not** `mmap`, so all
//! working-set traffic goes through this module. A pure bump allocator with a
//! no-op `free` exhausts quickly under archive create; real free-list + mmap
//! keeps multi‑MiB allocate/free churn alive.
//!
//! ## Size classes (plate-A residual)
//!
//! A single first-fit freelist walked **O(n)** per alloc → ~1e9 node visits on
//! multi-file `7zz` plate A (avg_walk thousands). Segregated LIFO free lists by
//! power-of-two payload class (`16 … 128KiB`) make reuse **O(1)** per class
//! (plus a short walk over empty larger classes).
//!
//! ## Alignment policy (clang / modern `ld`)
//!
//! - **Arena** (`<` [`MMAP_THRESHOLD`]): 16-byte alignment, freelist reuse.
//!   Mid-size traffic (LLVM/clang working set) **must** stay here — routing
//!   every `≥256` B alloc through anonymous `mmap`/`munmap` caused ~15k
//!   boundary crossings per `-cc1` on `g4-mini` (~50× wall residual).
//! - **mmap path** (`≥` [`MMAP_THRESHOLD`]): user pointer is **16 KiB-aligned**
//!   (Darwin arm64 page). Covers large buffers and, with over-alloc,
//!   `posix_memalign` / `operator new(align)` when align is a page.
//! - **`vm_allocate`**: separate soft path in `posix.rs` (also page-aligned)
//!   for modern `ld` `UnsafeHeaderWriter` when it uses Mach VM, not `malloc`.
//!
//! Do **not** re-introduce a blunt “every mid-size malloc is page-aligned mmap”
//! shortcut for G5 — fix alignment on the explicit align / large / VM paths.
//!
//! ## Heap stats (`KAKEHASHI_HEAP_STATS`)
//!
//! **Off by default.** Opt-in counters for plate-A residual digs. Hot path when
//! off: one `AtomicU8` load after first resolve. When on: cheap `fetch_add` on
//! alloc/free; dump to guest stderr (fd 2) at `_exit` / post-`main` dump.
//!
//! Host enables with `KAKEHASHI_HEAP_STATS=1` (truthy). Freestanding cannot
//! read host environ, so the first stats resolve queries
//! [`crate::KH_HELPER_HEAP_STATS_ON`] and seeds soft env. Guest `setenv` /
//! `kh_heap_stats_enable` also work.

use core::ffi::c_void;
use core::sync::atomic::{AtomicU8, AtomicU32, AtomicU64, AtomicUsize, Ordering};

use crate::errno;
use crate::sys::{self, SYS_MMAP, SYS_MUNMAP};
use crate::trace;
use crate::{KH_HELPER_PARK, KH_HELPER_WAKE};

const ALIGN: usize = 16;
/// Larger arena cuts mmap/munmap trap traffic for 7zz-class working sets.
const ARENA_SIZE: usize = 64 * 1024 * 1024;
const PAGE: usize = 16_384;
/// Allocations ≥ this size go straight to anonymous `mmap` (and `munmap` on free).
///
/// Equal to Darwin arm64 page so large `malloc` returns a **page-aligned** user
/// pointer (host Linux mmap is often only 4 KiB-aligned). Arena path only
/// guarantees [`ALIGN`] (16). Mid-size (`ALIGN … PAGE`) stays on the freelist.
const MMAP_THRESHOLD: usize = PAGE;
const MAGIC_ARENA: u32 = 0x4B48_4152; // "KHAR"
const MAGIC_MMAP: u32 = 0x4B48_4D4D; // "KHMM"
const FLAG_FREE: u32 = 1;

/// Power-of-two payload classes: `16 << i` for `i ∈ 0..NUM_CLASSES`.
/// Last class is 128 KiB; live arena traffic is only `<` [`MMAP_THRESHOLD`]
/// (larger requests use the page-aligned mmap path).
const NUM_CLASSES: usize = 14; // 16 … 128KiB

/// Header immediately before every user pointer.
#[repr(C, align(16))]
struct Hdr {
    magic: u32,
    flags: u32,
    /// Usable payload size in bytes (not including this header).
    size: usize,
    /// Next free chunk in the same size-class list (when `FLAG_FREE` is set).
    next: *mut Hdr,
}

const HDR_SIZE: usize = core::mem::size_of::<Hdr>();

struct Arena {
    buf: core::cell::UnsafeCell<[u8; ARENA_SIZE]>,
    /// Bump cursor for never-before-used arena bytes.
    bump: AtomicUsize,
    /// LIFO free list heads, one per size class (see [`NUM_CLASSES`]).
    free_heads: core::cell::UnsafeCell<[*mut Hdr; NUM_CLASSES]>,
}

// SAFETY: guarded by [`HEAP_LOCK`].
unsafe impl Sync for Arena {}

static ARENA: Arena = Arena {
    buf: core::cell::UnsafeCell::new([0; ARENA_SIZE]),
    bump: AtomicUsize::new(0),
    free_heads: core::cell::UnsafeCell::new([core::ptr::null_mut(); NUM_CLASSES]),
};

/// Payload size for size-class `idx` (`16 << idx`).
#[inline]
fn class_payload(idx: usize) -> usize {
    let shift = u32::try_from(idx).unwrap_or(0);
    // NUM_CLASSES is small; overflow → max usize (never used as live size).
    ALIGN.checked_shl(shift).unwrap_or(usize::MAX)
}

/// Smallest class whose payload is ≥ `need` (caller: `need` already aligned).
#[inline]
fn size_to_class(need: usize) -> usize {
    let need = need.max(ALIGN);
    let mut idx = 0_usize;
    while idx.saturating_add(1) < NUM_CLASSES && class_payload(idx) < need {
        idx = idx.saturating_add(1);
    }
    idx
}

/// Largest class whose payload is ≤ `size` (for free-list placement).
#[inline]
fn floor_class(size: usize) -> usize {
    if size < ALIGN {
        return 0;
    }
    let mut idx = 0_usize;
    while idx.saturating_add(1) < NUM_CLASSES && class_payload(idx.saturating_add(1)) <= size {
        idx = idx.saturating_add(1);
    }
    idx
}

// Futex-style heap lock (same 0/1/2 protocol as freestanding pthread_mutex).
// Pure spin deadlocks under zip MT: a worker can hold HEAP_LOCK then park on a
// guest mutex while another holds that mutex and needs malloc (spin forever).
const HEAP_UNLOCKED: u32 = 0;
const HEAP_LOCKED: u32 = 1;
const HEAP_CONTENDED: u32 = 2;

static HEAP_LOCK: AtomicU32 = AtomicU32::new(HEAP_UNLOCKED);

// ── Opt-in heap stats ───────────────────────────────────────────────────────
//
// Mode: 0 uninit, 1 off, 2 on. Resolved once from soft getenv + host seed.
const STATS_UNINIT: u8 = 0;
const STATS_OFF: u8 = 1;
const STATS_ON: u8 = 2;
static STATS_MODE: AtomicU8 = AtomicU8::new(STATS_UNINIT);

static STAT_MALLOC: AtomicU64 = AtomicU64::new(0);
static STAT_CALLOC: AtomicU64 = AtomicU64::new(0);
static STAT_REALLOC: AtomicU64 = AtomicU64::new(0);
static STAT_FREE: AtomicU64 = AtomicU64::new(0);
static STAT_REALLOC_INPLACE: AtomicU64 = AtomicU64::new(0);
static STAT_REALLOC_MOVE: AtomicU64 = AtomicU64::new(0);
static STAT_ARENA_OK: AtomicU64 = AtomicU64::new(0);
static STAT_MMAP_OK: AtomicU64 = AtomicU64::new(0);
static STAT_ARENA_TO_MMAP: AtomicU64 = AtomicU64::new(0);
static STAT_ENOMEM: AtomicU64 = AtomicU64::new(0);
static STAT_DOUBLE_FREE: AtomicU64 = AtomicU64::new(0);
static STAT_UNKNOWN_FREE: AtomicU64 = AtomicU64::new(0);
static STAT_MUNMAP: AtomicU64 = AtomicU64::new(0);
/// Free-list probes (each `allocate_arena` attempt; size-class LIFO).
static STAT_WALK_SCANS: AtomicU64 = AtomicU64::new(0);
/// Class probes per scan (was node visits under first-fit; n² signal).
static STAT_WALK_NODES: AtomicU64 = AtomicU64::new(0);
static STAT_WALK_HITS: AtomicU64 = AtomicU64::new(0);
static STAT_SPLITS: AtomicU64 = AtomicU64::new(0);
static STAT_BUMP: AtomicU64 = AtomicU64::new(0);
static STAT_FREELIST_PUSH: AtomicU64 = AtomicU64::new(0);
static STAT_FREELIST_LEN: AtomicUsize = AtomicUsize::new(0);
static STAT_FREELIST_MAX: AtomicUsize = AtomicUsize::new(0);
static STAT_BUMP_HW: AtomicUsize = AtomicUsize::new(0);
static STAT_LIVE_ARENA: AtomicUsize = AtomicUsize::new(0);
static STAT_LIVE_MMAP: AtomicUsize = AtomicUsize::new(0);
static STAT_PEAK_ARENA: AtomicUsize = AtomicUsize::new(0);
static STAT_PEAK_MMAP: AtomicUsize = AtomicUsize::new(0);
static STAT_MMAP_BYTES: AtomicU64 = AtomicU64::new(0);
static STAT_LOCK_PARK: AtomicU64 = AtomicU64::new(0);
/// Requested payload size histogram (need after align), 8 buckets.
const SIZE_BUCKETS: usize = 8;
#[allow(clippy::declare_interior_mutable_const)]
static STAT_SIZE_BUCKET: [AtomicU64; SIZE_BUCKETS] = {
    const ZERO: AtomicU64 = AtomicU64::new(0);
    [ZERO; SIZE_BUCKETS]
};

#[inline]
fn size_bucket(need: usize) -> usize {
    // 0: <64, 1: <256, 2: <1k, 3: <4k, 4: <16k (arena), 5: <64k mmap,
    // 6: <256k mmap, 7: ≥256k mmap
    if need < 64 {
        0
    } else if need < 256 {
        1
    } else if need < 1024 {
        2
    } else if need < 4096 {
        3
    } else if need < PAGE {
        4
    } else if need < 65_536 {
        5
    } else if need < 256 * 1024 {
        6
    } else {
        7
    }
}

#[inline]
fn note_size_bucket(need: usize) {
    if !stats_on_fast() {
        return;
    }
    let b = size_bucket(need);
    if let Some(a) = STAT_SIZE_BUCKET.get(b) {
        a.fetch_add(1, Ordering::Relaxed);
    }
}

#[inline]
fn stats_on_fast() -> bool {
    STATS_MODE.load(Ordering::Relaxed) == STATS_ON
}

/// Resolve mode once. Soft getenv after seed; also enable when host soft-seeded.
fn stats_mode() -> u8 {
    let m = STATS_MODE.load(Ordering::Relaxed);
    if m != STATS_UNINIT {
        return m;
    }
    // Seed soft env (PATH/HOME/…) then look for KAKEHASHI_HEAP_STATS.
    // Host bench scripts setenv into soft table via `soft_env_seed_heap_flag`.
    soft_env_seed_heap_flag();
    let on = soft_env_heap_stats_requested();
    let parsed = if on { STATS_ON } else { STATS_OFF };
    let _ = STATS_MODE.compare_exchange(STATS_UNINIT, parsed, Ordering::Relaxed, Ordering::Relaxed);
    STATS_MODE.load(Ordering::Relaxed)
}

/// Seed soft `KAKEHASHI_HEAP_STATS` from the host when requested.
///
/// Freestanding cannot read host `environ`; the loader/runtime exposes
/// [`crate::KH_HELPER_HEAP_STATS_ON`]. Digs and benches set
/// `KAKEHASHI_HEAP_STATS=1` on the **host** process; default is off (no
/// stderr dump noise on every `kh run`).
fn soft_env_seed_heap_flag() {
    let key = b"KAKEHASHI_HEAP_STATS\0";
    // SAFETY: key is NUL-terminated static.
    let existing = unsafe { crate::posix::getenv(key.as_ptr().cast()) };
    if !existing.is_null() {
        return;
    }
    // SAFETY: helper id matches kh-runtime; no guest buffer.
    let on = unsafe { sys::helper0(crate::KH_HELPER_HEAP_STATS_ON) };
    if on <= 0 {
        return;
    }
    let val = b"1\0";
    let _ = unsafe { crate::posix::setenv(key.as_ptr().cast(), val.as_ptr().cast(), 1) };
}

fn soft_env_heap_stats_requested() -> bool {
    let key = b"KAKEHASHI_HEAP_STATS\0";
    // SAFETY: key is NUL-terminated static.
    let p = unsafe { crate::posix::getenv(key.as_ptr().cast()) };
    if p.is_null() {
        return false;
    }
    // SAFETY: soft env slots are NUL-terminated. `c_char` is `i8` on Darwin.
    let b = unsafe { *p }.cast_unsigned();
    // off: empty, "0", "n"/"N", "f"/"F"
    !(b == 0 || b == b'0' || b == b'n' || b == b'N' || b == b'f' || b == b'F')
}

/// Force stats on (tests / dig hooks). No-op if already resolved off/on.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kh_heap_stats_enable() {
    STATS_MODE.store(STATS_ON, Ordering::Relaxed);
}

/// Dump freestanding heap stats to guest stderr (fd 2).
///
/// Called from guest `_exit` and from the host after `main` returns (dyld-style
/// `exit(main(...))` never enters freestanding `_exit`).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kh_heap_stats_dump() {
    dump_stats_if_enabled();
}

#[inline]
fn park_u32(word: &AtomicU32, expected: u32) {
    let addr = u64::try_from(core::ptr::from_ref(word).addr()).unwrap_or(0);
    let _ = unsafe { sys::helper2(KH_HELPER_PARK, addr, u64::from(expected)) };
}

#[inline]
fn wake_u32(word: &AtomicU32, n: u32) {
    let addr = u64::try_from(core::ptr::from_ref(word).addr()).unwrap_or(0);
    let _ = unsafe { sys::helper2(KH_HELPER_WAKE, addr, u64::from(n)) };
}

#[inline]
fn lock() {
    if HEAP_LOCK
        .compare_exchange(
            HEAP_UNLOCKED,
            HEAP_LOCKED,
            Ordering::Acquire,
            Ordering::Relaxed,
        )
        .is_ok()
    {
        return;
    }
    loop {
        for _ in 0..32_u32 {
            let cur = HEAP_LOCK.load(Ordering::Relaxed);
            if cur == HEAP_UNLOCKED {
                if HEAP_LOCK
                    .compare_exchange(
                        HEAP_UNLOCKED,
                        HEAP_LOCKED,
                        Ordering::Acquire,
                        Ordering::Relaxed,
                    )
                    .is_ok()
                {
                    return;
                }
            } else if cur == HEAP_LOCKED {
                let _ = HEAP_LOCK.compare_exchange(
                    HEAP_LOCKED,
                    HEAP_CONTENDED,
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                );
            }
            core::hint::spin_loop();
        }
        let prev = HEAP_LOCK.swap(HEAP_CONTENDED, Ordering::Acquire);
        if prev == HEAP_UNLOCKED {
            return;
        }
        if stats_on_fast() {
            STAT_LOCK_PARK.fetch_add(1, Ordering::Relaxed);
        }
        park_u32(&HEAP_LOCK, HEAP_CONTENDED);
    }
}

#[inline]
fn unlock() {
    // Clear to 0 in one step (avoids intermediate "locked" after contended).
    let prev = HEAP_LOCK.swap(HEAP_UNLOCKED, Ordering::Release);
    if prev == HEAP_CONTENDED {
        wake_u32(&HEAP_LOCK, u32::MAX);
    }
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

fn note_live_arena_add(bytes: usize) {
    if !stats_on_fast() {
        return;
    }
    let now = STAT_LIVE_ARENA
        .fetch_add(bytes, Ordering::Relaxed)
        .saturating_add(bytes);
    bump_peak(&STAT_PEAK_ARENA, now);
}

fn note_live_arena_sub(bytes: usize) {
    if !stats_on_fast() {
        return;
    }
    let _ = STAT_LIVE_ARENA.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
        Some(v.saturating_sub(bytes))
    });
}

fn note_live_mmap_add(bytes: usize, map_bytes: usize) {
    if !stats_on_fast() {
        return;
    }
    let now = STAT_LIVE_MMAP
        .fetch_add(bytes, Ordering::Relaxed)
        .saturating_add(bytes);
    bump_peak(&STAT_PEAK_MMAP, now);
    STAT_MMAP_BYTES.fetch_add(
        u64::try_from(map_bytes).unwrap_or(u64::MAX),
        Ordering::Relaxed,
    );
}

fn note_live_mmap_sub(bytes: usize) {
    if !stats_on_fast() {
        return;
    }
    let _ = STAT_LIVE_MMAP.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
        Some(v.saturating_sub(bytes))
    });
}

fn bump_peak(peak_slot: &AtomicUsize, now: usize) {
    let mut peak = peak_slot.load(Ordering::Relaxed);
    while now > peak {
        match peak_slot.compare_exchange(peak, now, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => break,
            Err(p) => peak = p,
        }
    }
}

fn freelist_push_note() {
    if !stats_on_fast() {
        return;
    }
    STAT_FREELIST_PUSH.fetch_add(1, Ordering::Relaxed);
    let n = STAT_FREELIST_LEN
        .fetch_add(1, Ordering::Relaxed)
        .saturating_add(1);
    bump_peak(&STAT_FREELIST_MAX, n);
}

fn freelist_pop_note() {
    if !stats_on_fast() {
        return;
    }
    let _ = STAT_FREELIST_LEN.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
        Some(v.saturating_sub(1))
    });
}

/// Push `h` onto the size-class freelist for its payload (under lock).
///
/// # Safety
/// `h` is a live arena header; `HEAP_LOCK` held; `(*h).size` is the payload.
unsafe fn freelist_push(h: *mut Hdr) {
    let size = unsafe { (*h).size };
    let c = floor_class(size);
    // SAFETY: free_heads only under lock.
    let heads = unsafe { &mut *ARENA.free_heads.get() };
    let Some(head_slot) = heads.get_mut(c) else {
        return;
    };
    unsafe {
        (*h).flags = FLAG_FREE;
        (*h).next = *head_slot;
    }
    *head_slot = h;
    freelist_push_note();
}

/// Pop the LIFO head of class `c` (under lock). `None` if empty.
///
/// # Safety
/// `HEAP_LOCK` held.
unsafe fn freelist_pop(c: usize) -> Option<*mut Hdr> {
    let heads = unsafe { &mut *ARENA.free_heads.get() };
    let head_slot = heads.get_mut(c)?;
    let h = *head_slot;
    if h.is_null() {
        return None;
    }
    // SAFETY: node was pushed by freelist_push.
    unsafe {
        *head_slot = (*h).next;
        (*h).flags = 0;
        (*h).next = core::ptr::null_mut();
    }
    freelist_pop_note();
    Some(h)
}

/// Take `take` bytes of payload from free chunk `h`, free remainder if any.
///
/// # Safety
/// `h` just popped; lock held; `(*h).size >= take`.
unsafe fn take_from_free(h: *mut Hdr, take: usize) -> *mut c_void {
    let sz = unsafe { (*h).size };
    let leftover = sz.saturating_sub(take);
    if leftover >= HDR_SIZE.saturating_add(ALIGN) {
        let split_addr = user_ptr(h).addr().saturating_add(take);
        let split = core::ptr::with_exposed_provenance_mut::<Hdr>(split_addr);
        unsafe {
            (*split).magic = MAGIC_ARENA;
            (*split).size = leftover.saturating_sub(HDR_SIZE);
            (*h).size = take;
            freelist_push(split);
        }
        if stats_on_fast() {
            STAT_SPLITS.fetch_add(1, Ordering::Relaxed);
        }
    }
    // else: keep whole chunk (internal waste ≤ one header + align)
    user_ptr(h)
}

/// C `malloc` → nlist `_malloc`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn malloc(size: usize) -> *mut c_void {
    // Soft iostream ZTT/ZTV absolute pointers (modern ld stringstream).
    crate::libcxx_iostream::ensure_iostream_vtables();
    // Resolve mode early so first-alloc digs count fully.
    let _ = stats_mode();
    if stats_on_fast() {
        STAT_MALLOC.fetch_add(1, Ordering::Relaxed);
    }
    trace::note_size(b"malloc", size);
    allocate(size)
}

/// C `free` → nlist `_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn free(ptr: *mut c_void) {
    if ptr.is_null() {
        return;
    }
    if stats_on_fast() {
        STAT_FREE.fetch_add(1, Ordering::Relaxed);
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
    let _ = stats_mode();
    let Some(total) = count.checked_mul(size) else {
        errno::set_errno(12);
        if stats_on_fast() {
            STAT_ENOMEM.fetch_add(1, Ordering::Relaxed);
        }
        trace::note(b"[kh-libsystem] calloc overflow\n");
        return core::ptr::null_mut();
    };
    if stats_on_fast() {
        STAT_CALLOC.fetch_add(1, Ordering::Relaxed);
    }
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
    let _ = stats_mode();
    if stats_on_fast() {
        STAT_REALLOC.fetch_add(1, Ordering::Relaxed);
    }
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
        if stats_on_fast() {
            STAT_REALLOC_INPLACE.fetch_add(1, Ordering::Relaxed);
        }
        return ptr;
    }
    let fresh = allocate(size);
    if fresh.is_null() {
        return core::ptr::null_mut();
    }
    if stats_on_fast() {
        STAT_REALLOC_MOVE.fetch_add(1, Ordering::Relaxed);
    }
    // SAFETY: both regions live; copy old payload.
    unsafe {
        let _ = crate::stdio::memcpy(fresh, ptr, old_size.min(size));
        free(ptr);
    }
    fresh
}

/// C `reallocf` → nlist `_reallocf` (BSD: free original on failure).
///
/// Observed: Apple `ld-classic` (G4 multi-file link).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn reallocf(ptr: *mut c_void, size: usize) -> *mut c_void {
    // SAFETY: same contract as realloc; on failure free the original when non-null.
    let p = unsafe { realloc(ptr, size) };
    if p.is_null() && !ptr.is_null() && size != 0 {
        unsafe {
            free(ptr);
        }
    }
    p
}

/// Darwin `malloc_size` → nlist `_malloc_size` (usable size of allocation).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn malloc_size(ptr: *const c_void) -> usize {
    if ptr.is_null() {
        return 0;
    }
    let h = hdr_from_user(ptr.cast_mut());
    // SAFETY: only valid for freestanding heap pointers.
    let magic = unsafe { (*h).magic };
    if magic != MAGIC_ARENA && magic != MAGIC_MMAP {
        return 0;
    }
    unsafe { (*h).size }
}

fn allocate(size: usize) -> *mut c_void {
    let need = if size == 0 { 1 } else { size };
    let need = align_up(need, ALIGN);
    note_size_bucket(need);

    // Large / page-class: anonymous mmap with 16 KiB-aligned user (see module
    // docs). Mid-size stays on the size-class arena — do not force mmap here.
    if need >= MMAP_THRESHOLD {
        return allocate_mmap(need);
    }

    lock();
    let p = allocate_arena(need);
    unlock();
    if p.is_null() {
        // Arena full / fragmented: try mmap for the small request too.
        if stats_on_fast() {
            STAT_ARENA_TO_MMAP.fetch_add(1, Ordering::Relaxed);
        }
        return allocate_mmap(need);
    }
    p
}

/// Allocate `size` bytes with user pointer aligned to `align` (power of two).
///
/// Returned pointer is freeable with [`free`] (heap header immediately before
/// the user address). Used by `posix_memalign` and high-align `operator new`.
///
/// - `align ≤ 16`: ordinary [`allocate`] (arena or large mmap).
/// - `align > 16`: page-aligned mmap path (satisfies any power-of-two align
///   up to Darwin page; larger align uses that align for the user pointer).
pub(crate) fn allocate_aligned(size: usize, align: usize) -> *mut c_void {
    let align = align.max(1).next_power_of_two().max(ALIGN);
    let need = if size == 0 { 1 } else { size };
    if align <= ALIGN {
        return allocate(need);
    }
    // PAGE-aligned mmap user also satisfies smaller power-of-two aligns.
    let user_align = align.max(PAGE);
    allocate_mmap_aligned(need, user_align)
}

fn allocate_arena(need: usize) -> *mut c_void {
    // Round up to size-class payload so free-list bins stay LIFO-exact-ish.
    let c0 = size_to_class(need);
    let take = class_payload(c0).max(need);

    // Segregated free lists: probe class c0.. then larger (each pop is O(1) LIFO).
    // SAFETY: free_heads only under HEAP_LOCK (caller holds lock).
    let mut probes = 0_u64;
    for c in c0..NUM_CLASSES {
        probes = probes.saturating_add(1);
        // SAFETY: lock held.
        if let Some(h) = unsafe { freelist_pop(c) } {
            let sz = unsafe { (*h).size };
            // floor_class placement ⇒ sz ≥ class_payload(c) ≥ class_payload(c0) ≥ need
            // when c ≥ c0; still guard for non-class leftovers.
            if sz < take {
                // Too small (should be rare): push back and try next class.
                unsafe {
                    freelist_push(h);
                }
                continue;
            }
            let p = unsafe { take_from_free(h, take) };
            if stats_on_fast() {
                STAT_WALK_SCANS.fetch_add(1, Ordering::Relaxed);
                STAT_WALK_NODES.fetch_add(probes, Ordering::Relaxed);
                STAT_WALK_HITS.fetch_add(1, Ordering::Relaxed);
                STAT_ARENA_OK.fetch_add(1, Ordering::Relaxed);
            }
            note_live_arena_add(take);
            return p;
        }
    }

    if stats_on_fast() {
        STAT_WALK_SCANS.fetch_add(1, Ordering::Relaxed);
        STAT_WALK_NODES.fetch_add(probes, Ordering::Relaxed);
    }

    // Bump allocate a fresh class-sized chunk.
    let total = align_up(HDR_SIZE.saturating_add(take), ALIGN);
    loop {
        let cur_off = ARENA.bump.load(Ordering::Relaxed);
        let next = match cur_off.checked_add(total) {
            Some(n) if n <= ARENA_SIZE => n,
            _ => {
                errno::set_errno(12);
                if stats_on_fast() {
                    STAT_ENOMEM.fetch_add(1, Ordering::Relaxed);
                }
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
                (*h).size = take;
                (*h).next = core::ptr::null_mut();
            }
            if stats_on_fast() {
                STAT_BUMP.fetch_add(1, Ordering::Relaxed);
                STAT_ARENA_OK.fetch_add(1, Ordering::Relaxed);
                bump_peak(&STAT_BUMP_HW, next);
            }
            note_live_arena_add(take);
            return user_ptr(h);
        }
    }
}

fn allocate_mmap(need: usize) -> *mut c_void {
    allocate_mmap_aligned(need, PAGE)
}

/// Anonymous mmap with user pointer aligned to `user_align` (power of two ≥ 16).
///
/// Layout:
///   mmap base (host-aligned)
///   … pad …
///   Hdr immediately before user
///   user @ align_up(base+HDR_SIZE, user_align)
///
/// `Hdr.next` = original mmap base; `Hdr.flags` = map length (bytes) for munmap
/// (not a freelist link; MAGIC_MMAP never uses freelist).
fn allocate_mmap_aligned(need: usize, user_align: usize) -> *mut c_void {
    let need = need.max(1);
    let user_align = user_align.max(ALIGN).next_power_of_two();
    // Worst-case pad to user_align, then round map length to PAGE for host.
    let total = align_up(
        HDR_SIZE
            .saturating_add(need)
            .saturating_add(user_align),
        PAGE,
    );
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
        if stats_on_fast() {
            STAT_ENOMEM.fetch_add(1, Ordering::Relaxed);
        }
        trace::note(b"[kh-libsystem] malloc ENOMEM (mmap)\n");
        return core::ptr::null_mut();
    }
    let base = usize::try_from(ret).unwrap_or(0);
    if base == 0 {
        errno::set_errno(12);
        if stats_on_fast() {
            STAT_ENOMEM.fetch_add(1, Ordering::Relaxed);
        }
        return core::ptr::null_mut();
    }
    let user_addr = align_up(base.saturating_add(HDR_SIZE), user_align);
    if user_addr.saturating_add(need) > base.saturating_add(total)
        || user_addr < base.saturating_add(HDR_SIZE)
    {
        let _ = unsafe {
            sys::syscall2(
                SYS_MUNMAP,
                u64::try_from(base).unwrap_or(0),
                u64::try_from(total).unwrap_or(0),
            )
        };
        errno::set_errno(12);
        if stats_on_fast() {
            STAT_ENOMEM.fetch_add(1, Ordering::Relaxed);
        }
        return core::ptr::null_mut();
    }
    let h = core::ptr::with_exposed_provenance_mut::<Hdr>(user_addr.saturating_sub(HDR_SIZE));
    unsafe {
        (*h).magic = MAGIC_MMAP;
        // flags: map length for munmap (fits in u32 for our sizes; use size_t via cast).
        (*h).flags = u32::try_from(total).unwrap_or(u32::MAX);
        (*h).size = need;
        // Stash mapping base for munmap (not a freelist link).
        (*h).next = core::ptr::with_exposed_provenance_mut::<Hdr>(base);
    }
    if stats_on_fast() {
        STAT_MMAP_OK.fetch_add(1, Ordering::Relaxed);
    }
    note_live_mmap_add(need, total);
    core::ptr::with_exposed_provenance_mut(user_addr)
}

unsafe fn free_inner(ptr: *mut c_void) {
    let h = hdr_from_user(ptr);
    // SAFETY: header just before user pointer.
    let magic = unsafe { (*h).magic };
    match magic {
        MAGIC_MMAP => {
            let size = unsafe { (*h).size };
            // Original mmap base stashed in next; map length in flags (see allocate_mmap_aligned).
            let base = unsafe { (*h).next.addr() };
            let total = {
                let fl = usize::try_from(unsafe { (*h).flags }).unwrap_or(0);
                if fl >= size && fl >= HDR_SIZE {
                    fl
                } else {
                    // Legacy formula (pre-flags stash): same as old allocate_mmap.
                    align_up(HDR_SIZE.saturating_add(size), PAGE).saturating_add(PAGE)
                }
            };
            let addr = u64::try_from(base).unwrap_or(0);
            // SAFETY: whole mapping from allocate_mmap_aligned.
            let _ = unsafe { sys::syscall2(SYS_MUNMAP, addr, u64::try_from(total).unwrap_or(0)) };
            if stats_on_fast() {
                STAT_MUNMAP.fetch_add(1, Ordering::Relaxed);
            }
            note_live_mmap_sub(size);
        }
        MAGIC_ARENA => {
            lock();
            // SAFETY: arena header under lock.
            unsafe {
                if (*h).flags & FLAG_FREE != 0 {
                    // Double-free: ignore.
                    if stats_on_fast() {
                        STAT_DOUBLE_FREE.fetch_add(1, Ordering::Relaxed);
                    }
                    unlock();
                    return;
                }
                let size = (*h).size;
                freelist_push(h);
                unlock();
                note_live_arena_sub(size);
            }
        }
        _ => {
            // Not ours; ignore (matches soft freestanding behavior).
            if stats_on_fast() {
                STAT_UNKNOWN_FREE.fetch_add(1, Ordering::Relaxed);
            }
            trace::note(b"[kh-libsystem] free: unknown pointer\n");
        }
    }
}

/// Dump ranked freestanding heap counters to guest stderr (fd 2).
///
/// Safe from `_exit` / `exit` under guest TPIDR (uses Darwin `write`).
pub(crate) fn dump_stats_if_enabled() {
    if stats_mode() != STATS_ON {
        return;
    }
    let malloc_n = STAT_MALLOC.load(Ordering::Relaxed);
    let calloc_n = STAT_CALLOC.load(Ordering::Relaxed);
    let realloc_n = STAT_REALLOC.load(Ordering::Relaxed);
    let free_n = STAT_FREE.load(Ordering::Relaxed);
    if malloc_n == 0 && calloc_n == 0 && realloc_n == 0 && free_n == 0 {
        trace::force_note(b"kh heap stats: total_ops=0 (no alloc/free)\n");
        return;
    }

    let arena_ok = STAT_ARENA_OK.load(Ordering::Relaxed);
    let mmap_ok = STAT_MMAP_OK.load(Ordering::Relaxed);
    let arena_to_mmap = STAT_ARENA_TO_MMAP.load(Ordering::Relaxed);
    let walks = STAT_WALK_SCANS.load(Ordering::Relaxed);
    let walk_nodes = STAT_WALK_NODES.load(Ordering::Relaxed);
    let walk_hits = STAT_WALK_HITS.load(Ordering::Relaxed);
    let avg_walk = walk_nodes.checked_div(walks).unwrap_or(0);
    let bump = STAT_BUMP.load(Ordering::Relaxed);
    let splits = STAT_SPLITS.load(Ordering::Relaxed);
    let fl_max = usize_u64(STAT_FREELIST_MAX.load(Ordering::Relaxed));
    let fl_now = usize_u64(STAT_FREELIST_LEN.load(Ordering::Relaxed));
    let bump_hw = usize_u64(STAT_BUMP_HW.load(Ordering::Relaxed));
    let peak_a = usize_u64(STAT_PEAK_ARENA.load(Ordering::Relaxed));
    let peak_m = usize_u64(STAT_PEAK_MMAP.load(Ordering::Relaxed));
    let live_a = usize_u64(STAT_LIVE_ARENA.load(Ordering::Relaxed));
    let live_m = usize_u64(STAT_LIVE_MMAP.load(Ordering::Relaxed));
    let arena_cap = usize_u64(ARENA_SIZE);
    let mmap_bytes = STAT_MMAP_BYTES.load(Ordering::Relaxed);
    let munmap_n = STAT_MUNMAP.load(Ordering::Relaxed);
    let lock_park = STAT_LOCK_PARK.load(Ordering::Relaxed);
    let enomem = STAT_ENOMEM.load(Ordering::Relaxed);
    let realloc_in = STAT_REALLOC_INPLACE.load(Ordering::Relaxed);
    let realloc_mv = STAT_REALLOC_MOVE.load(Ordering::Relaxed);
    let double_free = STAT_DOUBLE_FREE.load(Ordering::Relaxed);
    let unknown_free = STAT_UNKNOWN_FREE.load(Ordering::Relaxed);

    // Multi-line dump via small stack buffers (no alloc).
    let mut line = [0_u8; 320];
    let mut n = 0_usize;
    n = append(&mut line, n, b"kh heap stats:\n");
    n = append(&mut line, n, b"\tmalloc=");
    n = append_dec(&mut line, n, malloc_n);
    n = append(&mut line, n, b" calloc=");
    n = append_dec(&mut line, n, calloc_n);
    n = append(&mut line, n, b" realloc=");
    n = append_dec(&mut line, n, realloc_n);
    n = append(&mut line, n, b" free=");
    n = append_dec(&mut line, n, free_n);
    n = append(&mut line, n, b"\n");
    force_line(&line, n);

    n = 0;
    n = append(&mut line, n, b"\trealloc_inplace=");
    n = append_dec(&mut line, n, realloc_in);
    n = append(&mut line, n, b" realloc_move=");
    n = append_dec(&mut line, n, realloc_mv);
    n = append(&mut line, n, b" enomem=");
    n = append_dec(&mut line, n, enomem);
    n = append(&mut line, n, b" double_free=");
    n = append_dec(&mut line, n, double_free);
    n = append(&mut line, n, b" unknown_free=");
    n = append_dec(&mut line, n, unknown_free);
    n = append(&mut line, n, b"\n");
    force_line(&line, n);

    n = 0;
    n = append(&mut line, n, b"\tarena_ok=");
    n = append_dec(&mut line, n, arena_ok);
    n = append(&mut line, n, b" (bump=");
    n = append_dec(&mut line, n, bump);
    n = append(&mut line, n, b" freelist_hit=");
    n = append_dec(&mut line, n, walk_hits);
    n = append(&mut line, n, b") mmap_ok=");
    n = append_dec(&mut line, n, mmap_ok);
    n = append(&mut line, n, b" arena_to_mmap=");
    n = append_dec(&mut line, n, arena_to_mmap);
    n = append(&mut line, n, b" munmap=");
    n = append_dec(&mut line, n, munmap_n);
    n = append(&mut line, n, b"\n");
    force_line(&line, n);

    n = 0;
    n = append(&mut line, n, b"\tfreelist: scans=");
    n = append_dec(&mut line, n, walks);
    n = append(&mut line, n, b" nodes_walked=");
    n = append_dec(&mut line, n, walk_nodes);
    n = append(&mut line, n, b" avg_walk=");
    n = append_dec(&mut line, n, avg_walk);
    n = append(&mut line, n, b" splits=");
    n = append_dec(&mut line, n, splits);
    n = append(&mut line, n, b" len_now=");
    n = append_dec(&mut line, n, fl_now);
    n = append(&mut line, n, b" len_max=");
    n = append_dec(&mut line, n, fl_max);
    n = append(&mut line, n, b"\n");
    force_line(&line, n);

    n = 0;
    n = append(&mut line, n, b"\tbytes: bump_hw=");
    n = append_dec(&mut line, n, bump_hw);
    n = append(&mut line, n, b"/");
    n = append_dec(&mut line, n, arena_cap);
    n = append(&mut line, n, b" arena_live=");
    n = append_dec(&mut line, n, live_a);
    n = append(&mut line, n, b" peak=");
    n = append_dec(&mut line, n, peak_a);
    n = append(&mut line, n, b" mmap_live=");
    n = append_dec(&mut line, n, live_m);
    n = append(&mut line, n, b" peak=");
    n = append_dec(&mut line, n, peak_m);
    n = append(&mut line, n, b" mmap_bytes_sum=");
    n = append_dec(&mut line, n, mmap_bytes);
    n = append(&mut line, n, b"\n");
    force_line(&line, n);

    n = 0;
    n = append(&mut line, n, b"\tlock_park=");
    n = append_dec(&mut line, n, lock_park);
    n = append(&mut line, n, b"\n");
    force_line(&line, n);

    // size buckets: <64 <256 <1k <4k <16k <64k <256k ≥256k
    let labels: [&[u8]; SIZE_BUCKETS] = [
        b"<64", b"<256", b"<1k", b"<4k", b"<16k", b"<64k", b"<256k", b">=256k",
    ];
    n = 0;
    n = append(&mut line, n, b"\tsizes:");
    for (i, lab) in labels.iter().enumerate() {
        let c = STAT_SIZE_BUCKET
            .get(i)
            .map_or(0, |a| a.load(Ordering::Relaxed));
        if c == 0 {
            continue;
        }
        n = append(&mut line, n, b" ");
        n = append(&mut line, n, lab);
        n = append(&mut line, n, b"=");
        n = append_dec(&mut line, n, c);
    }
    n = append(&mut line, n, b"\n");
    force_line(&line, n);
}

#[inline]
fn usize_u64(v: usize) -> u64 {
    u64::try_from(v).unwrap_or(u64::MAX)
}

#[inline]
fn force_line(buf: &[u8], n: usize) {
    if let Some(slice) = buf.get(..n) {
        trace::force_note(slice);
    }
}

fn append(buf: &mut [u8], off: usize, bytes: &[u8]) -> usize {
    let mut o = off;
    for &b in bytes {
        if let Some(slot) = buf.get_mut(o) {
            *slot = b;
            o = o.saturating_add(1);
        } else {
            break;
        }
    }
    o
}

fn append_dec(buf: &mut [u8], off: usize, mut value: u64) -> usize {
    if value == 0 {
        return append(buf, off, b"0");
    }
    let mut tmp = [0_u8; 20];
    let mut i = 0_usize;
    while value > 0 {
        if let Some(slot) = tmp.get_mut(i) {
            let digit = value % 10;
            *slot = b'0'.saturating_add(u8::try_from(digit).unwrap_or(0));
            i = i.saturating_add(1);
            value /= 10;
        } else {
            break;
        }
    }
    let mut o = off;
    while i > 0 {
        i = i.saturating_sub(1);
        if let (Some(slot), Some(&d)) = (buf.get_mut(o), tmp.get(i)) {
            *slot = d;
            o = o.saturating_add(1);
        }
    }
    o
}
