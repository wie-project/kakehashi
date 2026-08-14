//! Minimal pthread: park mutex/cond + real workers via `bsdthread_*`.
//!
//! Soft `pthread_create` → `EAGAIN` plus immediate `pthread_cond_wait` caused
//! pure-userspace hangs in multi-thread guests (`7zz a`): main waited forever
//! for workers that never ran. We register a freestanding trampoline, spawn
//! host-backed guest threads through the runtime, and join on a done flag.
//!
//! **Join protocol (must stay in sync with `kh-runtime::thread`):**
//! 1. Guest trampoline stores `result`, then `bsdthread_terminate`.
//! 2. Host leaves the guest stack, then sets `done` + futex-wakes joiners.
//! 3. `pthread_join` waits for `done`, then reclaims stack/control.
//!
//! Publishing `done` from the guest *before* terminate races with join's
//! `munmap` of the worker stack while hypercall dispatch still runs on it.

use core::ffi::{c_char, c_int, c_void};
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};

use crate::kh_core::errno;
use crate::kh_core::heap::{free, malloc};
use crate::kh_core::sys::{
    self, SYS_BSDTHREAD_CREATE, SYS_BSDTHREAD_REGISTER, SYS_BSDTHREAD_TERMINATE, SYS_MMAP,
    SYS_MUNMAP,
};
use crate::kh_core::trace;
use crate::{KH_HELPER_MAIN_STACK, KH_HELPER_PARK, KH_HELPER_WAKE};

const EAGAIN: i32 = 35;
const EINVAL: i32 = 22;
const ENOMEM: i32 = 12;

/// Shared with `kh-runtime::thread` (host publishes `done` after stack switch).
const MAGIC: u64 = 0x4B48_5054_4852_4401; // "KHPTHRD\x01"
/// Guest TLS magic — keep in sync with `kh-runtime::tls::GUEST_TLS_MAGIC`.
const TLS_MAGIC: u64 = 0x4B48_544C_5301; // "KHTLS\x01"
/// Guest worker stacks must fit freestanding NEON hypercall frames + host
/// dispatch + 7zz LZMA worker frames. 1 MiB was tight under `-mmt>1`.
const STACK_SIZE: usize = 4 * 1024 * 1024;
const PAGE: usize = 16_384;
const TLS_SIZE: usize = 64;

static REGISTERED: AtomicBool = AtomicBool::new(false);

/// Per-thread guest TLS block pointed to by `TPIDR_EL0`.
///
/// Layout ABI with `kh-runtime::tls` / `errno`:
/// `magic @ 0`, `errno @ 8`, `pthread_self @ 16`,
/// `host_tpidr @ 24` / `alt_top @ 32` (host-owned A1 mirrors; guest must not
/// treat them as ABI for freestanding logic),
/// `tsd_vals @ 40` (guest-owned; pointer to per-thread `pthread` TSD array).
///
/// Host only reads/writes offsets 0..40; freestanding owns `tsd_vals`.
#[repr(C, align(16))]
struct GuestTls {
    magic: u64,
    errno: i32,
    pad: u32,
    pthread_self: u64,
    /// Host-written; zero until `kh-runtime` publishes boundary.
    host_tpidr: u64,
    /// Host-written hypercall alt stack top.
    alt_top: u64,
    /// Heap array of [`MAX_KEYS`] `AtomicUsize` TSD values for this thread.
    /// Null until first `pthread_setspecific` / lazy ensure (main thread).
    tsd_vals: *mut AtomicUsize,
}

/// Control block pointed to by guest `pthread_t`.
///
/// Layout is an ABI with the host worker exit path (`kh-runtime::thread`):
/// `magic @ 0`, `done @ 8`, `detached @ 12`, `result @ 16`, stack fields,
/// then `tsd @ 56` (guest TPIDR base).
#[repr(C, align(16))]
struct KhThread {
    magic: u64,
    /// Set to 1 by the **host** after leaving the guest stack (not by the
    /// trampoline). Joiners park on this word via `KH_HELPER_PARK`.
    done: AtomicU32,
    detached: AtomicU32,
    result: AtomicUsize,
    stack: *mut u8,
    stack_size: usize,
    /// User start routine (kept for debugging).
    start_func: usize,
    start_arg: usize,
    /// Guest TLS base for `TPIDR_EL0` (host may install before jump).
    tsd: *mut GuestTls,
}

type StartFn = unsafe extern "C" fn(*mut c_void) -> *mut c_void;

/// Trampoline registered with `bsdthread_register`.
///
/// Runtime enters here with Darwin `_pthread_start` convention:
/// `x0=pthread`, `x1=port`, `x2=func`, `x3=arg`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn kh_pthread_start(
    pthread: *mut c_void,
    _port: u64,
    func: *mut c_void,
    arg: *mut c_void,
) {
    // Install guest TPIDR before any libSystem call that uses ___error / TSD.
    // Host runtime also installs this when KhThread.tsd is visible; idempotent.
    if !pthread.is_null() {
        let t = pthread.cast::<KhThread>();
        // SAFETY: control block from our pthread_create.
        unsafe {
            if (*t).magic == MAGIC {
                let tsd = (*t).tsd;
                if !tsd.is_null() {
                    let va = u64::try_from(tsd.addr()).unwrap_or(0);
                    if va != 0 {
                        write_tpidr_el0(va);
                    }
                }
            }
        }
    }

    let mut ret: *mut c_void = core::ptr::null_mut();
    if !func.is_null() {
        let f: StartFn = unsafe { core::mem::transmute(func) };
        ret = unsafe { f(arg) };
    }
    if !pthread.is_null() {
        let t = pthread.cast::<KhThread>();
        // SAFETY: our create allocated this block.
        // Store result only — `done` + joiner wake are published by the host
        // after `bsdthread_terminate` switches off this guest stack.
        unsafe {
            if (*t).magic == MAGIC {
                (*t).result.store(ret.addr(), Ordering::Release);
            }
        }
    }
    // End this host worker only (runtime: host stack → done/wake → pthread_exit).
    let _ = unsafe { sys::syscall6(SYS_BSDTHREAD_TERMINATE, 0, 0, 0, 0, 0, 0) };
    loop {
        core::hint::spin_loop();
    }
}

#[cfg(target_arch = "aarch64")]
#[inline]
fn write_tpidr_el0(val: u64) {
    // SAFETY: guest TLS block lives until join reclaims the thread.
    unsafe {
        core::arch::asm!(
            "msr tpidr_el0, {}",
            in(reg) val,
            options(nomem, nostack, preserves_flags),
        );
    }
}

#[cfg(not(target_arch = "aarch64"))]
#[inline]
fn write_tpidr_el0(_val: u64) {}

fn trampoline_va() -> u64 {
    // Function-item → code address for `bsdthread_register`.
    // rustc requires `fn-item as *const () as usize` (no freestanding alternative).
    #[allow(
        unknown_lints,
        clippy::as_conversions,
        clippy::fn_to_numeric_cast_with_truncation,
        function_casts_as_integer
    )]
    let addr = kh_pthread_start as *const () as usize;
    u64::try_from(addr).unwrap_or(0)
}

fn ensure_registered() -> bool {
    if REGISTERED.load(Ordering::Acquire) {
        return true;
    }
    let entry = trampoline_va();
    if entry == 0 {
        return false;
    }
    // bsdthread_register(threadstart, wqthread, flags, stack_hint,
    //                    targetconc, dispatchqueue_offset, tsd_offset)
    let ret = unsafe { sys::syscall7(SYS_BSDTHREAD_REGISTER, entry, 0, 0, 0, 0, 0, 0) };
    if ret < 0 {
        trace::note(b"[kh-libsystem] bsdthread_register failed\n");
        return false;
    }
    REGISTERED.store(true, Ordering::Release);
    true
}

fn mmap_anon(len: usize) -> *mut u8 {
    let mask = PAGE.saturating_sub(1);
    let total = len.saturating_add(mask) & !mask;
    let prot = 3_u64; // R|W
    let flags = 0x1000_u64 | 0x0002_u64; // ANON|PRIVATE
    let fd = !0_u64;
    let total_u = u64::try_from(total).unwrap_or(0);
    let ret = unsafe { sys::syscall6(SYS_MMAP, 0, total_u, prot, flags, fd, 0) };
    if ret < 0 {
        return core::ptr::null_mut();
    }
    let addr = usize::try_from(ret).unwrap_or(0);
    core::ptr::with_exposed_provenance_mut::<u8>(addr)
}

fn munmap_anon(ptr: *mut u8, len: usize) {
    if ptr.is_null() || len == 0 {
        return;
    }
    let mask = PAGE.saturating_sub(1);
    let total = len.saturating_add(mask) & !mask;
    let addr = u64::try_from(ptr.addr()).unwrap_or(0);
    let total_u = u64::try_from(total).unwrap_or(0);
    let _ = unsafe { sys::syscall2(SYS_MUNMAP, addr, total_u) };
}

// ── mutex (freestanding word inside guest pthread_mutex_t) ──────────────────
//
// Futex mutex states (Drepper / Linux classic):
//   0 = unlocked
//   1 = locked, no known waiters
//   2 = locked, waiters may exist → unlock must FUTEX_WAKE
//
// Uncontended unlock is store-only (no KH_HELPER_WAKE). Always-wake was the
// main residual futex storm after A1 (UTM 8k-file: ~257k futex, mostly guest).
//
// Layout: Darwin `pthread_mutex_t` stores signature `_PTHREAD_MUTEX_SIG_init`
// (`0x32AAABA7`) in the first word of static/in-place initializers (protobuf,
// libc++). Using that word as the futex state parks forever on the magic.
// Freestanding lock state lives at **offset +8** (still zero for BSS-zero
// mutexes that 7zz/curl rely on).

/// Unlocked.
const MUTEX_UNLOCKED: u32 = 0;
/// Locked, no known waiters — unlock without wake.
const MUTEX_LOCKED: u32 = 1;
/// Locked with waiters — unlock clears + wakes one.
const MUTEX_CONTENDED: u32 = 2;

/// Byte offset of freestanding lock word inside `pthread_mutex_t`.
const MUTEX_STATE_OFF: usize = 8;
/// Owner `pthread_self` token (0 = none). Enables same-thread re-entry so
/// LLVM `ManagedStatic` / nested `cl::opt` registration does not futex-deadlock
/// on a non-recursive freestanding mutex.
const MUTEX_OWNER_OFF: usize = 16;
/// Re-entry depth while `owner` is set.
const MUTEX_DEPTH_OFF: usize = 24;

/// Darwin `_PTHREAD_MUTEX_SIG_init` (public man / header value).
const DARWIN_MUTEX_SIG: u32 = 0x32AA_ABA7;

#[inline]
fn mutex_word(mutex: *mut c_void) -> *mut AtomicU32 {
    // SAFETY: Darwin mutex is ≥ 64 bytes and ≥ 8-byte aligned; +8 stays
    // 4-byte aligned for `AtomicU32`.
    let addr = mutex.addr().saturating_add(MUTEX_STATE_OFF);
    core::ptr::with_exposed_provenance_mut::<AtomicU32>(addr)
}

#[inline]
fn mutex_owner(mutex: *mut c_void) -> *mut AtomicU64 {
    let addr = mutex.addr().saturating_add(MUTEX_OWNER_OFF);
    core::ptr::with_exposed_provenance_mut::<AtomicU64>(addr)
}

#[inline]
fn mutex_depth(mutex: *mut c_void) -> *mut u32 {
    let addr = mutex.addr().saturating_add(MUTEX_DEPTH_OFF);
    core::ptr::with_exposed_provenance_mut::<u32>(addr)
}

#[inline]
fn self_token() -> u64 {
    // SAFETY: pthread_self is freestanding and always returns a stable token.
    let p = unsafe { pthread_self() };
    u64::try_from(p.addr()).unwrap_or(1)
}

#[inline]
fn park_word(word: *const AtomicU32, expected: u32) {
    let addr = u64::try_from(word.addr()).unwrap_or(0);
    let _ = unsafe { sys::helper2(KH_HELPER_PARK, addr, u64::from(expected)) };
}

#[inline]
fn wake_word(word: *const AtomicU32, n: u32) {
    let addr = u64::try_from(word.addr()).unwrap_or(0);
    let _ = unsafe { sys::helper2(KH_HELPER_WAKE, addr, u64::from(n)) };
}

/// Darwin `pthread_once_t` first word may be a non-zero init signature; we only
/// treat our own sentinels as terminal/in-progress.
const ONCE_DONE: u32 = 0x4B48_4F4E; // "KHON"
const ONCE_RUNNING: u32 = 0x4B48_5255; // "KHRU"

/// C `pthread_once` → nlist `_pthread_once` (curl G1 after `_fcntl`).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn pthread_once(
    once_control: *mut c_void,
    init_routine: Option<unsafe extern "C" fn()>,
) -> c_int {
    if once_control.is_null() {
        return EINVAL;
    }
    // First word of `pthread_once_t` (struct or scalar) is our control.
    let w = unsafe { &*once_control.cast::<AtomicU32>() };
    loop {
        let cur = w.load(Ordering::Acquire);
        if cur == ONCE_DONE {
            return 0;
        }
        if cur == ONCE_RUNNING {
            park_word(w, ONCE_RUNNING);
            continue;
        }
        // Claim: any other value (incl. Darwin `PTHREAD_ONCE_INIT` magic) → running.
        if w.compare_exchange(cur, ONCE_RUNNING, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            if let Some(init) = init_routine {
                // SAFETY: caller registered a valid init routine for this once.
                unsafe {
                    init();
                }
            }
            w.store(ONCE_DONE, Ordering::Release);
            wake_word(w, u32::MAX);
            return 0;
        }
    }
}

// ── rwlock (minimal; curl G1 after pthread_once) ────────────────────────────
// Layout: word0 = writer/state, word1 = reader count (u32 each).
// 0 = free for writers; readers use word1 with word0==0.

const RW_FREE: u32 = 0;
const RW_WRITE: u32 = 1;

#[inline]
fn rw_state(rwlock: *mut c_void) -> *mut AtomicU32 {
    rwlock.cast::<AtomicU32>()
}

#[inline]
fn rw_readers(rwlock: *mut c_void) -> *mut AtomicU32 {
    // SAFETY: Darwin pthread_rwlock_t is large enough for two u32 words.
    unsafe { rwlock.cast::<AtomicU32>().add(1) }
}

/// C `pthread_rwlock_init` → nlist `_pthread_rwlock_init`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn pthread_rwlock_init(
    rwlock: *mut c_void,
    _attr: *const c_void,
) -> c_int {
    if rwlock.is_null() {
        return EINVAL;
    }
    unsafe {
        (*rw_state(rwlock)).store(RW_FREE, Ordering::Relaxed);
        (*rw_readers(rwlock)).store(0, Ordering::Relaxed);
    }
    0
}

/// C `pthread_rwlock_destroy` → nlist `_pthread_rwlock_destroy`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn pthread_rwlock_destroy(rwlock: *mut c_void) -> c_int {
    if rwlock.is_null() {
        return EINVAL;
    }
    unsafe {
        (*rw_state(rwlock)).store(RW_FREE, Ordering::Relaxed);
        (*rw_readers(rwlock)).store(0, Ordering::Relaxed);
    }
    0
}

/// C `pthread_rwlock_rdlock` → nlist `_pthread_rwlock_rdlock`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn pthread_rwlock_rdlock(rwlock: *mut c_void) -> c_int {
    if rwlock.is_null() {
        return EINVAL;
    }
    let st = unsafe { &*rw_state(rwlock) };
    let rc = unsafe { &*rw_readers(rwlock) };
    loop {
        // Wait while a writer holds the lock.
        while st.load(Ordering::Acquire) != RW_FREE {
            park_word(st, RW_WRITE);
        }
        rc.fetch_add(1, Ordering::AcqRel);
        // Recheck: writer may have sneaked in.
        if st.load(Ordering::Acquire) == RW_FREE {
            return 0;
        }
        rc.fetch_sub(1, Ordering::AcqRel);
        wake_word(st, u32::MAX);
    }
}

/// C `pthread_rwlock_wrlock` → nlist `_pthread_rwlock_wrlock`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn pthread_rwlock_wrlock(rwlock: *mut c_void) -> c_int {
    if rwlock.is_null() {
        return EINVAL;
    }
    let st = unsafe { &*rw_state(rwlock) };
    let rc = unsafe { &*rw_readers(rwlock) };
    loop {
        if st
            .compare_exchange(RW_FREE, RW_WRITE, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            // Wait for existing readers to drain.
            while rc.load(Ordering::Acquire) != 0 {
                core::hint::spin_loop();
            }
            return 0;
        }
        park_word(st, RW_WRITE);
    }
}

/// C `pthread_rwlock_unlock` → nlist `_pthread_rwlock_unlock`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn pthread_rwlock_unlock(rwlock: *mut c_void) -> c_int {
    if rwlock.is_null() {
        return EINVAL;
    }
    let st = unsafe { &*rw_state(rwlock) };
    let rc = unsafe { &*rw_readers(rwlock) };
    if st.load(Ordering::Acquire) == RW_WRITE {
        st.store(RW_FREE, Ordering::Release);
        wake_word(st, u32::MAX);
        return 0;
    }
    // Reader unlock.
    let prev = rc.fetch_sub(1, Ordering::AcqRel);
    if prev == 1 {
        wake_word(st, u32::MAX);
    }
    0
}

/// C `pthread_mutex_init` → nlist `_pthread_mutex_init`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn pthread_mutex_init(
    mutex: *mut c_void,
    _attr: *const c_void,
) -> c_int {
    if mutex.is_null() {
        return EINVAL;
    }
    unsafe {
        // Optional Darwin-shaped sig so guests that probe it see a normal mutex.
        mutex.cast::<u32>().write(DARWIN_MUTEX_SIG);
        (*mutex_word(mutex)).store(MUTEX_UNLOCKED, Ordering::Relaxed);
        (*mutex_owner(mutex)).store(0, Ordering::Relaxed);
        mutex_depth(mutex).write(0);
    }
    0
}

/// C `pthread_mutex_destroy` → nlist `_pthread_mutex_destroy`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn pthread_mutex_destroy(mutex: *mut c_void) -> c_int {
    if mutex.is_null() {
        return EINVAL;
    }
    unsafe {
        (*mutex_word(mutex)).store(MUTEX_UNLOCKED, Ordering::Relaxed);
        (*mutex_owner(mutex)).store(0, Ordering::Relaxed);
        mutex_depth(mutex).write(0);
    }
    0
}

/// C `pthread_mutexattr_init` → nlist `_pthread_mutexattr_init` (curl G3).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn pthread_mutexattr_init(attr: *mut c_void) -> c_int {
    if attr.is_null() {
        return EINVAL;
    }
    // Opaque attr: zero first word (default type).
    unsafe {
        attr.cast::<u32>().write(0);
    }
    0
}

/// C `pthread_mutexattr_destroy`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn pthread_mutexattr_destroy(attr: *mut c_void) -> c_int {
    if attr.is_null() {
        return EINVAL;
    }
    0
}

/// C `pthread_mutexattr_settype` (PTHREAD_MUTEX_NORMAL=0, ERRORCHECK=1, RECURSIVE=2).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn pthread_mutexattr_settype(
    attr: *mut c_void,
    type_: c_int,
) -> c_int {
    if attr.is_null() {
        return EINVAL;
    }
    // Soft-accept; freestanding mutex is non-recursive. Store for debugging.
    unsafe {
        attr.cast::<u32>().write(type_.cast_unsigned());
    }
    0
}

/// C `pthread_mutex_trylock`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn pthread_mutex_trylock(mutex: *mut c_void) -> c_int {
    if mutex.is_null() {
        return EINVAL;
    }
    let me = self_token();
    let owner = unsafe { &*mutex_owner(mutex) };
    if owner.load(Ordering::Relaxed) == me {
        unsafe {
            let d = mutex_depth(mutex);
            d.write(d.read().saturating_add(1));
        }
        return 0;
    }
    let w = unsafe { &*mutex_word(mutex) };
    if w.compare_exchange(
        MUTEX_UNLOCKED,
        MUTEX_LOCKED,
        Ordering::Acquire,
        Ordering::Relaxed,
    )
    .is_ok()
    {
        owner.store(me, Ordering::Relaxed);
        unsafe {
            mutex_depth(mutex).write(1);
        }
        0
    } else {
        // Darwin EBUSY
        16
    }
}

/// C `pthread_mutex_lock` → nlist `_pthread_mutex_lock`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn pthread_mutex_lock(mutex: *mut c_void) -> c_int {
    if mutex.is_null() {
        return EINVAL;
    }
    let me = self_token();
    let owner = unsafe { &*mutex_owner(mutex) };
    // Same-thread re-entry (LLVM ManagedStatic / nested option registration).
    if owner.load(Ordering::Relaxed) == me {
        unsafe {
            let d = mutex_depth(mutex);
            d.write(d.read().saturating_add(1));
        }
        return 0;
    }

    let w = unsafe { &*mutex_word(mutex) };

    // Fast path: uncontended.
    if w.compare_exchange(
        MUTEX_UNLOCKED,
        MUTEX_LOCKED,
        Ordering::Acquire,
        Ordering::Relaxed,
    )
    .is_ok()
    {
        owner.store(me, Ordering::Relaxed);
        unsafe {
            mutex_depth(mutex).write(1);
        }
        return 0;
    }

    // Slow path: short spin, then mark contended and park (F1).
    loop {
        // Re-check owner after another thread may have released.
        if owner.load(Ordering::Relaxed) == me {
            unsafe {
                let d = mutex_depth(mutex);
                d.write(d.read().saturating_add(1));
            }
            return 0;
        }
        for _ in 0..64_u32 {
            let cur = w.load(Ordering::Relaxed);
            if cur == MUTEX_UNLOCKED {
                if w.compare_exchange(
                    MUTEX_UNLOCKED,
                    MUTEX_LOCKED,
                    Ordering::Acquire,
                    Ordering::Relaxed,
                )
                .is_ok()
                {
                    owner.store(me, Ordering::Relaxed);
                    unsafe {
                        mutex_depth(mutex).write(1);
                    }
                    return 0;
                }
            } else if cur == MUTEX_LOCKED {
                // Advertise waiters so unlock issues FUTEX_WAKE.
                let _ = w.compare_exchange(
                    MUTEX_LOCKED,
                    MUTEX_CONTENDED,
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                );
            }
            core::hint::spin_loop();
        }

        // Before park: own it as CONTENDED if free, else ensure CONTENDED and wait.
        // swap(2): if prev==0 we acquired; if prev!=0 someone still holds → park.
        let prev = w.swap(MUTEX_CONTENDED, Ordering::Acquire);
        if prev == MUTEX_UNLOCKED {
            owner.store(me, Ordering::Relaxed);
            unsafe {
                mutex_depth(mutex).write(1);
            }
            return 0;
        }
        // FUTEX_WAIT returns if value ≠ expected (unlock raced ahead → 0).
        park_word(w, MUTEX_CONTENDED);
    }
}

/// C `pthread_mutex_unlock` → nlist `_pthread_mutex_unlock`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn pthread_mutex_unlock(mutex: *mut c_void) -> c_int {
    if mutex.is_null() {
        return EINVAL;
    }
    let me = self_token();
    let owner = unsafe { &*mutex_owner(mutex) };
    if owner.load(Ordering::Relaxed) == me {
        let d = mutex_depth(mutex);
        // SAFETY: mutex object is live guest storage ≥ 64 bytes.
        let depth = unsafe { d.read() };
        if depth > 1 {
            unsafe {
                d.write(depth.saturating_sub(1));
            }
            return 0;
        }
        unsafe {
            d.write(0);
        }
        owner.store(0, Ordering::Release);
    }
    let w = unsafe { &*mutex_word(mutex) };
    // Swap to 0 (not fetch_sub): avoids a transient LOCKED(1) window after
    // CONTENDED that can strand waiters under zip multi-thread compress.
    // Uncontended LOCKED → no wake; CONTENDED → wake all waiters (zip MT
    // can have several threads on the same mutex after a cond broadcast).
    let prev = w.swap(MUTEX_UNLOCKED, Ordering::Release);
    if prev == MUTEX_CONTENDED {
        wake_word(w, u32::MAX);
    }
    0
}

// ── cond (generation + waiter count) ────────────────────────────────────────
//
// Layout inside opaque `pthread_cond_t` (Darwin ≥ 40 B opaque; we use 8 B):
//   word0 @0: generation (futex wait word)
//   word1 @4: nwaiters (diagnostic / optional wake elision)
//
// Always bump generation. Wake is **not** elided on nwaiters==0: zip MT
// (`7zz a -tzip -mmt≥3`) deadlocked when a notify raced a waiter that had not
// yet published nwaiters (and related heap-lock inversion amplified it).

#[inline]
fn cond_gen(cond: *mut c_void) -> *mut AtomicU32 {
    cond.cast::<AtomicU32>()
}

#[inline]
fn cond_waiters(cond: *mut c_void) -> *mut AtomicU32 {
    // SAFETY: caller ensures non-null cond; +4 within opaque pthread_cond_t.
    unsafe { cond.cast::<AtomicU32>().add(1) }
}

/// C `pthread_cond_init` → nlist `_pthread_cond_init`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn pthread_cond_init(
    cond: *mut c_void,
    _attr: *const c_void,
) -> c_int {
    if cond.is_null() {
        return EINVAL;
    }
    unsafe {
        (*cond_gen(cond)).store(0, Ordering::Relaxed);
        (*cond_waiters(cond)).store(0, Ordering::Relaxed);
    }
    0
}

/// C `pthread_cond_destroy` → nlist `_pthread_cond_destroy`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn pthread_cond_destroy(cond: *mut c_void) -> c_int {
    if cond.is_null() {
        return EINVAL;
    }
    0
}

/// C `pthread_cond_wait` → nlist `_pthread_cond_wait`.
///
/// Generation wait via host futex park (not yield-spin).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn pthread_cond_wait(cond: *mut c_void, mutex: *mut c_void) -> c_int {
    if cond.is_null() || mutex.is_null() {
        return EINVAL;
    }
    let generation = unsafe { &*cond_gen(cond) };
    let waiters = unsafe { &*cond_waiters(cond) };
    // Advertise waiters *before* sampling generation so a concurrent notify
    // that still elides (older dylibs) is less likely to race; we always wake
    // now, but ordering still matters for the generation snapshot.
    waiters.fetch_add(1, Ordering::AcqRel);
    let snapshot = generation.load(Ordering::Acquire);
    let _ = unsafe { pthread_mutex_unlock(mutex) };
    while generation.load(Ordering::Acquire) == snapshot {
        park_word(generation, snapshot);
    }
    waiters.fetch_sub(1, Ordering::AcqRel);
    let _ = unsafe { pthread_mutex_lock(mutex) };
    0
}

fn timespec_now_ns() -> Option<i64> {
    // Darwin timeval via gettimeofday: sec i64 + usec i32 + pad.
    let mut tv = [0_u8; 16];
    let ret = unsafe {
        sys::syscall2(
            crate::kh_core::sys::SYS_GETTIMEOFDAY,
            u64::try_from(tv.as_mut_ptr().addr()).unwrap_or(0),
            0,
        )
    };
    if ret < 0 {
        return None;
    }
    let sec = i64::from_le_bytes([tv[0], tv[1], tv[2], tv[3], tv[4], tv[5], tv[6], tv[7]]);
    let usec = i32::from_le_bytes([tv[8], tv[9], tv[10], tv[11]]);
    Some(
        sec.saturating_mul(1_000_000_000)
            .saturating_add(i64::from(usec).saturating_mul(1000)),
    )
}

fn abstime_ns(abstime: *const c_void) -> Option<i64> {
    if abstime.is_null() {
        return None;
    }
    // Darwin timespec: tv_sec i64 + tv_nsec i64 on arm64.
    let p = abstime.cast::<i64>();
    let sec = unsafe { p.read() };
    let nsec = unsafe { p.add(1).read() };
    Some(sec.saturating_mul(1_000_000_000).saturating_add(nsec))
}

/// C `pthread_cond_timedwait` (absolute `timespec`; curl G3).
///
/// Host park has no timeout, so we unlock, yield-poll generation until signal
/// or deadline, then re-lock. Returns Darwin `ETIMEDOUT` (60) on timeout.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn pthread_cond_timedwait(
    cond: *mut c_void,
    mutex: *mut c_void,
    abstime: *const c_void,
) -> c_int {
    if cond.is_null() || mutex.is_null() || abstime.is_null() {
        return EINVAL;
    }
    let Some(deadline) = abstime_ns(abstime) else {
        return EINVAL;
    };
    let generation = unsafe { &*cond_gen(cond) };
    let waiters = unsafe { &*cond_waiters(cond) };
    waiters.fetch_add(1, Ordering::AcqRel);
    let snapshot = generation.load(Ordering::Acquire);
    let _ = unsafe { pthread_mutex_unlock(mutex) };

    let mut timed_out = false;
    while generation.load(Ordering::Acquire) == snapshot {
        if let Some(now) = timespec_now_ns()
            && now >= deadline
        {
            timed_out = true;
            break;
        }
        // Brief yield so multi-thread notify can run; avoid infinite park.
        let _ = unsafe { sys::helper0(crate::kh_core::helpers::KH_HELPER_YIELD) };
        core::hint::spin_loop();
    }

    waiters.fetch_sub(1, Ordering::AcqRel);
    let _ = unsafe { pthread_mutex_lock(mutex) };
    if timed_out && generation.load(Ordering::Acquire) == snapshot {
        60 // ETIMEDOUT
    } else {
        0
    }
}

/// Bump generation and always futex-wake (wake_n waiters).
#[inline]
fn cond_notify(cond: *mut c_void, wake_n: u32) {
    let generation = unsafe { &*cond_gen(cond) };
    let _ = generation.fetch_add(1, Ordering::Release);
    // Always wake: eliding on nwaiters==0 lost wakeups under zip -mmt≥3.
    wake_word(generation, wake_n);
}

/// C `pthread_cond_broadcast` → nlist `_pthread_cond_broadcast`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn pthread_cond_broadcast(cond: *mut c_void) -> c_int {
    if cond.is_null() {
        return EINVAL;
    }
    cond_notify(cond, u32::MAX);
    0
}

/// C `pthread_cond_signal` → nlist `_pthread_cond_signal` (wake **one**).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn pthread_cond_signal(cond: *mut c_void) -> c_int {
    if cond.is_null() {
        return EINVAL;
    }
    cond_notify(cond, 1);
    0
}

// ── TSD / self ──────────────────────────────────────────────────────────────
//
// Keys are process-wide; **values are per-thread** (Darwin / POSIX). A single
// process-global value table races under curl's DNS thread pool + OpenSSL and
// produced intermittent guest SIGSEGV in `_async_thrdd_item_process` (bad
// `thrdq_item.item`, often shaped `(aslr_tag << 32) | 0xb`).

const MAX_KEYS: usize = 64;
/// Next key id (1..=MAX_KEYS). Key 0 is invalid / deleted.
static NEXT_KEY: AtomicUsize = AtomicUsize::new(1);
static KEY_LIVE: [AtomicBool; MAX_KEYS] = [const { AtomicBool::new(false) }; MAX_KEYS];
/// Fallback when guest TLS is missing (early boot / no TPIDR). Not used once
/// each thread has `GuestTls.tsd_vals`.
static TSD_FALLBACK: [AtomicUsize; MAX_KEYS] = [const { AtomicUsize::new(0) }; MAX_KEYS];

#[inline]
fn tsd_array_bytes() -> usize {
    core::mem::size_of::<AtomicUsize>().saturating_mul(MAX_KEYS)
}

/// Allocate and zero a per-thread TSD value array.
fn alloc_tsd_array() -> *mut AtomicUsize {
    let n = tsd_array_bytes();
    let raw = unsafe { malloc(n) };
    if raw.is_null() {
        return core::ptr::null_mut();
    }
    unsafe {
        crate::dylib::libsystem_c::stdio::bzero(raw, n);
    }
    raw.cast::<AtomicUsize>()
}

#[inline]
fn free_tsd_array(p: *mut AtomicUsize) {
    if !p.is_null() {
        unsafe {
            free(p.cast::<c_void>());
        }
    }
}

/// Current thread's `GuestTls`, or null if TPIDR unset / magic mismatch.
fn current_guest_tls() -> *mut GuestTls {
    #[cfg(target_arch = "aarch64")]
    {
        let tpidr: u64;
        // SAFETY: pure register read.
        unsafe {
            core::arch::asm!(
                "mrs {}, tpidr_el0",
                out(reg) tpidr,
                options(nomem, nostack, preserves_flags),
            );
        }
        if tpidr == 0 {
            return core::ptr::null_mut();
        }
        let base = usize::try_from(tpidr).unwrap_or(0);
        if base == 0 {
            return core::ptr::null_mut();
        }
        let tls = core::ptr::with_exposed_provenance_mut::<GuestTls>(base);
        // SAFETY: identity-mapped guest TLS when magic matches.
        let magic = unsafe { core::ptr::read_volatile(core::ptr::addr_of!((*tls).magic)) };
        if magic != TLS_MAGIC {
            return core::ptr::null_mut();
        }
        tls
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        core::ptr::null_mut()
    }
}

/// Ensure this thread has a TSD value array; returns base or null on OOM / no TLS.
fn ensure_thread_tsd_vals() -> *mut AtomicUsize {
    let tls = current_guest_tls();
    if tls.is_null() {
        return core::ptr::null_mut();
    }
    // SAFETY: magic-checked GuestTls for this thread only.
    let existing = unsafe { (*tls).tsd_vals };
    if !existing.is_null() {
        return existing;
    }
    let fresh = alloc_tsd_array();
    if fresh.is_null() {
        return core::ptr::null_mut();
    }
    // Only this thread writes tsd_vals; no atomic needed.
    unsafe {
        (*tls).tsd_vals = fresh;
    }
    fresh
}

#[inline]
fn tsd_value_slot(idx: usize) -> Option<&'static AtomicUsize> {
    if idx >= MAX_KEYS {
        return None;
    }
    let base = ensure_thread_tsd_vals();
    if !base.is_null() {
        // SAFETY: array of MAX_KEYS; idx checked; lives until thread join.
        return Some(unsafe { &*base.add(idx) });
    }
    TSD_FALLBACK.get(idx)
}

/// C `pthread_key_create` → nlist `_pthread_key_create`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn pthread_key_create(
    key: *mut c_int,
    _destructor: Option<unsafe extern "C" fn(*mut c_void)>,
) -> c_int {
    if key.is_null() {
        return EINVAL;
    }
    for _ in 0..MAX_KEYS {
        let id = NEXT_KEY.fetch_add(1, Ordering::Relaxed);
        if id == 0 || id > MAX_KEYS {
            NEXT_KEY.store(1, Ordering::Relaxed);
            continue;
        }
        let idx = id.saturating_sub(1);
        if let Some(slot) = KEY_LIVE.get(idx)
            && slot
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
        {
            // Clear fallback slot; per-thread arrays start zeroed on alloc.
            if let Some(v) = TSD_FALLBACK.get(idx) {
                v.store(0, Ordering::Relaxed);
            }
            // SAFETY: caller provided writable key out-param.
            unsafe {
                *key = c_int::try_from(id).unwrap_or(0);
            }
            return 0;
        }
    }
    EAGAIN
}

/// C `pthread_key_delete` → nlist `_pthread_key_delete`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn pthread_key_delete(key: c_int) -> c_int {
    let id = usize::try_from(key).unwrap_or(0);
    if id == 0 || id > MAX_KEYS {
        return EINVAL;
    }
    let idx = id.saturating_sub(1);
    if let Some(slot) = KEY_LIVE.get(idx) {
        slot.store(false, Ordering::Release);
    }
    if let Some(v) = TSD_FALLBACK.get(idx) {
        v.store(0, Ordering::Relaxed);
    }
    // Per-thread slots for this key are left as-is; next create reuses the
    // key id only after live=false, and getspecific rejects dead keys.
    0
}

/// C `pthread_getspecific` → nlist `_pthread_getspecific`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn pthread_getspecific(key: c_int) -> *mut c_void {
    let id = usize::try_from(key).unwrap_or(0);
    if id == 0 || id > MAX_KEYS {
        return core::ptr::null_mut();
    }
    let idx = id.saturating_sub(1);
    if !KEY_LIVE.get(idx).is_some_and(|s| s.load(Ordering::Acquire)) {
        return core::ptr::null_mut();
    }
    let val = tsd_value_slot(idx).map_or(0, |v| v.load(Ordering::Acquire));
    core::ptr::with_exposed_provenance_mut(val)
}

/// C `pthread_setspecific` → nlist `_pthread_setspecific`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn pthread_setspecific(key: c_int, value: *const c_void) -> c_int {
    let id = usize::try_from(key).unwrap_or(0);
    if id == 0 || id > MAX_KEYS {
        return EINVAL;
    }
    let idx = id.saturating_sub(1);
    if !KEY_LIVE.get(idx).is_some_and(|s| s.load(Ordering::Acquire)) {
        return EINVAL;
    }
    let Some(slot) = tsd_value_slot(idx) else {
        return ENOMEM;
    };
    slot.store(value.addr(), Ordering::Release);
    0
}

/// Stable non-null main-thread token when TLS `pthread_self` is not set.
static MAIN_SELF: u64 = 0x4B48_5054_5345_4C46; // "KHPSELF"

/// C `pthread_self` → nlist `_pthread_self`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn pthread_self() -> *mut c_void {
    // Prefer GuestTls.pthread_self when TPIDR is installed.
    let tpidr: u64;
    // SAFETY: read TPIDR_EL0 (guest TLS base on our path).
    unsafe {
        core::arch::asm!("mrs {}, tpidr_el0", out(reg) tpidr, options(nomem, nostack, preserves_flags));
    }
    if tpidr != 0 {
        let tls =
            core::ptr::with_exposed_provenance::<GuestTls>(usize::try_from(tpidr).unwrap_or(0));
        // SAFETY: main TLS page / worker TLS installed by runtime has magic.
        let magic = unsafe { core::ptr::read_volatile(core::ptr::addr_of!((*tls).magic)) };
        if magic == TLS_MAGIC {
            let self_va =
                unsafe { core::ptr::read_volatile(core::ptr::addr_of!((*tls).pthread_self)) };
            if self_va != 0 {
                return core::ptr::with_exposed_provenance_mut(
                    usize::try_from(self_va).unwrap_or(0),
                );
            }
        }
    }
    core::ptr::from_ref(&MAIN_SELF).cast_mut().cast()
}

/// C `pthread_equal` → nlist `_pthread_equal`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn pthread_equal(t1: *mut c_void, t2: *mut c_void) -> c_int {
    i32::from(t1 == t2)
}

/// C `pthread_setcancelstate` → nlist `_pthread_setcancelstate` (soft; no cancel).
///
/// Apple `git` `start_command` brackets `fork` with this. A missing import is
/// bound to a noreturn trampoline and aborts the guest; always succeed.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn pthread_setcancelstate(
    _state: c_int,
    oldstate: *mut c_int,
) -> c_int {
    if !oldstate.is_null() {
        // PTHREAD_CANCEL_ENABLE == 0 on Darwin.
        // SAFETY: optional out-param from guest.
        unsafe {
            oldstate.write(0);
        }
    }
    0
}

/// C `pthread_setcanceltype` → nlist `_pthread_setcanceltype` (soft).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn pthread_setcanceltype(_type_: c_int, oldtype: *mut c_int) -> c_int {
    if !oldtype.is_null() {
        // SAFETY: optional out-param from guest.
        unsafe {
            oldtype.write(0);
        }
    }
    0
}

/// C `pthread_exit` → nlist `_pthread_exit` (main: process exit).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn pthread_exit(retval: *mut c_void) -> ! {
    let _ = retval;
    // SAFETY: never returns.
    unsafe {
        crate::kh_core::process::exit_now(0);
    }
}

// ── attrs ───────────────────────────────────────────────────────────────────

/// C `pthread_attr_init` → nlist `_pthread_attr_init`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn pthread_attr_init(_attr: *mut c_void) -> c_int {
    0
}

/// C `pthread_attr_destroy` → nlist `_pthread_attr_destroy`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn pthread_attr_destroy(_attr: *mut c_void) -> c_int {
    0
}

/// C `pthread_attr_setdetachstate` → nlist `_pthread_attr_setdetachstate`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn pthread_attr_setdetachstate(
    _attr: *mut c_void,
    _state: c_int,
) -> c_int {
    0
}

// Fallback main-stack slab when the runtime has not published the real stack
// (unit tests / not-yet-wired helper). Addr is the **top** (Darwin convention).
const SOFT_STACK_SIZE: usize = 8 * 1024 * 1024;
#[repr(C, align(16))]
struct SoftStack([u8; SOFT_STACK_SIZE]);
static mut SOFT_STACK: SoftStack = SoftStack([0; SOFT_STACK_SIZE]);

#[repr(C)]
struct MainStackInfo {
    top: u64,
    size: u64,
}

fn published_main_stack() -> Option<(usize, usize)> {
    let mut info = MainStackInfo { top: 0, size: 0 };
    let va = u64::try_from(core::ptr::from_mut(&mut info).addr()).unwrap_or(0);
    let rc = unsafe { sys::helper1(KH_HELPER_MAIN_STACK, va) };
    if rc <= 0 || info.top == 0 || info.size == 0 {
        return None;
    }
    let top = usize::try_from(info.top).ok()?;
    let size = usize::try_from(info.size).ok()?;
    Some((top, size))
}

fn worker_stack(thread: *mut c_void) -> Option<(*mut u8, usize)> {
    if thread.is_null() {
        return None;
    }
    // Main-thread token is a u64, not a KhThread.
    if core::ptr::eq(thread.cast::<u64>(), core::ptr::addr_of!(MAIN_SELF)) {
        return None;
    }
    let t = thread.cast::<KhThread>();
    // SAFETY: only dereference when magic matches our create block.
    unsafe {
        if (*t).magic != MAGIC || (*t).stack.is_null() || (*t).stack_size == 0 {
            return None;
        }
        Some(((*t).stack, (*t).stack_size))
    }
}

fn stack_top_size(thread: *mut c_void) -> (*mut c_void, usize) {
    if let Some((base, size)) = worker_stack(thread) {
        return (unsafe { base.add(size).cast() }, size);
    }
    if let Some((top, size)) = published_main_stack() {
        return (core::ptr::with_exposed_provenance_mut::<u8>(top).cast(), size);
    }
    // SAFETY: static SoftStack fallback; only used when helper is unset.
    let base = unsafe { core::ptr::addr_of_mut!(SOFT_STACK.0).cast::<u8>() };
    (unsafe { base.add(SOFT_STACK_SIZE).cast() }, SOFT_STACK_SIZE)
}

/// C `pthread_get_stackaddr_np` → nlist `_pthread_get_stackaddr_np`.
///
/// Returns the high address of the thread stack (grows down).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn pthread_get_stackaddr_np(thread: *mut c_void) -> *mut c_void {
    stack_top_size(thread).0
}

/// C `pthread_get_stacksize_np` → nlist `_pthread_get_stacksize_np`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn pthread_get_stacksize_np(thread: *mut c_void) -> usize {
    stack_top_size(thread).1
}

/// Darwin `pthread_setname_np` (current thread only) → nlist `_pthread_setname_np`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn pthread_setname_np(_name: *const c_char) -> c_int {
    0
}

/// Darwin `pthread_threadid_np` → nlist `_pthread_threadid_np`.
///
/// ```c
/// int pthread_threadid_np(pthread_t thread, uint64_t *thread_id);
/// ```
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn pthread_threadid_np(
    thread: *mut c_void,
    thread_id: *mut u64,
) -> c_int {
    if thread_id.is_null() {
        return EINVAL;
    }
    let id = if thread.is_null() {
        1_u64 // main
    } else {
        u64::try_from(thread.addr()).unwrap_or(1)
    };
    // SAFETY: guest out-param.
    unsafe {
        thread_id.write(id);
    }
    0
}

// ── create / join / detach ──────────────────────────────────────────────────

/// C `pthread_create` → nlist `_pthread_create`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn pthread_create(
    thread: *mut c_void,
    _attr: *const c_void,
    start: *mut c_void,
    arg: *mut c_void,
) -> c_int {
    if thread.is_null() || start.is_null() {
        return EINVAL;
    }
    if !ensure_registered() {
        return EAGAIN;
    }

    let stack = mmap_anon(STACK_SIZE);
    if stack.is_null() {
        errno::set_errno(ENOMEM);
        return EAGAIN;
    }

    let raw = unsafe { malloc(core::mem::size_of::<KhThread>()) };
    if raw.is_null() {
        munmap_anon(stack, STACK_SIZE);
        return EAGAIN;
    }
    let tsd_raw = unsafe { malloc(core::mem::size_of::<GuestTls>().max(TLS_SIZE)) };
    if tsd_raw.is_null() {
        unsafe {
            free(raw);
        }
        munmap_anon(stack, STACK_SIZE);
        return EAGAIN;
    }
    let tsd_vals = alloc_tsd_array();
    if tsd_vals.is_null() {
        unsafe {
            free(tsd_raw);
            free(raw);
        }
        munmap_anon(stack, STACK_SIZE);
        return EAGAIN;
    }
    let tsd = tsd_raw.cast::<GuestTls>();
    let t = raw.cast::<KhThread>();
    let pthread_va = u64::try_from(raw.addr()).unwrap_or(0);
    unsafe {
        (*tsd).magic = TLS_MAGIC;
        (*tsd).errno = 0;
        (*tsd).pad = 0;
        (*tsd).pthread_self = pthread_va;
        (*tsd).host_tpidr = 0;
        (*tsd).alt_top = 0;
        (*tsd).tsd_vals = tsd_vals;

        (*t).magic = MAGIC;
        (*t).done = AtomicU32::new(0);
        (*t).detached = AtomicU32::new(0);
        (*t).result = AtomicUsize::new(0);
        (*t).stack = stack;
        (*t).stack_size = STACK_SIZE;
        (*t).start_func = start.addr();
        (*t).start_arg = arg.addr();
        (*t).tsd = tsd;
    }

    // Stack grows down: pass high address (16-byte aligned).
    let stack_top = stack.addr().saturating_add(STACK_SIZE) & !0xF_usize;
    let func_va = u64::try_from(start.addr()).unwrap_or(0);
    let arg_va = u64::try_from(arg.addr()).unwrap_or(0);
    let stack_va = u64::try_from(stack_top).unwrap_or(0);

    // bsdthread_create(func, func_arg, stack, pthread, flags)
    let ret = unsafe {
        sys::syscall6(
            SYS_BSDTHREAD_CREATE,
            func_va,
            arg_va,
            stack_va,
            pthread_va,
            0,
            0,
        )
    };
    if ret < 0 {
        trace::note(b"[kh-libsystem] bsdthread_create failed\n");
        free_tsd_array(tsd_vals);
        unsafe {
            free(tsd_raw);
            free(raw);
        }
        munmap_anon(stack, STACK_SIZE);
        return EAGAIN;
    }

    // *thread = pthread_t
    unsafe {
        thread.cast::<*mut c_void>().write(raw);
    }
    0
}

/// C `pthread_join` → nlist `_pthread_join`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn pthread_join(
    thread: *mut c_void,
    value_ptr: *mut *mut c_void,
) -> c_int {
    if thread.is_null() {
        return EINVAL;
    }
    let t = thread.cast::<KhThread>();
    // SAFETY: must be a KhThread from create.
    if unsafe { (*t).magic } != MAGIC {
        return EINVAL;
    }
    if unsafe { (*t).detached.load(Ordering::Acquire) } != 0 {
        return EINVAL;
    }
    let done = unsafe { &(*t).done };
    while done.load(Ordering::Acquire) == 0 {
        park_word(done, 0);
    }
    if !value_ptr.is_null() {
        let r = unsafe { (*t).result.load(Ordering::Acquire) };
        unsafe {
            value_ptr.write(core::ptr::with_exposed_provenance_mut(r));
        }
    }
    // Reclaim TLS + stack + control block (after done; worker is finished).
    let stack = unsafe { (*t).stack };
    let stack_size = unsafe { (*t).stack_size };
    let tsd = unsafe { (*t).tsd };
    munmap_anon(stack, stack_size);
    unsafe {
        if !tsd.is_null() {
            free_tsd_array((*tsd).tsd_vals);
            (*tsd).tsd_vals = core::ptr::null_mut();
            free(tsd.cast::<c_void>());
        }
        free(thread);
    }
    0
}

/// C `pthread_detach` → nlist `_pthread_detach`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn pthread_detach(thread: *mut c_void) -> c_int {
    if thread.is_null() {
        return EINVAL;
    }
    let t = thread.cast::<KhThread>();
    if unsafe { (*t).magic } != MAGIC {
        return EINVAL;
    }
    unsafe {
        (*t).detached.store(1, Ordering::Release);
    }
    // Leak stack/control for micro (worker may still be running).
    0
}
