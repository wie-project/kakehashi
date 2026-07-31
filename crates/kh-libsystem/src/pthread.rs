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

use core::ffi::{c_int, c_void};
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};

use crate::errno;
use crate::heap::{free, malloc};
use crate::sys::{
    self, SYS_BSDTHREAD_CREATE, SYS_BSDTHREAD_REGISTER, SYS_BSDTHREAD_TERMINATE, SYS_MMAP,
    SYS_MUNMAP,
};
use crate::trace;
use crate::{KH_HELPER_PARK, KH_HELPER_WAKE};

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
/// treat them as ABI for freestanding logic).
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

// ── mutex (first word of guest pthread_mutex_t) ─────────────────────────────
//
// Futex mutex states (Drepper / Linux classic):
//   0 = unlocked
//   1 = locked, no known waiters
//   2 = locked, waiters may exist → unlock must FUTEX_WAKE
//
// Uncontended unlock is store-only (no KH_HELPER_WAKE). Always-wake was the
// main residual futex storm after A1 (UTM 8k-file: ~257k futex, mostly guest).

/// Unlocked.
const MUTEX_UNLOCKED: u32 = 0;
/// Locked, no known waiters — unlock without wake.
const MUTEX_LOCKED: u32 = 1;
/// Locked with waiters — unlock clears + wakes one.
const MUTEX_CONTENDED: u32 = 2;

#[inline]
fn mutex_word(mutex: *mut c_void) -> *mut AtomicU32 {
    mutex.cast::<AtomicU32>()
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
        (*mutex_word(mutex)).store(MUTEX_UNLOCKED, Ordering::Relaxed);
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
    }
    0
}

/// C `pthread_mutex_lock` → nlist `_pthread_mutex_lock`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn pthread_mutex_lock(mutex: *mut c_void) -> c_int {
    if mutex.is_null() {
        return EINVAL;
    }
    let w = unsafe { &*mutex_word(mutex) };

    // Fast path: uncontended.
    if w
        .compare_exchange(
            MUTEX_UNLOCKED,
            MUTEX_LOCKED,
            Ordering::Acquire,
            Ordering::Relaxed,
        )
        .is_ok()
    {
        return 0;
    }

    // Slow path: short spin, then mark contended and park (F1).
    loop {
        for _ in 0..64_u32 {
            let cur = w.load(Ordering::Relaxed);
            if cur == MUTEX_UNLOCKED {
                if w
                    .compare_exchange(
                        MUTEX_UNLOCKED,
                        MUTEX_LOCKED,
                        Ordering::Acquire,
                        Ordering::Relaxed,
                    )
                    .is_ok()
                {
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
