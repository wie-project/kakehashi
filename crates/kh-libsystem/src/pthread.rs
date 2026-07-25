//! Minimal pthread: spin mutex/cond + real workers via `bsdthread_*`.
//!
//! Soft `pthread_create` → `EAGAIN` plus immediate `pthread_cond_wait` caused
//! pure-userspace hangs in multi-thread guests (`7zz a`): main waited forever
//! for workers that never ran. We register a freestanding trampoline, spawn
//! host-backed guest threads through the runtime, and join on a done flag.

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

const MAGIC: u64 = 0x4B48_5054_4852_4401; // "KHPTHRD\x01"
/// Guest worker stacks must fit freestanding NEON hypercall frames + host
/// dispatch + 7zz LZMA worker frames. 1 MiB was tight under `-mmt>1`.
const STACK_SIZE: usize = 4 * 1024 * 1024;
const PAGE: usize = 16_384;

static REGISTERED: AtomicBool = AtomicBool::new(false);

/// Control block pointed to by guest `pthread_t`.
#[repr(C, align(16))]
struct KhThread {
    magic: u64,
    done: AtomicU32,
    detached: AtomicU32,
    result: AtomicUsize,
    stack: *mut u8,
    stack_size: usize,
    /// User start routine (kept for debugging).
    start_func: usize,
    start_arg: usize,
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
    let mut ret: *mut c_void = core::ptr::null_mut();
    if !func.is_null() {
        let f: StartFn = unsafe { core::mem::transmute(func) };
        ret = unsafe { f(arg) };
    }
    if !pthread.is_null() {
        let t = pthread.cast::<KhThread>();
        // SAFETY: our create allocated this block.
        unsafe {
            if (*t).magic == MAGIC {
                (*t).result.store(ret.addr(), Ordering::Release);
                (*t).done.store(1, Ordering::Release);
                // Wake joiners parked on `done`.
                let done = &(*t).done;
                let addr = u64::try_from(core::ptr::from_ref(done).addr()).unwrap_or(0);
                let _ = sys::helper2(KH_HELPER_WAKE, addr, u64::from(u32::MAX));
            }
        }
    }
    // End this host worker only (runtime maps this to pthread_exit).
    let _ = unsafe { sys::syscall6(SYS_BSDTHREAD_TERMINATE, 0, 0, 0, 0, 0, 0) };
    loop {
        core::hint::spin_loop();
    }
}

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
// 0 = unlocked, 1 = locked. Contended waiters park on the word via host futex
// so we do not burn the host with yield-SVC spin storms under 7zz MT.

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
        (*mutex_word(mutex)).store(0, Ordering::Relaxed);
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
        (*mutex_word(mutex)).store(0, Ordering::Relaxed);
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
        .compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed)
        .is_ok()
    {
        return 0;
    }
    // Short spin then park while still locked.
    loop {
        for _ in 0..64_u32 {
            if w
                .compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed)
                .is_ok()
            {
                return 0;
            }
            core::hint::spin_loop();
        }
        // FUTEX_WAIT returns if value ≠ expected (unlock raced ahead).
        park_word(w, 1);
    }
}

/// C `pthread_mutex_unlock` → nlist `_pthread_mutex_unlock`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn pthread_mutex_unlock(mutex: *mut c_void) -> c_int {
    if mutex.is_null() {
        return EINVAL;
    }
    let w = unsafe { &*mutex_word(mutex) };
    w.store(0, Ordering::Release);
    wake_word(w, 1);
    0
}

// ── cond (first word = generation) ──────────────────────────────────────────

#[inline]
fn cond_word(cond: *mut c_void) -> *mut AtomicU32 {
    cond.cast::<AtomicU32>()
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
        (*cond_word(cond)).store(0, Ordering::Relaxed);
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
pub(crate) unsafe extern "C" fn pthread_cond_wait(
    cond: *mut c_void,
    mutex: *mut c_void,
) -> c_int {
    if cond.is_null() || mutex.is_null() {
        return EINVAL;
    }
    let c = unsafe { &*cond_word(cond) };
    let snapshot = c.load(Ordering::Acquire);
    let _ = unsafe { pthread_mutex_unlock(mutex) };
    while c.load(Ordering::Acquire) == snapshot {
        park_word(c, snapshot);
    }
    let _ = unsafe { pthread_mutex_lock(mutex) };
    0
}

/// C `pthread_cond_broadcast` → nlist `_pthread_cond_broadcast`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn pthread_cond_broadcast(cond: *mut c_void) -> c_int {
    if cond.is_null() {
        return EINVAL;
    }
    let c = unsafe { &*cond_word(cond) };
    let _ = c.fetch_add(1, Ordering::Release);
    wake_word(c, u32::MAX);
    0
}

/// C `pthread_cond_signal` → nlist `_pthread_cond_signal` (same as broadcast).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn pthread_cond_signal(cond: *mut c_void) -> c_int {
    unsafe { pthread_cond_broadcast(cond) }
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
    let t = raw.cast::<KhThread>();
    unsafe {
        (*t).magic = MAGIC;
        (*t).done = AtomicU32::new(0);
        (*t).detached = AtomicU32::new(0);
        (*t).result = AtomicUsize::new(0);
        (*t).stack = stack;
        (*t).stack_size = STACK_SIZE;
        (*t).start_func = start.addr();
        (*t).start_arg = arg.addr();
    }

    // Stack grows down: pass high address (16-byte aligned).
    let stack_top = stack.addr().saturating_add(STACK_SIZE) & !0xF_usize;
    let pthread_va = u64::try_from(raw.addr()).unwrap_or(0);
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
            free(raw);
        }
        munmap_anon(stack, STACK_SIZE);
        return EAGAIN;
    }

    // After the first worker, freestanding hypercall falls back to svc→brk
    // (MT-safe path). See `sys::note_worker_spawned`.
    sys::note_worker_spawned();

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
    // Reclaim stack + control block.
    let stack = unsafe { (*t).stack };
    let stack_size = unsafe { (*t).stack_size };
    munmap_anon(stack, stack_size);
    unsafe {
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
