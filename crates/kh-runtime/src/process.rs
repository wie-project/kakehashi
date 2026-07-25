//! Process-wide translator state for the single guest-process model.
//!
//! Consolidates guest FD table, bottle root, soft signal state, and syscall
//! limits behind one active slot (same pattern as [`crate::mem::AddressSpace`]).
//! Trap handlers and BSD syscalls access this via [`with_mut`] / [`with_ref`].

use std::collections::HashMap;
use std::os::fd::RawFd;
use std::path::PathBuf;
use std::sync::atomic::{AtomicI32, AtomicU64, Ordering};
use std::sync::{OnceLock, RwLock};

use crate::host;

/// Process-wide syscall counter (hot path: no process-state lock).
static SYSCALL_COUNT: AtomicU64 = AtomicU64::new(0);
/// Cap for [`SYSCALL_COUNT`]; updated by [`reset_run`].
static MAX_SYSCALLS: AtomicU64 = AtomicU64::new(256);

/// Max guest FD slots (stdio 0–2 + table). Keeps FDs under typical OPEN_MAX.
const FD_SLOTS: usize = 1024;
/// Empty slot in the lock-free FD map.
const FD_EMPTY: i32 = -1;

/// Guest → host FD map for **lookup** without the process `RwLock`.
///
/// Slots 0–2 are unused (stdio identity). Other slots: host fd ≥ 0, or [`FD_EMPTY`].
/// Alloc/take update these atomics; dir streams still use the process lock.
static FD_HOST: [AtomicI32; FD_SLOTS] = [const { AtomicI32::new(FD_EMPTY) }; FD_SLOTS];
/// Hint for next free FD scan.
static FD_NEXT: AtomicI32 = AtomicI32::new(3);

/// Soft Darwin `sigaction` slot (handler + mask + flags).
#[derive(Clone, Copy, Debug)]
pub(crate) struct SoftSigAct {
    pub handler: u64,
    pub mask: u32,
    pub flags: i32,
}

/// Values from Darwin `bsdthread_register` (libpthread start trampoline, etc.).
///
/// Extra fields are retained for future workq/TLS wiring even when unused today.
#[derive(Clone, Copy, Debug, Default)]
#[allow(dead_code)]
pub(crate) struct BsdThreadReg {
    /// Userland start trampoline (`_pthread_start`).
    pub threadstart: u64,
    /// Workqueue thread entry (unused in micro; stored for completeness).
    pub wqthread: u64,
    /// Registration flags from libpthread.
    pub flags: u32,
    /// Stack address hint (unused in micro).
    pub stack_addr_hint: u64,
    /// TSD offset within the pthread structure.
    pub tsd_offset: u32,
    /// Dispatch queue offset within the pthread structure.
    pub dispatchqueue_offset: u32,
}

impl SoftSigAct {
    pub(crate) const fn zero() -> Self {
        Self {
            handler: 0,
            mask: 0,
            flags: 0,
        }
    }
}

/// Thin handle so `ProcessState` can still expose `fds_mut()` for alloc/take.
#[derive(Debug, Default)]
pub(crate) struct FdTable;

impl FdTable {
    const fn new() -> Self {
        Self
    }

    pub(crate) fn reset(&mut self) {
        let _ = self;
        reset_fd_map();
    }

    pub(crate) fn take(&mut self, gfd: i32) -> Option<RawFd> {
        let _ = self;
        fd_take(gfd)
    }

    pub(crate) fn alloc(&mut self, host_fd: RawFd) -> Option<i32> {
        let _ = self;
        fd_alloc(host_fd)
    }
}

/// Resolve guest FD → host FD without taking the process lock (I/O hot path).
#[must_use]
#[inline]
pub fn fd_get(gfd: i32) -> Option<RawFd> {
    if gfd == 0 || gfd == 1 || gfd == 2 {
        return Some(gfd);
    }
    if gfd < 0 {
        return None;
    }
    let Ok(idx) = usize::try_from(gfd) else {
        return None;
    };
    let slot = FD_HOST.get(idx)?;
    let v = slot.load(Ordering::Acquire);
    if v < 0 { None } else { Some(v) }
}

fn fd_take(gfd: i32) -> Option<RawFd> {
    if gfd <= 2 {
        return None;
    }
    let Ok(idx) = usize::try_from(gfd) else {
        return None;
    };
    let slot = FD_HOST.get(idx)?;
    let v = slot.swap(FD_EMPTY, Ordering::AcqRel);
    if v < 0 { None } else { Some(v) }
}

fn fd_alloc(host_fd: RawFd) -> Option<i32> {
    if host_fd < 0 {
        return None;
    }
    let start = usize::try_from(FD_NEXT.load(Ordering::Relaxed).max(3)).unwrap_or(3);
    for idx in start..FD_SLOTS {
        if try_claim_slot(idx, host_fd) {
            let gfd = i32::try_from(idx).ok()?;
            FD_NEXT.store(gfd.saturating_add(1), Ordering::Relaxed);
            return Some(gfd);
        }
    }
    for idx in 3..start.min(FD_SLOTS) {
        if try_claim_slot(idx, host_fd) {
            let gfd = i32::try_from(idx).ok()?;
            FD_NEXT.store(gfd.saturating_add(1), Ordering::Relaxed);
            return Some(gfd);
        }
    }
    None
}

fn try_claim_slot(idx: usize, host_fd: RawFd) -> bool {
    let Some(slot) = FD_HOST.get(idx) else {
        return false;
    };
    slot.compare_exchange(FD_EMPTY, host_fd, Ordering::AcqRel, Ordering::Relaxed)
        .is_ok()
}

fn reset_fd_map() {
    for (i, slot) in FD_HOST.iter().enumerate() {
        let prev = slot.swap(FD_EMPTY, Ordering::AcqRel);
        if i > 2 && prev >= 0 {
            host::close_fd(prev);
        }
    }
    FD_NEXT.store(3, Ordering::Relaxed);
}

/// Owned process state for one guest (or unit-test isolation via reset).
#[derive(Debug)]
pub struct ProcessState {
    fds: FdTable,
    /// Guest FD → directory stream (for `readdir` host helper).
    dir_streams: HashMap<i32, host::HostDir>,
    bottle_root: Option<PathBuf>,
    sig_mask: u32,
    sigactions: [SoftSigAct; 32],
    bsdthread: Option<BsdThreadReg>,
}

impl ProcessState {
    /// Fresh process state with default syscall limit.
    #[must_use]
    pub fn new() -> Self {
        Self {
            fds: FdTable::new(),
            dir_streams: HashMap::new(),
            bottle_root: None,
            sig_mask: 0,
            sigactions: [SoftSigAct::zero(); 32],
            bsdthread: None,
        }
    }

    /// Resets FD table, soft signals, thread reg, and counters. Preserves bottle root.
    pub fn reset_run(&mut self, max_syscalls: usize) {
        self.dir_streams.clear();
        self.fds.reset();
        self.sig_mask = 0;
        self.sigactions = [SoftSigAct::zero(); 32];
        self.bsdthread = None;
        let max = u64::try_from(max_syscalls).unwrap_or(256);
        MAX_SYSCALLS.store(max, Ordering::Relaxed);
        SYSCALL_COUNT.store(0, Ordering::Relaxed);
        crate::thread::reset_thread_runtime();
    }

    /// Closes any directory stream associated with `gfd` (call before FD free).
    pub(crate) fn close_dir_stream(&mut self, gfd: i32) {
        drop(self.dir_streams.remove(&gfd));
    }

    /// Returns the next directory entry for `gfd`, opening a stream on first use.
    ///
    /// `None` means end-of-directory (or empty). `Err(errno)` on failure.
    pub(crate) fn readdir_next(&mut self, gfd: i32) -> Result<Option<(Vec<u8>, u8)>, i64> {
        let Some(host_fd) = fd_get(gfd) else {
            return Err(9); // EBADF
        };

        if let std::collections::hash_map::Entry::Vacant(e) = self.dir_streams.entry(gfd) {
            match host::HostDir::open_dup(host_fd) {
                Ok(dir) => {
                    e.insert(dir);
                }
                Err(err) => return Err(i64::from(err)),
            }
        }

        let Some(stream) = self.dir_streams.get_mut(&gfd) else {
            return Err(9);
        };
        Ok(stream.read_next())
    }

    #[must_use]
    pub(crate) fn bsdthread(&self) -> Option<BsdThreadReg> {
        self.bsdthread
    }

    pub(crate) fn set_bsdthread(&mut self, reg: BsdThreadReg) {
        self.bsdthread = Some(reg);
    }

    pub(crate) fn fds_mut(&mut self) -> &mut FdTable {
        &mut self.fds
    }

    #[must_use]
    pub fn bottle_root(&self) -> Option<&std::path::Path> {
        self.bottle_root.as_deref()
    }

    pub fn set_bottle_root(&mut self, root: Option<PathBuf>) {
        self.bottle_root = root;
    }

    #[must_use]
    pub(crate) fn sig_mask(&self) -> u32 {
        self.sig_mask
    }

    pub(crate) fn set_sig_mask(&mut self, mask: u32) {
        self.sig_mask = mask;
    }

    #[must_use]
    pub(crate) fn sigaction(&self, sig: usize) -> Option<SoftSigAct> {
        self.sigactions.get(sig).copied()
    }

    pub(crate) fn set_sigaction(&mut self, sig: usize, act: SoftSigAct) -> bool {
        if let Some(slot) = self.sigactions.get_mut(sig) {
            *slot = act;
            true
        } else {
            false
        }
    }
}

impl Default for ProcessState {
    fn default() -> Self {
        Self::new()
    }
}

/// Bumps the process-wide syscall counter without taking the process lock.
///
/// Returns `true` when the configured max has been exceeded.
#[must_use]
pub fn tick_syscall() -> bool {
    let n = SYSCALL_COUNT.fetch_add(1, Ordering::Relaxed);
    n >= MAX_SYSCALLS.load(Ordering::Relaxed)
}

fn active_lock() -> &'static RwLock<ProcessState> {
    static ACTIVE: OnceLock<RwLock<ProcessState>> = OnceLock::new();
    ACTIVE.get_or_init(|| RwLock::new(ProcessState::new()))
}

/// Exclusive access to the active process state.
pub fn with_mut<R>(f: impl FnOnce(&mut ProcessState) -> R) -> R {
    match active_lock().write() {
        Ok(mut guard) => f(&mut guard),
        Err(poisoned) => f(&mut poisoned.into_inner()),
    }
}

/// Shared access to the active process state (concurrent FD lookups, etc.).
pub fn with_ref<R>(f: impl FnOnce(&ProcessState) -> R) -> R {
    match active_lock().read() {
        Ok(guard) => f(&guard),
        Err(poisoned) => f(&poisoned.into_inner()),
    }
}

/// Resets FD/signals/counters for a new guest run (keeps bottle root).
pub fn reset_run(max_syscalls: usize) {
    with_mut(|p| p.reset_run(max_syscalls));
}

/// Configures the bottle root used by path-taking syscalls.
pub fn set_bottle_root(root: Option<PathBuf>) {
    with_mut(|p| p.set_bottle_root(root));
}

/// Clone of the configured bottle root, if any.
#[must_use]
pub fn bottle_root() -> Option<PathBuf> {
    with_ref(|p| p.bottle_root.clone())
}

/// Borrow the bottle root without cloning (hot path for path translation).
pub fn with_bottle_root<R>(f: impl FnOnce(Option<&std::path::Path>) -> R) -> R {
    with_ref(|p| f(p.bottle_root.as_deref()))
}

/// Serializes tests that mutate process-wide state (address space + process).
#[cfg(test)]
pub(crate) fn test_lock() -> std::sync::MutexGuard<'static, ()> {
    use std::sync::Mutex;
    static LOCK: Mutex<()> = Mutex::new(());
    LOCK.lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}
