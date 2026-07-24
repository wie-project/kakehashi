//! Process-wide translator state for the single guest-process model.
//!
//! Consolidates guest FD table, bottle root, soft signal state, and syscall
//! limits behind one active slot (same pattern as [`crate::mem::AddressSpace`]).
//! Trap handlers and BSD syscalls access this via [`with_mut`] / [`with_ref`].

use std::collections::HashMap;
use std::os::fd::RawFd;
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};

use crate::host;

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

/// Guest FD → host FD mapping (stdio 0/1/2 are identity).
#[derive(Debug)]
pub(crate) struct FdTable {
    map: HashMap<i32, RawFd>,
    next: i32,
}

impl FdTable {
    fn new() -> Self {
        Self {
            map: HashMap::new(),
            next: 32,
        }
    }

    pub(crate) fn reset(&mut self) {
        for (gfd, hfd) in self.map.drain() {
            if gfd > 2 {
                host::close_fd(hfd);
            }
        }
        self.next = 32;
    }

    #[must_use]
    pub(crate) fn get(&self, gfd: i32) -> Option<RawFd> {
        if gfd == 0 || gfd == 1 || gfd == 2 {
            return Some(gfd);
        }
        self.map.get(&gfd).copied()
    }

    pub(crate) fn take(&mut self, gfd: i32) -> Option<RawFd> {
        self.map.remove(&gfd)
    }

    pub(crate) fn alloc(&mut self, host_fd: RawFd) -> Option<i32> {
        for _ in 0..1024 {
            let gfd = self.next;
            self.next = self.next.saturating_add(1);
            if gfd > 2 && !self.map.contains_key(&gfd) {
                self.map.insert(gfd, host_fd);
                return Some(gfd);
            }
        }
        None
    }
}

/// Owned process state for one guest (or unit-test isolation via reset).
#[derive(Debug)]
pub struct ProcessState {
    fds: FdTable,
    bottle_root: Option<PathBuf>,
    sig_mask: u32,
    sigactions: [SoftSigAct; 32],
    bsdthread: Option<BsdThreadReg>,
    syscall_count: u64,
    max_syscalls: u64,
}

impl ProcessState {
    /// Fresh process state with default syscall limit.
    #[must_use]
    pub fn new() -> Self {
        Self {
            fds: FdTable::new(),
            bottle_root: None,
            sig_mask: 0,
            sigactions: [SoftSigAct::zero(); 32],
            bsdthread: None,
            syscall_count: 0,
            max_syscalls: 256,
        }
    }

    /// Resets FD table, soft signals, thread reg, and counters. Preserves bottle root.
    pub fn reset_run(&mut self, max_syscalls: usize) {
        self.fds.reset();
        self.sig_mask = 0;
        self.sigactions = [SoftSigAct::zero(); 32];
        self.bsdthread = None;
        self.syscall_count = 0;
        self.max_syscalls = u64::try_from(max_syscalls).unwrap_or(256);
        crate::thread::reset_thread_runtime();
    }

    #[must_use]
    pub(crate) fn bsdthread(&self) -> Option<BsdThreadReg> {
        self.bsdthread
    }

    pub(crate) fn set_bsdthread(&mut self, reg: BsdThreadReg) {
        self.bsdthread = Some(reg);
    }

    #[must_use]
    pub(crate) fn fds(&self) -> &FdTable {
        &self.fds
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

    /// Bumps the syscall counter; returns `true` if the limit was exceeded.
    pub(crate) fn tick_syscall(&mut self) -> bool {
        self.syscall_count = self.syscall_count.saturating_add(1);
        self.syscall_count > self.max_syscalls
    }
}

impl Default for ProcessState {
    fn default() -> Self {
        Self::new()
    }
}

fn active_mutex() -> &'static Mutex<ProcessState> {
    static ACTIVE: OnceLock<Mutex<ProcessState>> = OnceLock::new();
    ACTIVE.get_or_init(|| Mutex::new(ProcessState::new()))
}

/// Exclusive access to the active process state.
pub fn with_mut<R>(f: impl FnOnce(&mut ProcessState) -> R) -> R {
    match active_mutex().lock() {
        Ok(mut guard) => f(&mut guard),
        Err(poisoned) => f(&mut poisoned.into_inner()),
    }
}

/// Shared access to the active process state.
pub fn with_ref<R>(f: impl FnOnce(&ProcessState) -> R) -> R {
    match active_mutex().lock() {
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

/// Serializes tests that mutate process-wide state (address space + process).
#[cfg(test)]
pub(crate) fn test_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: Mutex<()> = Mutex::new(());
    LOCK.lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}
