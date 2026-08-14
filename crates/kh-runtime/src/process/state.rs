//! Process-wide translator state (single guest-process model).
//!
//! Hot paths avoid the process [`RwLock`]: lock-free FD map, bottle-root
//! [`Arc`] slot, atomic `bsdthread_register` snapshot. Soft signals and
//! directory streams still use [`with_mut`] / [`with_ref`].

use std::collections::HashMap;
use std::os::fd::RawFd;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicI32, AtomicU8, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock, RwLock};

use crate::host;

/// Process-wide syscall counter (hot path: no process-state lock).
static SYSCALL_COUNT: AtomicU64 = AtomicU64::new(0);
/// Cap for [`SYSCALL_COUNT`]; updated by [`reset_run`].
static MAX_SYSCALLS: AtomicU64 = AtomicU64::new(256);

/// Unreaped host children from guest `fork` (parent side only).
///
/// Secondary signal for blocking I/O waits; primary control is
/// [`fd_guest_nonblock`] (guest `O_NONBLOCK` flag).
static LIVE_CHILDREN: AtomicU64 = AtomicU64::new(0);

/// Max guest FD slots (stdio 0–2 + table). Keeps FDs under typical OPEN_MAX.
const FD_SLOTS: usize = 1024;
/// Empty slot in the lock-free FD map.
const FD_EMPTY: i32 = -1;

/// Guest → host FD map for **lookup** without the process `RwLock`.
///
/// Slots 0–2 are unused (stdio identity). Other slots: host fd ≥ 0, or [`FD_EMPTY`].
/// Alloc/take update these atomics; dir streams still use the process lock.
static FD_HOST: [AtomicI32; FD_SLOTS] = [const { AtomicI32::new(FD_EMPTY) }; FD_SLOTS];
/// Guest-visible `O_NONBLOCK` per FD slot (including stdio 0–2).
///
/// Host pipes/sockets are often forced non-blocking for curl multi; Darwin
/// guests still expect **blocking** semantics until they `fcntl(F_SETFL)`.
/// I/O emulates blocking waits when this bit is clear.
static FD_GUEST_NB: [AtomicU8; FD_SLOTS] = [const { AtomicU8::new(0) }; FD_SLOTS];
/// Guest FD has a host-side TLS session ([`crate::tls_fd`]).
///
/// Lock-free hot-path check so ordinary `read`/`write` skip the TLS HashMap.
static FD_TLS: [AtomicU8; FD_SLOTS] = [const { AtomicU8::new(0) }; FD_SLOTS];
/// Hint for next free FD scan.
static FD_NEXT: AtomicI32 = AtomicI32::new(3);
/// Guest path string for each allocated FD (for `fcntl(F_GETPATH)` after
/// fat-thin replaces the host FD with a memfd / unlinked temp).
static FD_GUEST_PATH: RwLock<Option<HashMap<i32, String>>> = RwLock::new(None);
/// Guest has `close`'d stdio slots 0/1/2 (bit0=stdin, bit1=stdout, bit2=stderr).
///
/// Stdio is identity-mapped; soft no-op close would leave host pipes open and
/// leak fetch-pack noise into git remote-curl helpers.
static STDIO_CLOSED: AtomicU8 = AtomicU8::new(0);

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

/// Marker so `ProcessState::reset_run` can clear the lock-free FD map.
#[derive(Debug, Default)]
struct FdTable;

impl FdTable {
    const fn new() -> Self {
        Self
    }

    fn reset(&mut self) {
        let _ = self;
        reset_fd_map();
    }
}

/// Resolve guest FD → host FD without taking the process lock (I/O hot path).
#[must_use]
#[inline]
pub fn fd_get(gfd: i32) -> Option<RawFd> {
    if gfd == 0 || gfd == 1 || gfd == 2 {
        if stdio_is_closed(gfd) {
            return None;
        }
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

/// Removes a guest FD mapping and returns the host fd (lock-free).
///
/// For stdio 0–2: marks the slot closed and returns the host fd (identity) so
/// the caller can `close` it — matching Darwin when `fetch-pack` drops stdout.
#[must_use]
#[inline]
pub fn fd_take(gfd: i32) -> Option<RawFd> {
    if gfd == 0 || gfd == 1 || gfd == 2 {
        if stdio_is_closed(gfd) {
            return None;
        }
        stdio_mark_closed(gfd);
        return Some(gfd);
    }
    if gfd < 0 {
        return None;
    }
    let Ok(idx) = usize::try_from(gfd) else {
        return None;
    };
    let slot = FD_HOST.get(idx)?;
    let v = slot.swap(FD_EMPTY, Ordering::AcqRel);
    if let Some(t) = FD_TLS.get(idx) {
        t.store(0, Ordering::Release);
    }
    if let Some(nb) = FD_GUEST_NB.get(idx) {
        nb.store(0, Ordering::Release);
    }
    fd_clear_guest_path(gfd);
    if v < 0 { None } else { Some(v) }
}

/// Record the guest path used to open `gfd` (absolute Darwin path).
pub fn fd_set_guest_path(gfd: i32, path: impl Into<String>) {
    if gfd < 3 {
        return;
    }
    if let Ok(mut g) = FD_GUEST_PATH.write() {
        let map = g.get_or_insert_with(HashMap::new);
        map.insert(gfd, path.into());
    }
}

/// Guest path for `gfd`, if recorded at open.
#[must_use]
pub fn fd_guest_path(gfd: i32) -> Option<String> {
    if gfd < 3 {
        return None;
    }
    FD_GUEST_PATH
        .read()
        .ok()
        .and_then(|g| g.as_ref().and_then(|m| m.get(&gfd).cloned()))
}

fn fd_clear_guest_path(gfd: i32) {
    if gfd < 3 {
        return;
    }
    if let Ok(mut g) = FD_GUEST_PATH.write()
        && let Some(map) = g.as_mut()
    {
        map.remove(&gfd);
    }
}

/// Bit for guest stdio FD in [`STDIO_CLOSED`] (`0→1`, `1→2`, `2→4`).
#[inline]
fn stdio_closed_bit(gfd: i32) -> Option<u8> {
    match gfd {
        0 => Some(1),
        1 => Some(2),
        2 => Some(4),
        _ => None,
    }
}

#[inline]
fn stdio_is_closed(gfd: i32) -> bool {
    let Some(bit) = stdio_closed_bit(gfd) else {
        return false;
    };
    STDIO_CLOSED.load(Ordering::Acquire) & bit != 0
}

#[inline]
fn stdio_mark_closed(gfd: i32) {
    let Some(bit) = stdio_closed_bit(gfd) else {
        return;
    };
    STDIO_CLOSED.fetch_or(bit, Ordering::AcqRel);
}

/// Clear the closed bit for a stdio slot (after successful `dup2` onto 0/1/2).
#[inline]
pub fn stdio_mark_open(gfd: i32) {
    let Some(bit) = stdio_closed_bit(gfd) else {
        return;
    };
    STDIO_CLOSED.fetch_and(!bit, Ordering::AcqRel);
}

/// Installs `host_fd` into a **specific** guest FD slot (for `dup2`).
///
/// Closes any previous host mapping at `gfd` (except stdio 0–2 identity).
/// Guest nonblock flag is **not** updated — caller should copy from the source.
/// Returns `false` if `gfd` is out of range.
#[must_use]
#[inline]
pub fn fd_install(gfd: i32, host_fd: RawFd) -> bool {
    if host_fd < 0 || gfd < 3 {
        return false;
    }
    let Ok(idx) = usize::try_from(gfd) else {
        return false;
    };
    let Some(slot) = FD_HOST.get(idx) else {
        return false;
    };
    let prev = slot.swap(host_fd, Ordering::AcqRel);
    if prev >= 0 && prev != host_fd {
        host::close_fd(prev);
    }
    true
}

/// Allocates a guest FD slot for `host_fd` (lock-free CAS scan).
///
/// New slots start with guest-blocking semantics (`O_NONBLOCK` clear). Call
/// [`fd_set_guest_nonblock`] for sockets / after `fcntl(F_SETFL)`.
#[must_use]
#[inline]
pub fn fd_alloc(host_fd: RawFd) -> Option<i32> {
    if host_fd < 0 {
        return None;
    }
    let start = usize::try_from(FD_NEXT.load(Ordering::Relaxed).max(3)).unwrap_or(3);
    for idx in start..FD_SLOTS {
        if try_claim_slot(idx, host_fd) {
            let gfd = i32::try_from(idx).ok()?;
            fd_set_guest_nonblock(gfd, false);
            FD_NEXT.store(gfd.saturating_add(1), Ordering::Relaxed);
            return Some(gfd);
        }
    }
    for idx in 3..start.min(FD_SLOTS) {
        if try_claim_slot(idx, host_fd) {
            let gfd = i32::try_from(idx).ok()?;
            fd_set_guest_nonblock(gfd, false);
            FD_NEXT.store(gfd.saturating_add(1), Ordering::Relaxed);
            return Some(gfd);
        }
    }
    None
}

/// Guest-visible `O_NONBLOCK` for `gfd` (stdio or allocated slot).
#[must_use]
#[inline]
pub fn fd_guest_nonblock(gfd: i32) -> bool {
    if gfd < 0 {
        return false;
    }
    let Ok(idx) = usize::try_from(gfd) else {
        return false;
    };
    FD_GUEST_NB
        .get(idx)
        .is_some_and(|s| s.load(Ordering::Acquire) != 0)
}

/// Sets guest-visible `O_NONBLOCK` for `gfd`.
#[inline]
pub fn fd_set_guest_nonblock(gfd: i32, nonblock: bool) {
    if gfd < 0 {
        return;
    }
    let Ok(idx) = usize::try_from(gfd) else {
        return;
    };
    if let Some(slot) = FD_GUEST_NB.get(idx) {
        slot.store(u8::from(nonblock), Ordering::Release);
    }
}

/// True when `gfd` is a TLS-wrapped guest FD (hot path; no mutex).
#[must_use]
#[inline]
pub fn fd_is_tls(gfd: i32) -> bool {
    if gfd < 0 {
        return false;
    }
    let Ok(idx) = usize::try_from(gfd) else {
        return false;
    };
    FD_TLS
        .get(idx)
        .is_some_and(|s| s.load(Ordering::Acquire) != 0)
}

/// Mark / clear TLS session association for `gfd` (paired with [`crate::tls_fd`]).
#[inline]
pub fn fd_set_tls(gfd: i32, is_tls: bool) {
    if gfd < 0 {
        return;
    }
    let Ok(idx) = usize::try_from(gfd) else {
        return;
    };
    if let Some(slot) = FD_TLS.get(idx) {
        slot.store(u8::from(is_tls), Ordering::Release);
    }
}

/// Clear host `O_NONBLOCK` on stdio when the fd is a pipe/FIFO.
///
/// Nested `kh run` (git helpers after `fork`+re-exec) inherits command pipes as
/// host 0/1/2. Those pipes are created non-blocking for curl multi; helpers
/// expect Darwin blocking stdin/stdout. Call once per guest run start.
pub fn normalize_stdio_pipes_blocking() {
    for fd in 0_i32..=2 {
        if host::fd_is_fifo(fd) {
            host::clear_nonblock(fd);
            fd_set_guest_nonblock(fd, false);
        }
    }
}

/// Bottle root published for path translation (set once per run; rare updates).
static BOTTLE_ROOT: RwLock<Option<Arc<PathBuf>>> = RwLock::new(None);

/// Guest `argv` for `_NSGetArgc` / `_NSGetArgv` (Rust `std::env::args` on Darwin).
static GUEST_ARGV: RwLock<Vec<String>> = RwLock::new(Vec::new());

/// Guest absolute path of the main executable (`_NSGetExecutablePath`).
///
/// Set at `kh run` / nested re-exec start. Soft-git fallback lived in freestanding
/// libSystem; clang spawn needs the real binary (not a hard-coded git path).
static GUEST_EXECUTABLE: RwLock<Option<Arc<str>>> = RwLock::new(None);

/// Darwin TLV template for one mapped image (`__thread_vars` + data/bss).
#[derive(Clone, Copy, Debug, Default)]
pub struct TlvTemplate {
    /// Inclusive start of `__thread_vars`.
    pub vars_lo: u64,
    /// Exclusive end of `__thread_vars`.
    pub vars_hi: u64,
    /// Start of `__thread_data` (initial values).
    pub data_lo: u64,
    /// Bytes of initialized TLS.
    pub data_len: u64,
    /// Bytes of `__thread_bss` (stay zero).
    pub bss_len: u64,
}

static TLV_TEMPLATES: RwLock<Vec<TlvTemplate>> = RwLock::new(Vec::new());

/// Record one image's Darwin TLV template (call after slide is known).
pub fn register_tlv_template(tmpl: TlvTemplate) {
    if tmpl.vars_hi <= tmpl.vars_lo {
        return;
    }
    match TLV_TEMPLATES.write() {
        Ok(mut g) => g.push(tmpl),
        Err(p) => p.into_inner().push(tmpl),
    }
}

/// Template whose `__thread_vars` range contains `desc_va`.
#[must_use]
pub fn tlv_template_for_desc(desc_va: u64) -> Option<TlvTemplate> {
    let g = match TLV_TEMPLATES.read() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };
    g.iter()
        .copied()
        .find(|t| desc_va >= t.vars_lo && desc_va < t.vars_hi)
}

fn clear_tlv_templates() {
    match TLV_TEMPLATES.write() {
        Ok(mut g) => g.clear(),
        Err(p) => p.into_inner().clear(),
    }
}

/// Main guest stack low address (identity VA). `0` = unset.
static MAIN_STACK_BASE: AtomicU64 = AtomicU64::new(0);
/// Main guest stack length in bytes. `0` = unset.
static MAIN_STACK_LEN: AtomicU64 = AtomicU64::new(0);

/// Open `O_DIRECTORY` fd for the bottle root (`-1` = none).
///
/// Hot path: absolute guest paths use `openat`/`fstatat` against this fd
/// instead of building `{root}/{rel}` PathBuf + `open` from `/` each call (B1).
static BOTTLE_DIRFD: AtomicI32 = AtomicI32::new(-1);

/// `bsdthread_register` snapshot (narrow lock; not the full process state).
static BSDTHREAD_REG: RwLock<Option<BsdThreadReg>> = RwLock::new(None);

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
    for slot in &FD_GUEST_NB {
        slot.store(0, Ordering::Relaxed);
    }
    for slot in &FD_TLS {
        slot.store(0, Ordering::Relaxed);
    }
    if let Ok(mut g) = FD_GUEST_PATH.write() {
        *g = None;
    }
    STDIO_CLOSED.store(0, Ordering::Relaxed);
    FD_NEXT.store(3, Ordering::Relaxed);
}

/// Owned process state for one guest (or unit-test isolation via reset).
///
/// Bottle root and `bsdthread_register` live in separate process-wide slots so
/// open/create hot paths do not take this lock.
#[derive(Debug)]
pub struct ProcessState {
    fds: FdTable,
    /// Guest FD → directory stream (for `readdir` host helper).
    dir_streams: HashMap<i32, host::HostDir>,
    sig_mask: u32,
    sigactions: [SoftSigAct; 32],
}

impl ProcessState {
    /// Fresh process state with default syscall limit.
    #[must_use]
    pub fn new() -> Self {
        Self {
            fds: FdTable::new(),
            dir_streams: HashMap::new(),
            sig_mask: 0,
            sigactions: [SoftSigAct::zero(); 32],
        }
    }

    /// Resets FD table, soft signals, thread reg, and counters. Preserves bottle root.
    pub fn reset_run(&mut self, max_syscalls: usize) {
        self.dir_streams.clear();
        self.fds.reset();
        self.sig_mask = 0;
        self.sigactions = [SoftSigAct::zero(); 32];
        clear_bsdthread_reg();
        let max = u64::try_from(max_syscalls).unwrap_or(256);
        MAX_SYSCALLS.store(max, Ordering::Relaxed);
        SYSCALL_COUNT.store(0, Ordering::Relaxed);
        LIVE_CHILDREN.store(0, Ordering::Relaxed);
        MAIN_STACK_BASE.store(0, Ordering::Relaxed);
        MAIN_STACK_LEN.store(0, Ordering::Relaxed);
        clear_tlv_templates();
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

/// Parent observed a successful `fork` (child pid > 0).
#[inline]
pub fn child_born() {
    LIVE_CHILDREN.fetch_add(1, Ordering::Relaxed);
}

/// Parent reaped at least one child via `waitpid`/`wait4`.
#[inline]
pub fn child_reaped() {
    let _ = LIVE_CHILDREN.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
        Some(n.saturating_sub(1))
    });
}

/// Number of unreaped host children (approximate; for pipe blocking heuristics).
#[must_use]
#[inline]
pub fn live_children() -> u64 {
    LIVE_CHILDREN.load(Ordering::Relaxed)
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
    // Fresh guest process: drop prior dlopen image table.
    crate::dyld_table::clear();
    // After re-exec of a Mach-O helper, host 0/1/2 may be O_NONBLOCK pipes
    // created for curl multi in the parent — restore Darwin blocking stdio.
    normalize_stdio_pipes_blocking();
}

/// Configures the bottle root used by path-taking syscalls.
///
/// Also opens/replaces the process-wide bottle directory fd for B1 `openat`.
pub fn set_bottle_root(root: Option<PathBuf>) {
    let new_fd = root
        .as_ref()
        .map_or(-1, |p| open_bottle_dirfd(p).unwrap_or(-1));
    let old_fd = BOTTLE_DIRFD.swap(new_fd, Ordering::AcqRel);
    if old_fd >= 0 {
        host::close_fd(old_fd);
    }

    let next = root.map(Arc::new);
    match BOTTLE_ROOT.write() {
        Ok(mut guard) => {
            *guard = next;
        }
        Err(poisoned) => {
            *poisoned.into_inner() = next;
        }
    }
}

/// Clone of the configured bottle root, if any.
#[must_use]
pub fn bottle_root() -> Option<PathBuf> {
    with_bottle_root(|p| p.map(Path::to_path_buf))
}

/// Borrow the bottle root without cloning (hot path for path translation).
///
/// Uses a **narrow** bottle-root lock (not the full process state).
pub fn with_bottle_root<R>(f: impl FnOnce(Option<&Path>) -> R) -> R {
    match BOTTLE_ROOT.read() {
        Ok(guard) => f(guard.as_ref().map(|a| a.as_path())),
        Err(poisoned) => f(poisoned.into_inner().as_ref().map(|a| a.as_path())),
    }
}

/// Store guest argv (including argv0) for `_NSGetArgc` / `_NSGetArgv`.
pub fn set_guest_argv(argv: Vec<String>) {
    match GUEST_ARGV.write() {
        Ok(mut g) => *g = argv,
        Err(p) => *p.into_inner() = argv,
    }
}

/// Snapshot of guest argv for this run.
#[must_use]
pub fn guest_argv() -> Vec<String> {
    match GUEST_ARGV.read() {
        Ok(g) => g.clone(),
        Err(p) => p.into_inner().clone(),
    }
}

/// Records the guest-visible main executable path for `_NSGetExecutablePath`.
pub fn set_guest_executable_path(path: Option<String>) {
    let next = path
        .filter(|s| !s.is_empty() && !s.contains('\0'))
        .map(Arc::from);
    match GUEST_EXECUTABLE.write() {
        Ok(mut guard) => {
            *guard = next;
        }
        Err(poisoned) => {
            *poisoned.into_inner() = next;
        }
    }
}

/// Records the main guest stack (low address + length) for `pthread_get_stack*_np`.
pub fn set_main_stack(base: u64, len: u64) {
    MAIN_STACK_BASE.store(base, Ordering::Release);
    MAIN_STACK_LEN.store(len, Ordering::Release);
}

/// Main stack low address and length, when published for this run.
#[must_use]
pub fn main_stack() -> Option<(u64, u64)> {
    let base = MAIN_STACK_BASE.load(Ordering::Acquire);
    let len = MAIN_STACK_LEN.load(Ordering::Acquire);
    if base == 0 || len == 0 {
        None
    } else {
        Some((base, len))
    }
}

/// Guest absolute executable path, if set for this run.
#[must_use]
pub fn guest_executable_path() -> Option<String> {
    match GUEST_EXECUTABLE.read() {
        Ok(guard) => guard.as_ref().map(|s| s.as_ref().to_owned()),
        Err(poisoned) => poisoned
            .into_inner()
            .as_ref()
            .map(|s| s.as_ref().to_owned()),
    }
}

/// Process-wide bottle root directory fd for `openat`/`fstatat` (B1).
///
/// `None` when no bottle is configured or the directory could not be opened.
#[must_use]
pub fn bottle_dirfd() -> Option<RawFd> {
    let fd = BOTTLE_DIRFD.load(Ordering::Acquire);
    if fd >= 0 { Some(fd) } else { None }
}

/// Open `root` as `O_RDONLY|O_DIRECTORY|O_CLOEXEC` for hot-path `openat`.
fn open_bottle_dirfd(root: &Path) -> Option<RawFd> {
    let c = std::ffi::CString::new(root.as_os_str().as_encoded_bytes()).ok()?;
    host::open_directory(&c)
}

/// Stores `bsdthread_register` metadata for subsequent `bsdthread_create`.
pub(crate) fn set_bsdthread_reg(reg: BsdThreadReg) {
    match BSDTHREAD_REG.write() {
        Ok(mut guard) => {
            *guard = Some(reg);
        }
        Err(poisoned) => {
            *poisoned.into_inner() = Some(reg);
        }
    }
}

/// Snapshot of the last `bsdthread_register` (narrow lock, copy-out).
#[must_use]
pub(crate) fn bsdthread_reg() -> Option<BsdThreadReg> {
    match BSDTHREAD_REG.read() {
        Ok(guard) => *guard,
        Err(poisoned) => *poisoned.into_inner(),
    }
}

fn clear_bsdthread_reg() {
    match BSDTHREAD_REG.write() {
        Ok(mut guard) => {
            *guard = None;
        }
        Err(poisoned) => {
            *poisoned.into_inner() = None;
        }
    }
}

/// Serializes tests that mutate process-wide state (address space + process).
#[cfg(test)]
pub(crate) fn test_lock() -> std::sync::MutexGuard<'static, ()> {
    use std::sync::Mutex;
    static LOCK: Mutex<()> = Mutex::new(());
    LOCK.lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}
