//! Trap backend: rewrite Darwin `svc` for Linux aarch64 translation.
//!
//! Linux aarch64 treats every `svc` as a Linux syscall (number in `x8`), which
//! is incompatible with Darwin (number in `x16`, `svc #0x80`).
//!
//! Prefer **userspace trampoline** so the common path never hits `SIGTRAP`:
//! each `svc` becomes `b veneer` (no link — **preserves `x30`/LR**), and the
//! per-site veneer saves LR, `bl`s the shared dispatcher, restores LR, then
//! `b`s back to the instruction after the original `svc`. Fall back to
//! `brk #IMM` + `SIGTRAP` when a branch is out of range.
//!
//! Live handlers require **Linux aarch64**. Patching works on any host.
#![allow(unsafe_code)]

use std::io::{self, Write};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU64, Ordering};

use thiserror::Error;

use crate::mem::{
    MapError, MappedRegion, VM_PROT_EXECUTE, VM_PROT_READ, VM_PROT_WRITE, mprotect_darwin,
    mprotect_rw,
};
use crate::syscall;
#[cfg(all(target_arch = "aarch64", target_os = "linux"))]
use crate::syscall::SyscallArgs;

/// Marker immediate for patched traps (`brk #0x0F00`).
pub const BRK_TRAP_IMM: u32 = 0x0F00;

/// AArch64 `svc #imm16` base encoding: `0xD4000001 | (imm16 << 5)`.
const SVC_MASK: u32 = 0xFFE0_001F;
const SVC_BASE: u32 = 0xD400_0001;

/// AArch64 `brk #imm16`: `0xD4200000 | (imm16 << 5)`.
const fn brk_encoding(imm16: u32) -> u32 {
    0xD420_0000 | ((imm16 & 0xFFFF) << 5)
}

/// AArch64 PC-relative branch imm26 (±128 MiB), or `None` if out of range.
#[cfg(all(target_arch = "aarch64", target_os = "linux"))]
#[allow(
    clippy::as_conversions,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::manual_range_contains
)]
fn branch_imm26(from: u64, to: u64) -> Option<u32> {
    let delta = i64::try_from(to).ok()?.wrapping_sub(i64::try_from(from).ok()?);
    if delta & 3 != 0 {
        return None;
    }
    let imm = delta >> 2;
    // Imm26 signed range for B/BL.
    if imm < -(1_i64 << 25) || imm >= (1_i64 << 25) {
        return None;
    }
    // Truncate to 26-bit two's complement field (intentional).
    Some((imm as u32) & 0x03FF_FFFF)
}

/// AArch64 `BL` (imm26) from `from` to `to`.
#[cfg(all(target_arch = "aarch64", target_os = "linux"))]
fn bl_encoding(from: u64, to: u64) -> Option<u32> {
    Some(0x9400_0000 | branch_imm26(from, to)?)
}

/// AArch64 `B` (imm26, **no link** — preserves `x30`) from `from` to `to`.
#[cfg(all(target_arch = "aarch64", target_os = "linux"))]
fn b_encoding(from: u64, to: u64) -> Option<u32> {
    Some(0x1400_0000 | branch_imm26(from, to)?)
}

/// AArch64 `PSTATE` / CPSR carry flag (bit 29 of NZCV).
///
/// Darwin arm64 syscall convention: set on error (errno in `x0`), clear on success.
pub const PSTATE_C: u64 = 1 << 29;

/// One observed trap / translated syscall event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrapEvent {
    /// Guest PC at the trap (instruction address).
    pub pc: u64,
    /// Darwin BSD syscall number (`x16`) when recognized; otherwise `None`.
    pub syscall: Option<u32>,
    /// Short label (`exit`, `write`, `unknown`, …).
    pub name: String,
    /// First argument (`x0`) when applicable.
    pub arg0: u64,
    /// Second argument (`x1`) when applicable.
    pub arg1: u64,
    /// Third argument (`x2`) when applicable.
    pub arg2: u64,
    /// Return value written to `x0`, if any.
    pub retval: Option<u64>,
    /// Darwin error path: carry set, `retval` is positive errno.
    pub error: bool,
}

/// Outcome of handling a trap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrapOutcome {
    /// Guest called BSD `exit` (or the host forced process termination).
    Exit {
        /// Process exit code.
        code: i32,
    },
    /// Guest should resume after the trap instruction.
    Continue,
    /// Guest called `bsdthread_terminate` (or equivalent): end this host thread only.
    ThreadExit,
}

/// Configuration for the trap backend.
#[derive(Debug, Clone)]
pub struct TrapConfig {
    /// Maximum number of events to retain for `kh trace`.
    pub max_events: usize,
    /// Maximum syscalls before forced exit (safety cap).
    pub max_syscalls: usize,
}

impl Default for TrapConfig {
    fn default() -> Self {
        Self {
            max_events: 256,
            max_syscalls: 256,
        }
    }
}

/// Trap subsystem errors.
#[derive(Debug, Error)]
pub enum TrapError {
    /// Failed to install signal handlers.
    #[error("failed to install trap signal handler: {0}")]
    SignalSetup(#[source] io::Error),

    /// Memory protect / patch failure.
    #[error(transparent)]
    Map(#[from] MapError),

    /// Architecture / OS is not supported for live traps.
    #[error("trap backend requires Linux aarch64 for live execution")]
    UnsupportedArch,
}

#[cfg(all(target_arch = "aarch64", target_os = "linux"))]
static HANDLER_INSTALLED: AtomicBool = AtomicBool::new(false);
static EXIT_CODE: AtomicI32 = AtomicI32::new(0);
static EXIT_REQUESTED: AtomicBool = AtomicBool::new(false);
static EVENT_COUNT: AtomicU64 = AtomicU64::new(0);
static MAX_EVENTS: AtomicU64 = AtomicU64::new(256);
static TRACE_ON_EXIT: AtomicBool = AtomicBool::new(false);
static TRACE_JSON: AtomicBool = AtomicBool::new(false);
/// When set (not `i32::MIN`): if guest exit code differs, process exits 1.
static EXPECT_CODE: AtomicI32 = AtomicI32::new(i32::MIN);
static EVENTS: Mutex<Vec<TrapEvent>> = Mutex::new(Vec::new());

/// Patches every AArch64 `svc` in executable regions.
///
/// On Linux aarch64: prefers `bl` into a guest-mapped trampoline (no signal).
/// Falls back to `brk #IMM` for out-of-range sites.
pub fn patch_svc_to_brk(regions: &mut [MappedRegion]) -> Result<usize, TrapError> {
    #[cfg(all(target_arch = "aarch64", target_os = "linux"))]
    {
        patch_svc_linux(regions)
    }
    #[cfg(not(all(target_arch = "aarch64", target_os = "linux")))]
    {
        patch_svc_brk_only(regions)
    }
}

#[cfg_attr(
    all(target_arch = "aarch64", target_os = "linux"),
    allow(dead_code)
)]
fn patch_svc_brk_only(regions: &mut [MappedRegion]) -> Result<usize, TrapError> {
    let mut patched = 0_usize;
    for region in regions.iter_mut() {
        if region.prot & VM_PROT_EXECUTE == 0 {
            continue;
        }
        mprotect_rw(region)?;
        let guest_base = region.guest_addr;
        let bytes = region.host_bytes_mut();
        let mut off = 0_usize;
        while off.saturating_add(4) <= bytes.len() {
            let end = off.saturating_add(4);
            let Some(word) = bytes.get(off..end) else {
                break;
            };
            let Ok(word_bytes) = <[u8; 4]>::try_from(word) else {
                break;
            };
            let insn = u32::from_le_bytes(word_bytes);
            if is_svc(insn) {
                let brk = brk_encoding(BRK_TRAP_IMM).to_le_bytes();
                if let Some(slot) = bytes.get_mut(off..end) {
                    slot.copy_from_slice(&brk);
                    patched = patched.saturating_add(1);
                }
            }
            let _ = guest_base;
            off = end;
        }
        let restore = (region.prot | VM_PROT_READ | VM_PROT_EXECUTE) & !VM_PROT_WRITE;
        mprotect_darwin(region, restore)?;
        region.prot = restore;
    }
    Ok(patched)
}

const fn is_svc(insn: u32) -> bool {
    (insn & SVC_MASK) == SVC_BASE
}

/// Linux aarch64: optional userspace trampoline (`svc`→`b veneer`).
///
/// Enable with `KAKEHASHI_TRAMPOLINE=1`. Default is classic `brk` + `SIGTRAP`
/// (safe fallback when freestanding hypercall is off). Prefer hypercall for
/// multi-thread compression; the veneer path remains opt-in.
///
/// **Why a veneer (not a direct `bl`)?** Darwin `svc` preserves `x30` (LR). A
/// direct `bl trampoline` overwrites LR with the resume PC; the libSystem stub
/// then `ret`s to itself and spins. The veneer saves/restores the real LR.
///
/// The shared dispatcher also saves **Q0–Q31 + FPCR/FPSR** (Darwin `svc`
/// preserves SIMD; Rust would otherwise clobber NEON used by 7zz workers).
#[cfg(all(target_arch = "aarch64", target_os = "linux"))]
fn patch_svc_linux(regions: &mut [MappedRegion]) -> Result<usize, TrapError> {
    if !trampoline_enabled() {
        return patch_svc_brk_only(regions);
    }
    let mut patched = 0_usize;
    for region in regions.iter_mut() {
        if region.prot & VM_PROT_EXECUTE == 0 {
            continue;
        }
        mprotect_rw(region)?;
        let guest_base = region.guest_addr;
        // Collect svc offsets first.
        let mut sites = Vec::new();
        {
            let bytes = region.host_bytes();
            let mut off = 0_usize;
            while off.saturating_add(4) <= bytes.len() {
                let end = off.saturating_add(4);
                if let Some(word) = bytes.get(off..end)
                    && let Ok(word_bytes) = <[u8; 4]>::try_from(word)
                {
                    let insn = u32::from_le_bytes(word_bytes);
                    if is_svc(insn) {
                        sites.push(off);
                    }
                }
                off = end;
            }
        }
        if sites.is_empty() {
            let restore = (region.prot | VM_PROT_READ | VM_PROT_EXECUTE) & !VM_PROT_WRITE;
            mprotect_darwin(region, restore)?;
            region.prot = restore;
            continue;
        }

        patched = patched.saturating_add(patch_region_with_veneers(region, guest_base, &sites));
    }
    Ok(patched)
}

/// Per-site veneer size: `str lr; bl shared; ldr lr; b site+4`.
#[cfg(all(target_arch = "aarch64", target_os = "linux"))]
const VENEER_BYTES: usize = 16;

/// How many page slots to probe above/below an RX region for a veneer hub.
#[cfg(all(target_arch = "aarch64", target_os = "linux"))]
const VENEER_PROBE_RADIUS: u64 = 128;

/// Round `len` up to a multiple of `page` (page must be a power of two ≥ 1).
#[cfg(all(target_arch = "aarch64", target_os = "linux"))]
#[inline]
fn align_up_to_page(len: usize, page: usize) -> usize {
    if page <= 1 {
        return len.max(1);
    }
    let mask = page.saturating_sub(1);
    len.saturating_add(mask) & !mask
}

// libgcc / compiler-rt symbol linked on Linux aarch64 toolchains.
#[cfg(all(target_arch = "aarch64", target_os = "linux"))]
unsafe extern "C" {
    fn __clear_cache(start: *mut libc::c_void, end: *mut libc::c_void);
}

/// Opt-in trampoline: `KAKEHASHI_TRAMPOLINE=1|true|yes|on`.
#[cfg(all(target_arch = "aarch64", target_os = "linux"))]
fn trampoline_enabled() -> bool {
    match std::env::var_os("KAKEHASHI_TRAMPOLINE") {
        None => false,
        Some(v) => {
            v == "1"
                || v.eq_ignore_ascii_case("true")
                || v.eq_ignore_ascii_case("yes")
                || v.eq_ignore_ascii_case("on")
        }
    }
}

/// Flush D/I caches after writing executable code (aarch64 requirement).
#[cfg(all(target_arch = "aarch64", target_os = "linux"))]
fn clear_icache(ptr: *mut u8, len: usize) {
    if ptr.is_null() || len == 0 {
        return;
    }
    // SAFETY: range is a live mapping the caller owns and just wrote.
    unsafe {
        let start = ptr.cast::<libc::c_void>();
        let end = ptr.wrapping_add(len).cast::<libc::c_void>();
        __clear_cache(start, end);
    }
}

/// Drop trampoline bookkeeping (owned pages are munmap'd with the address space).
pub fn clear_trampoline_cache() {
    // Veneer hubs live only as `register_owned` mappings; nothing else to clear.
}

/// Patch one RX region: map shared dispatcher + per-site veneers near it.
///
/// Returns the number of sites rewritten (`b veneer` or fallback `brk`).
#[cfg(all(target_arch = "aarch64", target_os = "linux"))]
fn patch_region_with_veneers(
    region: &mut MappedRegion,
    guest_base: u64,
    sites: &[usize],
) -> usize {
    let n_sites = sites.len();
    let Some(hub) = install_veneer_hub(guest_base, region.host_len(), n_sites) else {
        return patch_sites_brk(region, sites);
    };

    let mut patched = 0_usize;
    // SAFETY: hub mapping is RW until we mprotect RX below; length is hub.map_len.
    let slice = unsafe { std::slice::from_raw_parts_mut(hub.ptr, hub.map_len) };

    for (i, &off) in sites.iter().enumerate() {
        let site_va = guest_base.saturating_add(u64::try_from(off).unwrap_or(0));
        let site_ret = site_va.saturating_add(4);
        let veneer_off = hub.veneer0.saturating_add(i.saturating_mul(VENEER_BYTES));
        let veneer_va = hub.base_va.saturating_add(u64::try_from(veneer_off).unwrap_or(0));
        let end = off.saturating_add(4);

        let ok = write_veneer(slice, veneer_off, veneer_va, hub.shared_va, site_ret)
            .and_then(|()| b_encoding(site_va, veneer_va))
            .and_then(|enc| {
                let bytes = region.host_bytes_mut();
                let slot = bytes.get_mut(off..end)?;
                slot.copy_from_slice(&enc.to_le_bytes());
                Some(())
            })
            .is_some();

        if !ok {
            let bytes = region.host_bytes_mut();
            let brk = brk_encoding(BRK_TRAP_IMM).to_le_bytes();
            if let Some(slot) = bytes.get_mut(off..end) {
                slot.copy_from_slice(&brk);
            }
        }
        patched = patched.saturating_add(1);
    }

    // W^X on hub + I-cache; register owned RX.
    let prot_rx = libc::PROT_READ | libc::PROT_EXEC;
    if !crate::host::mprotect(hub.ptr, hub.map_len, prot_rx) {
        let _ = crate::host::munmap(hub.ptr, hub.map_len);
        return patch_sites_brk(region, sites);
    }
    clear_icache(hub.ptr, hub.map_len);
    crate::mem::register_owned(
        hub.base_va,
        hub.ptr,
        hub.map_len,
        VM_PROT_READ | VM_PROT_EXECUTE,
    );

    let restore = (region.prot | VM_PROT_READ | VM_PROT_EXECUTE) & !VM_PROT_WRITE;
    drop(mprotect_darwin(region, restore));
    region.prot = restore;
    let host = region.host_addr();
    let len = region.host_len();
    if let (Ok(base), true) = (usize::try_from(host), len > 0) {
        let p = std::ptr::with_exposed_provenance_mut::<u8>(base);
        clear_icache(p, len);
    }
    patched
}

#[cfg(all(target_arch = "aarch64", target_os = "linux"))]
fn patch_sites_brk(region: &mut MappedRegion, sites: &[usize]) -> usize {
    let mut patched = 0_usize;
    let bytes = region.host_bytes_mut();
    for &off in sites {
        let end = off.saturating_add(4);
        let brk = brk_encoding(BRK_TRAP_IMM).to_le_bytes();
        if let Some(slot) = bytes.get_mut(off..end) {
            slot.copy_from_slice(&brk);
            patched = patched.saturating_add(1);
        }
    }
    let restore = (region.prot | VM_PROT_READ | VM_PROT_EXECUTE) & !VM_PROT_WRITE;
    drop(mprotect_darwin(region, restore));
    region.prot = restore;
    patched
}

/// Shared dispatcher + veneer pool mapping.
#[cfg(all(target_arch = "aarch64", target_os = "linux"))]
struct VeneerHub {
    ptr: *mut u8,
    map_len: usize,
    base_va: u64,
    shared_va: u64,
    veneer0: usize,
}

/// Map RW hub near the RX region (enough room for `n_sites` veneers).
#[cfg(all(target_arch = "aarch64", target_os = "linux"))]
fn install_veneer_hub(region_guest: u64, region_len: usize, n_sites: usize) -> Option<VeneerHub> {
    let region_end = region_guest.saturating_add(u64::try_from(region_len).unwrap_or(0));
    let site_lo = region_guest;
    let site_hi = region_end.saturating_sub(4).max(region_guest);

    let page = crate::host::page_size().unwrap_or(4096);
    let page_u = u64::try_from(page).unwrap_or(4096);
    let code = trampoline_template();
    let veneer0 = code.len().saturating_add(15) & !15_usize;
    let need = veneer0.saturating_add(n_sites.saturating_mul(VENEER_BYTES));
    let map_len = align_up_to_page(need, page).max(page);

    let flags_fixed = libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | crate::host::fixed_map_flag();
    let flags_free = libc::MAP_PRIVATE | libc::MAP_ANONYMOUS;
    let prot_rw = libc::PROT_READ | libc::PROT_WRITE;

    let after0 = region_end.saturating_add(page_u.saturating_sub(1)) & !(page_u.saturating_sub(1));
    let before0 = region_guest.saturating_sub(page_u) & !(page_u.saturating_sub(1));

    for i in 0..VENEER_PROBE_RADIUS {
        let mut candidates = [after0.saturating_add(i.saturating_mul(page_u)), 0_u64];
        if before0 >= i.saturating_mul(page_u) {
            candidates[1] = before0.saturating_sub(i.saturating_mul(page_u));
        }
        for &prefer in &candidates {
            if prefer == 0 {
                continue;
            }
            // Sites must `b` to veneers in this hub; veneers `bl` shared at base.
            if b_encoding(site_lo, prefer).is_none() || b_encoding(site_hi, prefer).is_none() {
                continue;
            }
            if let Some(ptr) =
                crate::host::mmap(Some(prefer), map_len, prot_rw, flags_fixed, -1, 0)
            {
                return init_hub_slice(ptr, map_len, code, veneer0);
            }
        }
    }

    let ptr = crate::host::mmap(None, map_len, prot_rw, flags_free, -1, 0)?;
    let va = crate::host::ptr_addr_u64(ptr);
    if b_encoding(site_lo, va).is_none() || b_encoding(site_hi, va).is_none() {
        let _ = crate::host::munmap(ptr, map_len);
        return None;
    }
    init_hub_slice(ptr, map_len, code, veneer0)
}

#[cfg(all(target_arch = "aarch64", target_os = "linux"))]
fn init_hub_slice(ptr: *mut u8, map_len: usize, code: &[u8], veneer0: usize) -> Option<VeneerHub> {
    // SAFETY: fresh RW mapping of `map_len`.
    let slice = unsafe { std::slice::from_raw_parts_mut(ptr, map_len) };
    if code.len() > slice.len() || veneer0 > slice.len() {
        let _ = crate::host::munmap(ptr, map_len);
        return None;
    }
    slice.fill(0);
    slice.get_mut(..code.len())?.copy_from_slice(code);
    let reloc_off = trampoline_reloc_offset();
    if let Some(slot) = slice.get_mut(reloc_off..reloc_off.saturating_add(8)) {
        slot.copy_from_slice(&trampoline_rust_entry_addr().to_le_bytes());
    } else {
        let _ = crate::host::munmap(ptr, map_len);
        return None;
    }
    let base_va = crate::host::ptr_addr_u64(ptr);
    Some(VeneerHub {
        ptr,
        map_len,
        base_va,
        shared_va: base_va,
        veneer0,
    })
}

/// Emit one veneer: save LR → bl shared → restore LR → b resume.
#[cfg(all(target_arch = "aarch64", target_os = "linux"))]
fn write_veneer(
    slice: &mut [u8],
    veneer_off: usize,
    veneer_va: u64,
    shared_va: u64,
    site_ret: u64,
) -> Option<()> {
    // str x30, [sp, #-16]!
    let str_lr: u32 = 0xf81f_0ffe;
    // ldr x30, [sp], #16
    let ldr_lr: u32 = 0xf841_07fe;
    let bl = bl_encoding(veneer_va.saturating_add(4), shared_va)?;
    let b_back = b_encoding(veneer_va.saturating_add(12), site_ret)?;
    let words = [str_lr, bl, ldr_lr, b_back];
    let end = veneer_off.saturating_add(VENEER_BYTES);
    let slot = slice.get_mut(veneer_off..end)?;
    for (i, w) in words.iter().enumerate() {
        let o = i.saturating_mul(4);
        slot.get_mut(o..o.saturating_add(4))?.copy_from_slice(&w.to_le_bytes());
    }
    Some(())
}

/// Verified aarch64 trampoline (no host-relative BL).
///
/// Layout: code bytes + 8-byte absolute pointer (`kh_trampoline_dispatch`).
#[cfg(all(target_arch = "aarch64", target_os = "linux"))]
fn trampoline_template() -> &'static [u8] {
    TRAMP_BYTES
}

#[cfg(all(target_arch = "aarch64", target_os = "linux"))]
fn trampoline_reloc_offset() -> usize {
    TRAMP_RELOC_OFF
}

#[cfg(all(target_arch = "aarch64", target_os = "linux"))]
#[allow(clippy::as_conversions, function_casts_as_integer)]
fn trampoline_rust_entry_addr() -> u64 {
    u64::try_from(kh_trampoline_dispatch as usize).unwrap_or(0)
}

/// Return value of the trampoline dispatch (x0=retval, x1=error flag).
#[cfg(all(target_arch = "aarch64", target_os = "linux"))]
#[repr(C)]
pub struct TrampRet {
    /// Value for guest `x0`.
    pub retval: u64,
    /// Non-zero → set Darwin carry (error path).
    pub error: u64,
}

/// Called from the guest-mapped trampoline (AAPCS64).
///
/// # Safety
///
/// Caller must preserve guest SIMD/GPRs around the call (veneer trampoline or
/// freestanding NEON shim). Arguments are Darwin BSD syscall registers;
/// `x16` holds the syscall number (or AAPCS 8th arg after the hypercall
/// prologue). May end the current host worker thread on
/// `bsdthread_terminate` (`SYS_exit`, not `pthread_exit`), or `_exit` the
/// process on guest `exit`.
///
/// Prefer [`kh_hypercall_entry`] for freestanding libSystem: that path switches
/// onto a host alt stack first so multi-thread guests never run host Rust on
/// guest worker stacks.
#[cfg(all(target_arch = "aarch64", target_os = "linux"))]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kh_trampoline_dispatch(
    x0: u64,
    x1: u64,
    x2: u64,
    x3: u64,
    x4: u64,
    x5: u64,
    x6: u64,
    x16: u64,
) -> TrampRet {
    let sys_no = u32::try_from(x16 & 0xFFFF_FFFF).unwrap_or(u32::MAX);
    let result = syscall::dispatch(SyscallArgs {
        pc: 0,
        number: sys_no,
        x0,
        x1,
        x2,
        x3,
        x4,
        x5,
        x6,
    });
    if MAX_EVENTS.load(Ordering::Relaxed) != 0 {
        maybe_push_event(0, sys_no, result.name, x0, x1, x2, result.retval, result.error);
    }
    match result.outcome {
        TrapOutcome::Exit { code } => finish_with_exit_code(code),
        TrapOutcome::ThreadExit => {
            // End this host worker only (same as bsdthread_terminate).
            crate::thread::exit_current_guest_worker();
        }
        TrapOutcome::Continue => {}
    }
    TrampRet {
        retval: result.retval.unwrap_or(0),
        error: u64::from(result.error),
    }
}

// Freestanding hypercall entry (`kh_hypercall_entry`):
// Prefer host alt stack (so join/terminate never runs host Rust on a guest
// stack that `pthread_join` may unmap).
//
// **NEON:** Darwin `svc` preserves Q0–Q31. We must too. Any `bl` into Rust/C
// (TLS enter, alt-stack map) clobbers caller-saved SIMD under AAPCS64, so full
// Q0–Q31 + FPCR/FPSR are saved on the *guest* prolog frame *before* any `bl`.
// TRAMP_BYTES still saves around the dispatch body (belt-and-braces).
//
// ABI: x0–x6 + number in x7 → TrampRet in x0/x1.
// Guest frame layout (640 B):
//   [0]   x29,x30
//   [16]  x0,x1  [32] x2,x3  [48] x4,x5  [64] x6,x7
//   [80]  pad
//   [96]  q0..q31 (512 B)
//   [608] fpcr,fpsr
#[cfg(all(target_arch = "aarch64", target_os = "linux"))]
std::arch::global_asm!(
    r#"
    .text
    .align 2
    .global kh_hypercall_entry
    .type kh_hypercall_entry, %function
kh_hypercall_entry:
    // Guest prolog: GPRs + full NEON *before* any bl (NEON must survive host TLS).
    sub sp, sp, #640
    stp x29, x30, [sp, #0]
    stp x0, x1, [sp, #16]
    stp x2, x3, [sp, #32]
    stp x4, x5, [sp, #48]
    stp x6, x7, [sp, #64]
    mov x29, sp
    stp q0, q1, [sp, #96]
    stp q2, q3, [sp, #128]
    stp q4, q5, [sp, #160]
    stp q6, q7, [sp, #192]
    stp q8, q9, [sp, #224]
    stp q10, q11, [sp, #256]
    stp q12, q13, [sp, #288]
    stp q14, q15, [sp, #320]
    stp q16, q17, [sp, #352]
    stp q18, q19, [sp, #384]
    stp q20, q21, [sp, #416]
    stp q22, q23, [sp, #448]
    stp q24, q25, [sp, #480]
    stp q26, q27, [sp, #512]
    stp q28, q29, [sp, #544]
    stp q30, q31, [sp, #576]
    mrs x9, fpcr
    mrs x10, fpsr
    // #608 exceeds signed LDP imm7*8 range (±512); use base+add.
    add x11, sp, #608
    stp x9, x10, [x11]

    // Host glibc TLS *before* alt-stack lookup/alloc (mmap/mutex need host TPIDR).
    bl kh_tls_enter_host
    bl kh_host_alt_sp
    cbz x0, 1f
    mov x9, sp                 // guest prolog frame
    mov sp, x0                 // host alt stack
    ldr x30, [x9, #8]          // reload LR → freestanding thin caller
    // Host frame: [guest_frame, lr]
    stp x9, x30, [sp, #-16]!
    // Reload guest frame ptr / args (enter_host + alt_sp clobbered temps).
    ldr x9, [sp]
    ldp x0, x1, [x9, #16]
    ldp x2, x3, [x9, #32]
    ldp x4, x5, [x9, #48]
    ldp x6, x7, [x9, #64]
    mov x16, x7
    bl kh_neon_tramp_entry
    // Preserve TrampRet (x0/x1) across TLS restore.
    stp x0, x1, [sp, #-16]!
    bl kh_tls_leave_host
    ldp x0, x1, [sp], #16
    ldp x9, x30, [sp], #16
    mov sp, x9
    // Restore guest NEON from prolog (pre-bl snapshot).
    ldp q0, q1, [sp, #96]
    ldp q2, q3, [sp, #128]
    ldp q4, q5, [sp, #160]
    ldp q6, q7, [sp, #192]
    ldp q8, q9, [sp, #224]
    ldp q10, q11, [sp, #256]
    ldp q12, q13, [sp, #288]
    ldp q14, q15, [sp, #320]
    ldp q16, q17, [sp, #352]
    ldp q18, q19, [sp, #384]
    ldp q20, q21, [sp, #416]
    ldp q22, q23, [sp, #448]
    ldp q24, q25, [sp, #480]
    ldp q26, q27, [sp, #512]
    ldp q28, q29, [sp, #544]
    ldp q30, q31, [sp, #576]
    add x11, sp, #608
    ldp x9, x10, [x11]
    msr fpcr, x9
    msr fpsr, x10
    ldr x29, [sp, #0]
    add sp, sp, #640
    ret
1:
    // No alt stack: dispatch on the guest stack (ST / fallback only).
    // Already on host TLS from the enter above.
    ldp x0, x1, [sp, #16]
    ldp x2, x3, [sp, #32]
    ldp x4, x5, [sp, #48]
    ldp x6, x7, [sp, #64]
    mov x16, x7
    // Preserve real LR across the call (still on guest prolog frame).
    ldr x30, [sp, #8]
    bl kh_neon_tramp_entry
    stp x0, x1, [sp, #-16]!
    bl kh_tls_leave_host
    ldp x0, x1, [sp], #16
    // Restore guest NEON from prolog.
    ldp q0, q1, [sp, #96]
    ldp q2, q3, [sp, #128]
    ldp q4, q5, [sp, #160]
    ldp q6, q7, [sp, #192]
    ldp q8, q9, [sp, #224]
    ldp q10, q11, [sp, #256]
    ldp q12, q13, [sp, #288]
    ldp q14, q15, [sp, #320]
    ldp q16, q17, [sp, #352]
    ldp q18, q19, [sp, #384]
    ldp q20, q21, [sp, #416]
    ldp q22, q23, [sp, #448]
    ldp q24, q25, [sp, #480]
    ldp q26, q27, [sp, #512]
    ldp q28, q29, [sp, #544]
    ldp q30, q31, [sp, #576]
    add x11, sp, #608
    ldp x9, x10, [x11]
    msr fpcr, x9
    msr fpsr, x10
    ldp x29, x30, [sp, #0]
    add sp, sp, #640
    ret
    .size kh_hypercall_entry, .-kh_hypercall_entry
    "#
);

// `kh_neon_tramp_entry` + `KH_NEON_TRAMP_VA` (filled by `ensure_neon_tramp`).
#[cfg(all(target_arch = "aarch64", target_os = "linux"))]
std::arch::global_asm!(
    r#"
    .text
    .align 2
    .global kh_neon_tramp_entry
    .type kh_neon_tramp_entry, %function
kh_neon_tramp_entry:
    adrp x17, KH_NEON_TRAMP_VA
    ldr x17, [x17, :lo12:KH_NEON_TRAMP_VA]
    cbz x17, 1f
    br x17
1:
    mov x7, x16
    b kh_trampoline_dispatch
    .size kh_neon_tramp_entry, .-kh_neon_tramp_entry

    .data
    .align 3
    .global KH_NEON_TRAMP_VA
KH_NEON_TRAMP_VA:
    .quad 0
    "#
);

#[cfg(all(target_arch = "aarch64", target_os = "linux"))]
unsafe extern "C" {
    fn kh_hypercall_entry();
    static mut KH_NEON_TRAMP_VA: u64;
}

/// Address of freestanding hypercall entry (alt stack + NEON tramp + dispatch).
#[cfg(all(target_arch = "aarch64", target_os = "linux"))]
#[must_use]
pub fn hypercall_entry_addr() -> u64 {
    ensure_neon_tramp();
    #[allow(clippy::as_conversions, function_casts_as_integer)]
    {
        u64::try_from(kh_hypercall_entry as usize).unwrap_or(0)
    }
}

/// Map TRAMP_BYTES once and publish its VA to `KH_NEON_TRAMP_VA`.
#[cfg(all(target_arch = "aarch64", target_os = "linux"))]
fn ensure_neon_tramp() {
    static ONCE: AtomicU64 = AtomicU64::new(0);
    static LOCK: Mutex<()> = Mutex::new(());

    if ONCE.load(Ordering::Acquire) != 0 {
        return;
    }
    let _g = LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if ONCE.load(Ordering::Acquire) != 0 {
        return;
    }

    let code = trampoline_template();
    let page = crate::host::page_size().unwrap_or(4096);
    let map_len = align_up_to_page(code.len(), page).max(page);
    let flags = libc::MAP_PRIVATE | libc::MAP_ANONYMOUS;
    let prot_rw = libc::PROT_READ | libc::PROT_WRITE;
    let Some(ptr) = crate::host::mmap(None, map_len, prot_rw, flags, -1, 0) else {
        tracing::error!("NEON tramp mmap failed");
        return;
    };
    // SAFETY: fresh RW mapping.
    let slice = unsafe { std::slice::from_raw_parts_mut(ptr, map_len) };
    slice.fill(0);
    if let Some(dst) = slice.get_mut(..code.len()) {
        dst.copy_from_slice(code);
    } else {
        let _ = crate::host::munmap(ptr, map_len);
        return;
    }
    let reloc_off = trampoline_reloc_offset();
    if let Some(slot) = slice.get_mut(reloc_off..reloc_off.saturating_add(8)) {
        slot.copy_from_slice(&trampoline_rust_entry_addr().to_le_bytes());
    } else {
        let _ = crate::host::munmap(ptr, map_len);
        return;
    }
    let prot_rx = libc::PROT_READ | libc::PROT_EXEC;
    if !crate::host::mprotect(ptr, map_len, prot_rx) {
        tracing::error!("NEON tramp mprotect RX failed");
        let _ = crate::host::munmap(ptr, map_len);
        return;
    }
    clear_icache(ptr, map_len);
    let va = crate::host::ptr_addr_u64(ptr);
    // SAFETY: symbol from global_asm; written once under LOCK before guest entry.
    unsafe {
        KH_NEON_TRAMP_VA = va;
    }
    ONCE.store(va, Ordering::Release);
    tracing::info!(va = format_args!("{va:#x}"), "mapped NEON tramp for hypercall");
}

#[cfg(not(all(target_arch = "aarch64", target_os = "linux")))]
#[must_use]
pub fn hypercall_entry_addr() -> u64 {
    0
}

// ── trampoline machine code (verified via rustc/objdump aarch64) ─────────────

/// Offset of the 8-byte absolute `kh_trampoline_dispatch` pointer.
///
/// Layout (see `TRAMP_BYTES`): `bti c` + save GPRs/NEON/FPCR + `blr` dispatch
/// + restore + `ret` + `.quad` reloc @ 0x100.
#[cfg(all(target_arch = "aarch64", target_os = "linux"))]
const TRAMP_RELOC_OFF: usize = 0x100;

/// Exact opcodes from assembled trampoline (`as` / objdump on Linux aarch64).
///
/// Saves **all Q0–Q31 + FPCR/FPSR** around the Rust call: Darwin `svc` preserves
/// SIMD state; compression workers (7zz MT) rely on that. A bare GPR-only
/// trampoline clobbered NEON and faulted under `-mmt>1`.
#[cfg(all(target_arch = "aarch64", target_os = "linux"))]
#[rustfmt::skip]
const TRAMP_BYTES: &[u8] = &[
    0x5f, 0x24, 0x03, 0xd5, 0xff, 0x03, 0x0a, 0xd1, 0xe8, 0x27, 0x00, 0xa9, 0xea, 0x2f, 0x01, 0xa9,
    0xec, 0x37, 0x02, 0xa9, 0xee, 0x3f, 0x03, 0xa9, 0xf1, 0x4b, 0x04, 0xa9, 0xfe, 0x2b, 0x00, 0xf9,
    0x08, 0x44, 0x3b, 0xd5, 0x29, 0x44, 0x3b, 0xd5, 0xe8, 0x27, 0x06, 0xa9, 0xe0, 0x87, 0x03, 0xad,
    0xe2, 0x8f, 0x04, 0xad, 0xe4, 0x97, 0x05, 0xad, 0xe6, 0x9f, 0x06, 0xad, 0xe8, 0xa7, 0x07, 0xad,
    0xea, 0xaf, 0x08, 0xad, 0xec, 0xb7, 0x09, 0xad, 0xee, 0xbf, 0x0a, 0xad, 0xf0, 0xc7, 0x0b, 0xad,
    0xf2, 0xcf, 0x0c, 0xad, 0xf4, 0xd7, 0x0d, 0xad, 0xf6, 0xdf, 0x0e, 0xad, 0xf8, 0xe7, 0x0f, 0xad,
    0xfa, 0xef, 0x10, 0xad, 0xfc, 0xf7, 0x11, 0xad, 0xfe, 0xff, 0x12, 0xad, 0xe7, 0x03, 0x10, 0xaa,
    0x88, 0x04, 0x00, 0x58, 0x00, 0x01, 0x3f, 0xd6, 0x02, 0x42, 0x3b, 0xd5, 0x23, 0x00, 0x80, 0x52,
    0x63, 0x88, 0x63, 0xd3, 0x42, 0x00, 0x23, 0x8a, 0x41, 0x00, 0x00, 0xb4, 0x42, 0x00, 0x03, 0xaa,
    0x02, 0x42, 0x1b, 0xd5, 0xe8, 0x27, 0x46, 0xa9, 0x08, 0x44, 0x1b, 0xd5, 0x29, 0x44, 0x1b, 0xd5,
    0xe0, 0x87, 0x43, 0xad, 0xe2, 0x8f, 0x44, 0xad, 0xe4, 0x97, 0x45, 0xad, 0xe6, 0x9f, 0x46, 0xad,
    0xe8, 0xa7, 0x47, 0xad, 0xea, 0xaf, 0x48, 0xad, 0xec, 0xb7, 0x49, 0xad, 0xee, 0xbf, 0x4a, 0xad,
    0xf0, 0xc7, 0x4b, 0xad, 0xf2, 0xcf, 0x4c, 0xad, 0xf4, 0xd7, 0x4d, 0xad, 0xf6, 0xdf, 0x4e, 0xad,
    0xf8, 0xe7, 0x4f, 0xad, 0xfa, 0xef, 0x50, 0xad, 0xfc, 0xf7, 0x51, 0xad, 0xfe, 0xff, 0x52, 0xad,
    0xfe, 0x2b, 0x40, 0xf9, 0xf1, 0x4b, 0x44, 0xa9, 0xee, 0x3f, 0x43, 0xa9, 0xec, 0x37, 0x42, 0xa9,
    0xea, 0x2f, 0x41, 0xa9, 0xe8, 0x27, 0x40, 0xa9, 0xff, 0x03, 0x0a, 0x91, 0xc0, 0x03, 0x5f, 0xd6,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // reloc .quad @ 0x100
];
/// Installs the `SIGTRAP` handler used by the micro execution backend.
pub fn install_trap_handlers(config: &TrapConfig) -> Result<(), TrapError> {
    MAX_EVENTS.store(
        u64::try_from(config.max_events).unwrap_or(256),
        Ordering::SeqCst,
    );
    syscall::reset_syscall_state(config.max_syscalls);

    #[cfg(not(all(target_arch = "aarch64", target_os = "linux")))]
    {
        let _ = config;
        Err(TrapError::UnsupportedArch)
    }

    #[cfg(all(target_arch = "aarch64", target_os = "linux"))]
    {
        if HANDLER_INSTALLED.swap(true, Ordering::SeqCst) {
            reset_trap_state();
            syscall::reset_syscall_state(config.max_syscalls);
            return Ok(());
        }

        // Guest faults used to leave multi‑MB `core` files in the workspace cwd.
        // Faults go through our handler → `_exit`; disable dumps as belt-and-braces.
        disable_core_dumps();

        // SAFETY: process-wide SIGTRAP / fault handlers with SA_SIGINFO.
        unsafe {
            let mut sa: libc::sigaction = std::mem::zeroed();
            sa.sa_flags = libc::SA_SIGINFO;
            #[allow(clippy::as_conversions, function_casts_as_integer)]
            {
                sa.sa_sigaction = trap_sigaction as *const () as usize;
            }
            libc::sigemptyset(std::ptr::addr_of_mut!(sa.sa_mask));
            if libc::sigaction(libc::SIGTRAP, std::ptr::addr_of!(sa), std::ptr::null_mut()) != 0 {
                HANDLER_INSTALLED.store(false, Ordering::SeqCst);
                return Err(TrapError::SignalSetup(io::Error::last_os_error()));
            }

            // Guest faults: print PC/addr so `kh run` diagnoses unbound GOT / bad heap.
            let mut fault: libc::sigaction = std::mem::zeroed();
            fault.sa_flags = libc::SA_SIGINFO;
            #[allow(clippy::as_conversions, function_casts_as_integer)]
            {
                fault.sa_sigaction = guest_fault_sigaction as *const () as usize;
            }
            libc::sigemptyset(std::ptr::addr_of_mut!(fault.sa_mask));
            for sig in [libc::SIGSEGV, libc::SIGBUS] {
                if libc::sigaction(sig, std::ptr::addr_of!(fault), std::ptr::null_mut()) != 0 {
                    HANDLER_INSTALLED.store(false, Ordering::SeqCst);
                    return Err(TrapError::SignalSetup(io::Error::last_os_error()));
                }
            }
        }
        reset_trap_state();
        Ok(())
    }
}

/// Sets `RLIMIT_CORE` soft+hard to 0 so guest crashes never litter the repo with
/// `core` dumps (we already print a guest fault summary and `_exit`).
#[cfg(all(target_arch = "aarch64", target_os = "linux"))]
fn disable_core_dumps() {
    // SAFETY: process-wide rlimit; best-effort, ignore failure.
    unsafe {
        let lim = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        let _ = libc::setrlimit(libc::RLIMIT_CORE, std::ptr::addr_of!(lim));
    }
}

/// Logs guest `SIGSEGV` / `SIGBUS` (PC, fault address, key regs) then exits.
#[cfg(all(target_arch = "aarch64", target_os = "linux"))]
unsafe extern "C" fn guest_fault_sigaction(
    signo: libc::c_int,
    info: *mut libc::siginfo_t,
    ctx: *mut libc::c_void,
) {
    // May run under guest TPIDR; restore host before formatting / write.
    crate::tls::enter_host_tls();
    let name = match signo {
        libc::SIGSEGV => "SIGSEGV",
        libc::SIGBUS => "SIGBUS",
        _ => "FAULT",
    };
    let mut pc = 0_u64;
    let mut sp = 0_u64;
    let mut x0 = 0_u64;
    let mut x1 = 0_u64;
    let mut x8 = 0_u64;
    let mut x16 = 0_u64;
    let mut lr = 0_u64;
    if !ctx.is_null() {
        // SAFETY: kernel `ucontext_t` for SA_SIGINFO.
        let uctx = unsafe { &*ctx.cast::<libc::ucontext_t>() };
        let m = &uctx.uc_mcontext;
        pc = m.pc;
        sp = m.sp;
        x0 = m.regs[0];
        x1 = m.regs[1];
        x8 = m.regs[8];
        x16 = m.regs[16];
        lr = m.regs[30];
    }
    let addr = if info.is_null() {
        0_u64
    } else {
        // SAFETY: kernel-provided siginfo.
        let p = unsafe { (*info).si_addr() };
        u64::try_from(p.addr()).unwrap_or(0)
    };
    let msg = format!(
        "error: guest {name} pc={pc:#x} addr={addr:#x} sp={sp:#x} lr={lr:#x} \
         x0={x0:#x} x1={x1:#x} x8={x8:#x} x16={x16:#x}\n"
    );
    drop(io::stderr().write_all(msg.as_bytes()));
    // Best-effort: which mapping owns PC / fault address (helps MT diagnosis).
    if let Ok(maps) = std::fs::read_to_string("/proc/self/maps") {
        for &va in &[pc, addr, lr, x16] {
            for line in maps.lines() {
                let Some((range, rest)) = line.split_once(' ') else {
                    continue;
                };
                let Some((a, b)) = range.split_once('-') else {
                    continue;
                };
                let (Ok(lo), Ok(hi)) = (u64::from_str_radix(a, 16), u64::from_str_radix(b, 16))
                else {
                    continue;
                };
                if va >= lo && va < hi {
                    let off = va.saturating_sub(lo);
                    let m = format!("  map {va:#x} = {lo:#x}+{off:#x} {rest}\n");
                    drop(io::stderr().write_all(m.as_bytes()));
                    break;
                }
            }
        }
    }
    drop(io::stderr().flush());
    if TRACE_ON_EXIT.load(Ordering::SeqCst) {
        dump_events_before_exit();
    }
    // SAFETY: hard-stop after unrecoverable guest fault.
    unsafe { libc::_exit(128_i32.saturating_add(signo)) };
}

/// Drains recorded trap events (for `kh trace`).
#[must_use]
pub fn take_trace_events() -> Vec<TrapEvent> {
    EVENTS
        .lock()
        .map(|mut g| std::mem::take(&mut *g))
        .unwrap_or_default()
}

/// Whether the guest requested exit.
#[must_use]
pub fn exit_requested() -> bool {
    EXIT_REQUESTED.load(Ordering::SeqCst)
}

/// Exit code from the last guest `exit` trap.
#[must_use]
pub fn take_exit_code() -> Option<i32> {
    if EXIT_REQUESTED.load(Ordering::SeqCst) {
        Some(EXIT_CODE.load(Ordering::SeqCst))
    } else {
        None
    }
}

/// Resets exit / event state before a new run.
pub fn reset_trap_state() {
    EXIT_REQUESTED.store(false, Ordering::SeqCst);
    EXIT_CODE.store(0, Ordering::SeqCst);
    EVENT_COUNT.store(0, Ordering::SeqCst);
    if let Ok(mut guard) = EVENTS.lock() {
        guard.clear();
    }
}

/// When set, the exit trap prints recorded events to stdout before `_exit`.
pub fn set_trace_on_exit(json: bool) {
    TRACE_ON_EXIT.store(true, Ordering::SeqCst);
    TRACE_JSON.store(json, Ordering::SeqCst);
}

/// Clears the trace-on-exit flag (default for plain `kh run`).
pub fn clear_trace_on_exit() {
    TRACE_ON_EXIT.store(false, Ordering::SeqCst);
    TRACE_JSON.store(false, Ordering::SeqCst);
}

/// Sets the expected guest exit code for the micro gate (`--expect-code`).
pub fn set_expect_code(code: i32) {
    EXPECT_CODE.store(code, Ordering::SeqCst);
}

/// Disables the expect-code gate.
pub fn clear_expect_code() {
    EXPECT_CODE.store(i32::MIN, Ordering::SeqCst);
}

/// Terminates the host process as if the guest called BSD `exit(code)`.
///
/// Used after `LC_MAIN` returns (dyld calls `exit` with `main`'s return value).
/// Honours `--expect-code` and optional trace-on-exit dump.
pub fn finish_with_exit_code(code: i32) -> ! {
    EXIT_CODE.store(code, Ordering::SeqCst);
    EXIT_REQUESTED.store(true, Ordering::SeqCst);
    if TRACE_ON_EXIT.load(Ordering::SeqCst) {
        dump_events_before_exit();
    }
    let expect = EXPECT_CODE.load(Ordering::SeqCst);
    let status = if expect == i32::MIN || expect == code {
        code
    } else {
        let msg = format!("error: guest exit code {code} != expected {expect}\n");
        drop(io::stderr().write_all(msg.as_bytes()));
        1
    };
    // SAFETY: intentional process termination after guest main return / exit.
    unsafe { libc::_exit(status) };
}

#[cfg(all(target_arch = "aarch64", target_os = "linux"))]
unsafe extern "C" fn trap_sigaction(
    signo: libc::c_int,
    _info: *mut libc::siginfo_t,
    ctx: *mut libc::c_void,
) {
    if signo != libc::SIGTRAP || ctx.is_null() {
        return;
    }

    // Guest may have TPIDR_EL0 = guest TSD; restore host TLS before Rust/libc.
    crate::tls::enter_host_tls();

    // SAFETY: kernel provides a valid `ucontext_t` for SA_SIGINFO deliveries.
    let uctx = unsafe { &mut *ctx.cast::<libc::ucontext_t>() };
    let m = &mut uctx.uc_mcontext;
    let pc = m.pc;
    // Only pull the regs dispatch needs; avoid extra loads on the hot path.
    let x0 = m.regs[0];
    let x1 = m.regs[1];
    let x2 = m.regs[2];
    let x3 = m.regs[3];
    let x4 = m.regs[4];
    let x5 = m.regs[5];
    let x6 = m.regs[6];
    let x16 = m.regs[16];

    let sys_no = u32::try_from(x16 & 0xFFFF_FFFF).unwrap_or(u32::MAX);
    let result = syscall::dispatch(SyscallArgs {
        pc,
        number: sys_no,
        x0,
        x1,
        x2,
        x3,
        x4,
        x5,
        x6,
    });

    // Zero-cost when max_events == 0 (plain `kh run`).
    if MAX_EVENTS.load(Ordering::Relaxed) != 0 {
        maybe_push_event(pc, sys_no, result.name, x0, x1, x2, result.retval, result.error);
    }

    if let Some(ret) = result.retval {
        m.regs[0] = ret;
    }
    // Darwin arm64: error → set C; success with write-back → clear C.
    if result.error {
        m.pstate |= PSTATE_C;
    } else if result.retval.is_some() {
        m.pstate &= !PSTATE_C;
    }

    match result.outcome {
        TrapOutcome::Exit { code } => {
            finish_with_exit_code(code);
        }
        TrapOutcome::Continue => {
            m.pc = pc.wrapping_add(4);
            // Return to guest with guest TPIDR restored.
            crate::tls::leave_host_tls();
        }
        TrapOutcome::ThreadExit => {
            // Stay on host TLS; exit trampoline publishes join then pthread_exit.
            // Redirect ucontext to a host `pthread_exit` trampoline on this
            // thread's original stack (see `crate::thread`). Main thread
            // (no host frame) falls back to process exit.
            if !crate::thread::redirect_ucontext_to_host_exit(m) {
                finish_with_exit_code(0);
            }
        }
    }
}

fn dump_events_before_exit() {
    use std::fmt::Write as _;

    let json = TRACE_JSON.load(Ordering::SeqCst);
    let events = EVENTS.lock().map(|g| g.clone()).unwrap_or_default();
    if json {
        let mut out = String::from("{\"events\":[");
        for (i, e) in events.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            let sys = e
                .syscall
                .map_or_else(|| "null".to_owned(), |s| s.to_string());
            let ret = e
                .retval
                .map_or_else(|| "null".to_owned(), |v| v.to_string());
            let _ = write!(
                out,
                "{{\"pc\":{},\"syscall\":{},\"name\":\"{}\",\"arg0\":{},\"arg1\":{},\"arg2\":{},\"retval\":{},\"error\":{}}}",
                e.pc, sys, e.name, e.arg0, e.arg1, e.arg2, ret, e.error
            );
        }
        out.push_str("]}\n");
        drop(io::stdout().write_all(out.as_bytes()));
        drop(io::stdout().flush());
    } else {
        let header = format!("trace events: {}\n", events.len());
        drop(io::stdout().write_all(header.as_bytes()));
        for (i, e) in events.iter().enumerate() {
            let ret = e
                .retval
                .map_or_else(|| "-".to_owned(), |v| format!("{v:#x}"));
            let err = if e.error { " err" } else { "" };
            let line = format!(
                "  [{i}] pc={:#x} {} sys={:?} args=({:#x}, {:#x}, {:#x}) ret={ret}{err}\n",
                e.pc, e.name, e.syscall, e.arg0, e.arg1, e.arg2
            );
            drop(io::stdout().write_all(line.as_bytes()));
        }
        drop(io::stdout().flush());
    }
}

#[cfg(all(target_arch = "aarch64", target_os = "linux"))]
#[allow(clippy::too_many_arguments)]
fn maybe_push_event(
    pc: u64,
    sys_no: u32,
    name: &'static str,
    arg0: u64,
    arg1: u64,
    arg2: u64,
    retval: Option<u64>,
    error: bool,
) {
    let max = MAX_EVENTS.load(Ordering::Relaxed);
    // `kh run` sets max_events=0: single load, no String/Mutex.
    if max == 0 {
        return;
    }
    let n = EVENT_COUNT.fetch_add(1, Ordering::Relaxed);
    if n >= max {
        return;
    }
    if let Ok(mut guard) = EVENTS.lock()
        && u64::try_from(guard.len()).unwrap_or(u64::MAX) < max
    {
        guard.push(TrapEvent {
            pc,
            syscall: Some(sys_no),
            name: name.to_owned(),
            arg0,
            arg1,
            arg2,
            retval,
            error,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_svc_encoding() {
        assert!(is_svc(0xD400_0001));
        let svc80 = 0xD400_0001 | (0x80_u32 << 5);
        assert!(is_svc(svc80));
        assert!(!is_svc(0xD503_201F));
        assert!(!is_svc(brk_encoding(BRK_TRAP_IMM)));
    }

    #[test]
    fn brk_encoding_roundtrip_imm() {
        let enc = brk_encoding(BRK_TRAP_IMM);
        let imm = (enc >> 5) & 0xFFFF;
        assert_eq!(imm, BRK_TRAP_IMM);
    }
}
