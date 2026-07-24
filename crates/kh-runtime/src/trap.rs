//! Trap backend: rewrite Darwin `svc` to `brk` and dispatch BSD syscalls.
//!
//! Linux aarch64 treats every `svc` as a Linux syscall (number in `x8`), which
//! is incompatible with Darwin (number in `x16`, `svc #0x80`). Guest `svc`
//! instructions are rewritten to `brk #IMM` and handled via `SIGTRAP`.
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

/// Patches every AArch64 `svc` instruction in executable regions to `brk #IMM`.
pub fn patch_svc_to_brk(regions: &mut [MappedRegion]) -> Result<usize, TrapError> {
    let mut patched = 0_usize;
    for region in regions.iter_mut() {
        if region.prot & VM_PROT_EXECUTE == 0 {
            continue;
        }
        mprotect_rw(region)?;
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

        // SAFETY: process-wide SIGTRAP handler with SA_SIGINFO.
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
        }
        reset_trap_state();
        Ok(())
    }
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

    // SAFETY: kernel provides a valid `ucontext_t` for SA_SIGINFO deliveries.
    let uctx = unsafe { &mut *ctx.cast::<libc::ucontext_t>() };
    let m = &mut uctx.uc_mcontext;
    let pc = m.pc;
    let x0 = m.regs[0];
    let x1 = m.regs[1];
    let x2 = m.regs[2];
    let x3 = m.regs[3];
    let x4 = m.regs[4];
    let x5 = m.regs[5];
    let x16 = m.regs[16];

    let sys_no = u32::try_from(x16).unwrap_or(u32::MAX);
    let result = syscall::dispatch(SyscallArgs {
        pc,
        number: sys_no,
        x0,
        x1,
        x2,
        x3,
        x4,
        x5,
    });

    push_event(TrapEvent {
        pc,
        syscall: Some(sys_no),
        name: result.name.to_owned(),
        arg0: x0,
        arg1: x1,
        arg2: x2,
        retval: result.retval,
        error: result.error,
    });

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
fn push_event(event: TrapEvent) {
    let max = MAX_EVENTS.load(Ordering::SeqCst);
    let n = EVENT_COUNT.fetch_add(1, Ordering::SeqCst);
    if n >= max {
        return;
    }
    if let Ok(mut guard) = EVENTS.lock()
        && u64::try_from(guard.len()).unwrap_or(u64::MAX) < max
    {
        guard.push(event);
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
