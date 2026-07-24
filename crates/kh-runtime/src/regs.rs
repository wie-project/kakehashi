//! Guest AArch64 thread register snapshot (Darwin ABI conventions later).

/// General-purpose and control registers for one guest thread.
///
/// Layout is filled in when micro-execution lands; fields exist so the CLI and
/// loader can share a stable type early.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ThreadRegs {
    /// `x0`–`x30` (LR in `x[30]`).
    pub x: [u64; 31],
    /// Stack pointer.
    pub sp: u64,
    /// Program counter.
    pub pc: u64,
    /// Process state (`PSTATE` / `NZCV` subset as needed later).
    pub pstate: u64,
}

impl ThreadRegs {
    /// Creates a zeroed register file.
    #[inline]
    pub const fn new() -> Self {
        Self {
            x: [0; 31],
            sp: 0,
            pc: 0,
            pstate: 0,
        }
    }
}
