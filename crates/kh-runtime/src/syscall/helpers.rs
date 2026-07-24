//! Synthetic bottle helpers reached via high `x16` numbers (not real BSD).
//!
//! Used by the license-clean `libSystem` stubs for C functions that are
//! awkward as pure guest assembly (`puts`, minimal `printf`). Guest code is:
//! `movz x16, #HELPER; svc #0x80; ret` with args already in AAPCS64 regs.

use std::io::{self, Write};

use crate::bottle;

use super::common::{EFAULT, EINVAL, SyscallArgs, SyscallResult};

/// Base for Kakehashi host helpers (`'KH' << 16`).
pub(super) const KH_HELPER_BASE: u32 = 0x4B48_0000;

/// `puts(const char *s)` — `x0` = C string.
pub(super) const KH_HELPER_PUTS: u32 = KH_HELPER_BASE | 1;

/// Minimal `printf(const char *fmt, ...)` — `x0` = format string.
///
/// Supports only format strings **without** `%` conversions (writes the format
/// text as-is). Enough for `printf("hello\n")`.
pub(super) const KH_HELPER_PRINTF: u32 = KH_HELPER_BASE | 2;

const CSTR_MAX: usize = 1 << 20;

/// True when `number` is a synthetic bottle helper (not Darwin BSD).
#[must_use]
pub(super) const fn is_helper(number: u32) -> bool {
    number & 0xFFFF_0000 == KH_HELPER_BASE
}

/// Dispatches a bottle helper. Unknown helpers → `EINVAL`.
pub(crate) fn dispatch_helper(args: SyscallArgs) -> SyscallResult {
    match args.number {
        KH_HELPER_PUTS => handle_puts(args),
        KH_HELPER_PRINTF => handle_printf(args),
        _ => SyscallResult::err("kh_helper", EINVAL),
    }
}

fn handle_puts(args: SyscallArgs) -> SyscallResult {
    let name = "puts";
    let Some(s) = bottle::read_c_string(args.x0, CSTR_MAX) else {
        return SyscallResult::err(name, EFAULT);
    };
    let mut out = io::stdout().lock();
    if out.write_all(s.as_bytes()).is_err() || out.write_all(b"\n").is_err() {
        return SyscallResult::err(name, EFAULT);
    }
    // POSIX: non-negative on success (we return the string length + newline).
    let n = s.len().saturating_add(1);
    SyscallResult::ok(name, u64::try_from(n).unwrap_or(0))
}

fn handle_printf(args: SyscallArgs) -> SyscallResult {
    let name = "printf";
    let Some(fmt) = bottle::read_c_string(args.x0, CSTR_MAX) else {
        return SyscallResult::err(name, EFAULT);
    };
    // Minimal: no conversions. Reject '%' so we never silently mis-print.
    if fmt.contains('%') {
        return SyscallResult::err(name, EINVAL);
    }
    let mut out = io::stdout().lock();
    if out.write_all(fmt.as_bytes()).is_err() {
        return SyscallResult::err(name, EFAULT);
    }
    SyscallResult::ok(name, u64::try_from(fmt.len()).unwrap_or(0))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn helper_range() {
        assert!(is_helper(KH_HELPER_PUTS));
        assert!(is_helper(KH_HELPER_PRINTF));
        assert!(!is_helper(4)); // write
        assert!(!is_helper(1)); // exit
    }
}
