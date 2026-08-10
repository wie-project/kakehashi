//! Minimal Darwin-ish process stack bootstrap (argc / argv / env / terminator).

use thiserror::Error;

/// Errors while building a guest stack.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum StackError {
    /// Stack region is too small for the requested argv/env.
    #[error("guest stack too small: need {need} bytes, have {have}")]
    TooSmall {
        /// Required size in bytes.
        need: usize,
        /// Available size in bytes.
        have: usize,
    },

    /// Argument or environment string is not representable.
    #[error("invalid stack string")]
    InvalidString,
}

/// Builds a minimal C-like stack image at the high end of `stack_mem`.
///
/// Layout (low → high addresses toward `sp` growing down):
/// ```text
///   [strings: argv bytes, env bytes]
///   [padding to 16-byte align]
///   argc
///   argv[0..n]
///   NULL
///   envp[0..m]
///   NULL
///   NULL   // empty Apple/aux terminator
/// ```
///
/// Returns the guest stack pointer (16-byte aligned) that should be loaded into
/// `sp` before jumping to the entry point.
pub fn bootstrap_stack(
    stack_mem: &mut [u8],
    stack_guest_base: u64,
    argv: &[&str],
    envp: &[&str],
) -> Result<u64, StackError> {
    if stack_mem.is_empty() {
        return Err(StackError::TooSmall { need: 1, have: 0 });
    }

    // Place strings at the high end, pointers below them.
    let mut cursor = stack_mem.len();
    let mut argv_addrs = Vec::with_capacity(argv.len());
    let mut env_addrs = Vec::with_capacity(envp.len());

    for s in argv.iter().rev() {
        let addr = push_cstr(stack_mem, stack_guest_base, &mut cursor, s)?;
        argv_addrs.push(addr);
    }
    argv_addrs.reverse();

    for s in envp.iter().rev() {
        let addr = push_cstr(stack_mem, stack_guest_base, &mut cursor, s)?;
        env_addrs.push(addr);
    }
    env_addrs.reverse();

    // Align cursor down to 16 bytes for the pointer block.
    cursor &= !0xF;

    // Pointer block size: argc + argv* + NULL + env* + NULL + apple NULL
    let n_ptrs = argv_addrs
        .len()
        .saturating_add(env_addrs.len())
        .saturating_add(4); // argc + argv NULL + env NULL + apple NULL
    let ptr_bytes = n_ptrs.saturating_mul(8);
    let need = ptr_bytes;
    if cursor < need {
        return Err(StackError::TooSmall {
            need: need.saturating_add(stack_mem.len().saturating_sub(cursor)),
            have: stack_mem.len(),
        });
    }
    cursor = cursor.saturating_sub(need);
    // Re-align after subtract.
    cursor &= !0xF;
    // Recompute if alignment ate space — rebuild pointer block at final cursor.
    let ptr_start = cursor;
    let mut off = ptr_start;

    write_u64(stack_mem, off, u64::try_from(argv.len()).unwrap_or(0))?;
    off = off.saturating_add(8);

    for &a in &argv_addrs {
        write_u64(stack_mem, off, a)?;
        off = off.saturating_add(8);
    }
    write_u64(stack_mem, off, 0)?;
    off = off.saturating_add(8);

    for &a in &env_addrs {
        write_u64(stack_mem, off, a)?;
        off = off.saturating_add(8);
    }
    write_u64(stack_mem, off, 0)?;
    off = off.saturating_add(8);

    // Empty Apple vector terminator.
    write_u64(stack_mem, off, 0)?;

    let sp_offset = u64::try_from(ptr_start).map_err(|_| StackError::InvalidString)?;
    Ok(stack_guest_base.saturating_add(sp_offset))
}

fn push_cstr(
    mem: &mut [u8],
    guest_base: u64,
    cursor: &mut usize,
    s: &str,
) -> Result<u64, StackError> {
    let bytes = s.as_bytes();
    let need = bytes.len().saturating_add(1);
    if *cursor < need {
        return Err(StackError::TooSmall {
            need,
            have: *cursor,
        });
    }
    *cursor = cursor.saturating_sub(need);
    let start = *cursor;
    let Some(dst) = mem.get_mut(start..start.saturating_add(need)) else {
        return Err(StackError::InvalidString);
    };
    let Some((last, data)) = dst.split_last_mut() else {
        return Err(StackError::InvalidString);
    };
    if data.len() != bytes.len() {
        return Err(StackError::InvalidString);
    }
    data.copy_from_slice(bytes);
    *last = 0;
    let off = u64::try_from(start).map_err(|_| StackError::InvalidString)?;
    Ok(guest_base.saturating_add(off))
}

fn write_u64(mem: &mut [u8], off: usize, value: u64) -> Result<(), StackError> {
    let end = off.saturating_add(8);
    let Some(slot) = mem.get_mut(off..end) else {
        return Err(StackError::TooSmall {
            need: end,
            have: mem.len(),
        });
    };
    slot.copy_from_slice(&value.to_le_bytes());
    Ok(())
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn stack_has_argc_and_argv0() {
        let mut mem = vec![0_u8; 4096];
        let base = 0x0000_7FF0_0000_0000_u64;
        let sp = bootstrap_stack(&mut mem, base, &["prog", "a"], &[]).expect("stack");
        assert!(sp.is_multiple_of(16));
        assert!(sp >= base);
        assert!(sp < base + 4096);

        let off = usize::try_from(sp - base).unwrap();
        let argc = u64::from_le_bytes(mem.get(off..off + 8).unwrap().try_into().unwrap());
        assert_eq!(argc, 2);
        let argv0_ptr = u64::from_le_bytes(mem.get(off + 8..off + 16).unwrap().try_into().unwrap());
        assert!(argv0_ptr >= base);
        let s_off = usize::try_from(argv0_ptr - base).unwrap();
        assert_eq!(mem.get(s_off..s_off + 4).unwrap(), b"prog");
    }
}
