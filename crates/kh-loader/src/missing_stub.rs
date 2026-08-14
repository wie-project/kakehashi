//! Per-import AArch64 trampolines for unresolved strong symbols.
//!
//! Large guests (curl) import more libc surface than freestanding libSystem
//! implements. Binding every miss to the same `_kh_missing_symbol` finishes
//! load but hides *which* import was first called. On Linux aarch64 we emit a
//! small trampoline per unique name that loads the C string and jumps to
//! `_kh_missing_symbol_named` in the bottle.
//!
//! Layout (32-byte header + inline C string, identity-mapped guest VA):
//! ```text
//! +0  LDR X0,  #16     ; name pointer
//! +4  LDR X16, #20     ; handler
//! +8  BR  X16
//! +12 NOP
//! +16 .quad name_va    ; → +32
//! +24 .quad handler
//! +32 .asciz "name"
//! ```

use crate::error::LoadError;

/// Resolve (or create) a trampoline for an unresolved strong import.
///
/// `handler` must be the guest VA of `_kh_missing_symbol_named`. On hosts
/// without the Linux aarch64 emit path, returns `handler` unchanged (caller
/// may fall back to the anonymous missing stub).
pub(crate) fn trampoline_for(name: &str, handler: u64) -> Result<u64, LoadError> {
    if name.is_empty() {
        return Ok(handler);
    }
    linux_aarch64::emit_or_lookup(name, handler)
}

/// Freeze pool RX after bind completes.
pub(crate) fn seal_pool() {
    linux_aarch64::seal_pool();
}

#[cfg(all(target_arch = "aarch64", target_os = "linux"))]
#[allow(unsafe_code)] // mmap + raw write of guest trampoline machine code
mod linux_aarch64 {
    use std::collections::HashMap;
    use std::sync::Mutex;

    use super::LoadError;

    /// Bytes reserved before the C string in each stub slot.
    const HEADER: usize = 32;
    /// Max nlist name length we embed (excluding trailing NUL).
    ///
    /// Curl-era names fit in 96; Apple clang / libc++ mangles go past 100
    /// (e.g. `std::chrono::system_clock::to_time_t` ~109). Cap with headroom
    /// for longer templates; beyond this we fall back to the anonymous stub.
    const MAX_NAME: usize = 256;
    /// Initial pool — clang alone imports hundreds of strong symbols; each
    /// miss needs HEADER + name + NUL (16-byte aligned). 512 KiB covers a
    /// large miss list with long C++ names and still leaves room for deps.
    const POOL_BYTES: usize = 512 * 1024;

    struct Pool {
        base: *mut u8,
        len: usize,
        used: usize,
        /// nlist name → trampoline guest VA (= host address under identity map).
        by_name: HashMap<String, u64>,
        /// Address of `_kh_missing_symbol_named` used when the pool was first filled.
        handler: u64,
        /// True after [`seal_pool`] (RX). Late `dlopen` must unseal to emit.
        sealed: bool,
    }

    // SAFETY: pool is process-local; entries are only written under the mutex and
    // then become immutable RX code/strings for the guest lifetime.
    unsafe impl Send for Pool {}

    static POOL: Mutex<Option<Pool>> = Mutex::new(None);

    pub(super) fn emit_or_lookup(name: &str, handler: u64) -> Result<u64, LoadError> {
        let mut guard = POOL
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if guard.is_none() {
            *guard = Some(alloc_pool(handler)?);
        }
        let pool = guard.as_mut().ok_or(LoadError::NotImplemented(
            "missing-stub pool unavailable after init",
        ))?;
        if pool.handler != handler {
            // Bottle remapped in a new process image — rare mid-session; reset.
            *pool = alloc_pool(handler)?;
        }
        if let Some(&va) = pool.by_name.get(name) {
            return Ok(va);
        }
        let va = emit_one(pool, name, handler)?;
        pool.by_name.insert(name.to_owned(), va);
        Ok(va)
    }

    fn alloc_pool(handler: u64) -> Result<Pool, LoadError> {
        let flags = libc::MAP_PRIVATE | libc::MAP_ANONYMOUS;
        let prot = libc::PROT_READ | libc::PROT_WRITE;
        let Some(base) = kh_runtime::host::mmap(None, POOL_BYTES, prot, flags, -1, 0) else {
            return Err(LoadError::NotImplemented("mmap missing-stub pool failed"));
        };
        Ok(Pool {
            base,
            len: POOL_BYTES,
            used: 0,
            by_name: HashMap::new(),
            handler,
            sealed: false,
        })
    }

    fn unseal(pool: &mut Pool) -> Result<(), LoadError> {
        if !pool.sealed {
            return Ok(());
        }
        if !kh_runtime::host::mprotect(pool.base, pool.len, libc::PROT_READ | libc::PROT_WRITE) {
            return Err(LoadError::NotImplemented(
                "missing-stub pool mprotect RW failed",
            ));
        }
        pool.sealed = false;
        Ok(())
    }

    fn emit_one(pool: &mut Pool, name: &str, handler: u64) -> Result<u64, LoadError> {
        let name_bytes = name.as_bytes();
        if name_bytes.len() > MAX_NAME {
            return Err(LoadError::NotImplemented(
                "missing-stub name longer than MAX_NAME",
            ));
        }
        // Variable slot: header + C string + NUL, rounded up to 16 bytes.
        let raw = HEADER.saturating_add(name_bytes.len()).saturating_add(1);
        let need = raw.saturating_add(15) & !15_usize;
        if pool.used.saturating_add(need) > pool.len {
            return Err(LoadError::NotImplemented("missing-stub pool exhausted"));
        }
        unseal(pool)?;
        // SAFETY: `used..used+need` is within the mapped RW region; exclusive under mutex.
        let slot = unsafe { pool.base.add(pool.used) };
        let slot_va = kh_runtime::host::ptr_addr_u64(slot);
        let name_va = slot_va.wrapping_add(u64::try_from(HEADER).unwrap_or(32));

        // LDR Xt, #imm  (literal): 0x58 | (imm19<<5) | Rt ; imm is signed words from PC.
        // At +0: load name_va from +16 → imm = 4
        // At +4: load handler from +24 → PC=+4, target=+24 → imm = 5
        let ldr_x0 = 0x5800_0000_u32 | (4_u32 << 5);
        let ldr_x16 = 0x5800_0000_u32 | (5_u32 << 5) | 16;
        let br_x16 = 0xD61F_0200_u32; // br x16
        let nop = 0xD503_201F_u32;

        // SAFETY: slot has `need` bytes of writable mapped memory.
        unsafe {
            write_u32(slot, 0, ldr_x0);
            write_u32(slot, 4, ldr_x16);
            write_u32(slot, 8, br_x16);
            write_u32(slot, 12, nop);
            write_u64(slot, 16, name_va);
            write_u64(slot, 24, handler);
            let name_dst = slot.add(HEADER);
            core::ptr::copy_nonoverlapping(name_bytes.as_ptr(), name_dst, name_bytes.len());
            *name_dst.add(name_bytes.len()) = 0;
        }

        pool.used = pool.used.saturating_add(need);
        // Pool stays RW until [`seal_pool`] after bind completes.
        Ok(slot_va)
    }

    pub(super) fn seal_pool() {
        let mut guard = POOL
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(pool) = guard.as_mut() else {
            return;
        };
        if pool.sealed {
            return;
        }
        if kh_runtime::host::mprotect(pool.base, pool.len, libc::PROT_READ | libc::PROT_EXEC) {
            pool.sealed = true;
        } else {
            tracing::warn!("missing-stub pool mprotect RX failed; leaving RW");
        }
    }

    unsafe fn write_u32(base: *mut u8, off: usize, v: u32) {
        // SAFETY: caller guarantees `off..off+4` in mapped slot.
        unsafe {
            base.add(off).cast::<u32>().write_unaligned(v.to_le());
        }
    }

    unsafe fn write_u64(base: *mut u8, off: usize, v: u64) {
        // SAFETY: caller guarantees `off..off+8` in mapped slot.
        unsafe {
            base.add(off).cast::<u64>().write_unaligned(v.to_le());
        }
    }
}

#[cfg(not(all(target_arch = "aarch64", target_os = "linux")))]
mod linux_aarch64 {
    use super::LoadError;

    // Same `Result` shape as the Linux emit path for a uniform caller API.
    #[allow(clippy::unnecessary_wraps)]
    pub(super) fn emit_or_lookup(_name: &str, handler: u64) -> Result<u64, LoadError> {
        // Host is not the Linux aarch64 guest runner; caller falls back.
        Ok(handler)
    }

    pub(super) fn seal_pool() {}
}
