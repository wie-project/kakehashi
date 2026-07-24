//! Process-wide guest address registry for trap-path validation and dynamic maps.
//!
//! Image and stack regions are registered as **borrowed** (owned by `GuestMemory`
//! / the stack `MappedRegion`). Guest `mmap` (anonymous or file-backed) registers
//! **owned** regions that the registry unmaps on `munmap` / `clear`.

use std::sync::Mutex;

use super::map::{MappedRegion, VM_PROT_READ, VM_PROT_WRITE};

/// One live guest mapping visible to the syscall layer.
#[derive(Debug)]
struct RegRegion {
    /// Guest VA of the mapping base (identity with host in the current model).
    guest_addr: u64,
    /// Host mapping length in bytes.
    len: usize,
    /// Host base pointer.
    ptr: *mut u8,
    /// Darwin `VM_PROT_*` bits.
    prot: u32,
    /// When true, [`clear`] / `munmap` will `munmap` the host pages.
    owned: bool,
}

// SAFETY: registry is process-global and only mutated under the mutex from the
// single guest thread + setup path; pointers uniquely refer to live maps.
unsafe impl Send for RegRegion {}

impl RegRegion {
    /// Exclusive end guest address (`guest_addr + len`), saturating.
    #[must_use]
    fn guest_end(&self) -> u64 {
        self.guest_addr
            .saturating_add(u64::try_from(self.len).unwrap_or(u64::MAX))
    }

    /// Whether `[addr, addr+len)` is fully contained in this region.
    #[must_use]
    fn contains_range(&self, addr: u64, len: usize) -> bool {
        if len == 0 {
            return addr >= self.guest_addr && addr <= self.guest_end();
        }
        let Some(end) = addr.checked_add(u64::try_from(len).unwrap_or(u64::MAX)) else {
            return false;
        };
        addr >= self.guest_addr && end <= self.guest_end()
    }
}

static REGISTRY: Mutex<Vec<RegRegion>> = Mutex::new(Vec::new());

/// Clears the registry. Owned mappings are `munmap`'d; borrowed ones are not.
pub fn clear() {
    if let Ok(mut guard) = REGISTRY.lock() {
        for region in guard.drain(..) {
            if region.owned && !region.ptr.is_null() && region.len > 0 {
                // SAFETY: owned region came from a successful mmap in this process.
                let _ = unsafe { libc::munmap(region.ptr.cast(), region.len) };
            }
        }
    }
}

/// Registers a borrowed region (image / stack). Does not take ownership.
pub fn register_borrowed(region: &MappedRegion) {
    push(RegRegion {
        guest_addr: region.guest_addr,
        len: region.host_len(),
        ptr: host_ptr_from_addr(region.host_addr()),
        prot: region.prot,
        owned: false,
    });
}

/// Registers an owned anonymous mapping created by a guest `mmap`.
pub fn register_owned(guest_addr: u64, ptr: *mut u8, len: usize, prot: u32) {
    push(RegRegion {
        guest_addr,
        len,
        ptr,
        prot,
        owned: true,
    });
}

fn push(region: RegRegion) {
    if let Ok(mut guard) = REGISTRY.lock() {
        guard.push(region);
    }
}

/// True when at least one region is registered (live micro-run path).
#[must_use]
pub fn is_active() -> bool {
    REGISTRY.lock().is_ok_and(|g| !g.is_empty())
}

/// Validates that `[addr, addr+len)` lies in a registered region with the
/// requested access. When the registry is empty (unit tests), returns `true`
/// so pure dispatch tests do not need a full map setup.
#[must_use]
pub fn check_range(addr: u64, len: usize, need_write: bool) -> bool {
    if len == 0 {
        return true;
    }
    if addr == 0 {
        return false;
    }
    let Ok(guard) = REGISTRY.lock() else {
        return false;
    };
    if guard.is_empty() {
        return true;
    }
    for region in guard.iter() {
        if !region.contains_range(addr, len) {
            continue;
        }
        if need_write && region.prot & VM_PROT_WRITE == 0 {
            return false;
        }
        if !need_write && region.prot & (VM_PROT_READ | VM_PROT_WRITE) == 0 {
            // Execute-only or none: still allow read of identity-mapped text for
            // path strings if R is set; require R or W.
            return false;
        }
        // Readable if any of R/W/X is present on Darwin private maps we create
        // with at least one access bit. PROT_NONE fails both.
        if region.prot == 0 {
            return false;
        }
        if !need_write && region.prot & VM_PROT_READ == 0 && region.prot & VM_PROT_WRITE == 0 {
            // X-only: allow reads of code for C-strings in edge cases? Deny.
            return false;
        }
        return true;
    }
    false
}

/// Finds the region that fully contains `[addr, addr+len)`, if any.
#[must_use]
pub fn find_covering(addr: u64, len: usize) -> Option<RegRegionSnapshot> {
    let guard = REGISTRY.lock().ok()?;
    for region in guard.iter() {
        if region.contains_range(addr, len) {
            return Some(RegRegionSnapshot {
                guest_addr: region.guest_addr,
                len: region.len,
                ptr: region.ptr,
                prot: region.prot,
                owned: region.owned,
            });
        }
    }
    None
}

/// Snapshot of a registry entry (no ownership).
#[derive(Debug, Clone, Copy)]
pub struct RegRegionSnapshot {
    /// Guest base.
    pub guest_addr: u64,
    /// Host length.
    pub len: usize,
    /// Host pointer.
    pub ptr: *mut u8,
    /// Darwin prot.
    pub prot: u32,
    /// Owned by registry.
    pub owned: bool,
}

// SAFETY: snapshot is a POD copy of pointers managed under the registry mutex
// during the syscall that uses it.
unsafe impl Send for RegRegionSnapshot {}

/// Updates protection bits on the region covering `addr` (exact base preferred).
pub fn update_prot(addr: u64, len: usize, prot: u32) -> bool {
    let Ok(mut guard) = REGISTRY.lock() else {
        return false;
    };
    for region in guard.iter_mut() {
        if region.contains_range(addr, len) {
            region.prot = prot;
            return true;
        }
    }
    false
}

/// Removes and optionally unmaps an owned region that fully covers the range.
///
/// Returns `true` if a region was removed. Borrowed regions are removed from
/// the registry **without** `munmap` (caller must not free image pages).
pub fn remove_range(addr: u64, len: usize) -> RemoveOutcome {
    let Ok(mut guard) = REGISTRY.lock() else {
        return RemoveOutcome::NotFound;
    };
    let idx = guard.iter().position(|r| r.contains_range(addr, len));
    let Some(i) = idx else {
        return RemoveOutcome::NotFound;
    };
    let region = guard.remove(i);
    if region.owned {
        if !region.ptr.is_null() && region.len > 0 {
            // SAFETY: owned mmap from guest mmap handler.
            let rc = unsafe { libc::munmap(region.ptr.cast(), region.len) };
            if rc != 0 {
                return RemoveOutcome::UnmapFailed;
            }
        }
        RemoveOutcome::Unmapped
    } else {
        // Borrowed: only drop tracking; do not munmap host pages.
        RemoveOutcome::Untracked
    }
}

/// Result of [`remove_range`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemoveOutcome {
    /// No covering region.
    NotFound,
    /// Owned region unmapped successfully.
    Unmapped,
    /// Borrowed region dropped from tracking only.
    Untracked,
    /// `munmap` failed.
    UnmapFailed,
}

fn host_ptr_from_addr(addr: u64) -> *mut u8 {
    let u = usize::try_from(addr).unwrap_or(0);
    std::ptr::with_exposed_provenance_mut(u)
}

/// Serializes tests that mutate the process-wide registry / FD tables.
#[cfg(test)]
pub(crate) fn test_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: Mutex<()> = Mutex::new(());
    LOCK.lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use crate::mem::HostPageSize;
    use crate::mem::map::{VM_PROT_EXECUTE, map_stack};

    #[test]
    fn empty_registry_allows_checks() {
        let _g = test_lock();
        clear();
        assert!(!is_active());
        assert!(check_range(0x1000, 16, false));
    }

    #[test]
    fn stack_region_validates() {
        let _g = test_lock();
        clear();
        let host = HostPageSize::detect().expect("host page");
        let stack = map_stack(host, 64 * 1024).expect("stack");
        register_borrowed(&stack);
        assert!(is_active());
        let base = stack.guest_addr;
        assert!(check_range(base, 64, true));
        assert!(check_range(base, 64, false));
        assert!(!check_range(0, 8, false));
        // Outside mapping.
        let outside = base.wrapping_add(u64::try_from(stack.host_len()).unwrap_or(0));
        assert!(!check_range(outside, 8, false));
        clear();
        drop(stack);
    }

    #[test]
    fn execute_only_not_writable() {
        let _g = test_lock();
        clear();
        let host = HostPageSize::detect().expect("host page");
        let stack = map_stack(host, u64::from(host.bytes())).expect("stack");
        // Re-register with RX only for the test.
        push(RegRegion {
            guest_addr: stack.guest_addr,
            len: stack.host_len(),
            ptr: host_ptr_from_addr(stack.host_addr()),
            prot: VM_PROT_READ | VM_PROT_EXECUTE,
            owned: false,
        });
        assert!(check_range(stack.guest_addr, 8, false));
        assert!(!check_range(stack.guest_addr, 8, true));
        clear();
        drop(stack);
    }
}
