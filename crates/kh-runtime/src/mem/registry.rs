//! Guest address-space tracking for trap-path validation and dynamic maps.
//!
//! [`AddressSpace`] owns the region list for one guest process. Image and stack
//! regions are registered as **borrowed** (owned by `GuestMemory` / the stack
//! `MappedRegion`). Guest `mmap` registers **owned** regions that the space
//! unmaps on `munmap` / `clear`.
//!
//! Trap handlers and BSD syscalls use a process-wide **active** address space
//! installed before guest entry (see [`install_active`] / free-function
//! wrappers). Unit tests can exercise a local [`AddressSpace`] without touching
//! the active slot, or use the wrappers under [`test_lock`].

use std::cell::Cell;
use std::sync::RwLock;

use crate::host;

use super::map::{MappedRegion, VM_PROT_READ, VM_PROT_WRITE};

/// Per-thread last hit for [`check_range`] (archive I/O is highly sequential).
#[derive(Clone, Copy)]
struct RangeCache {
    guest_addr: u64,
    len: usize,
    prot: u32,
}

impl RangeCache {
    fn contains(self, addr: u64, len: usize) -> bool {
        if len == 0 {
            return addr >= self.guest_addr
                && addr
                    <= self
                        .guest_addr
                        .saturating_add(u64::try_from(self.len).unwrap_or(u64::MAX));
        }
        let Some(end) = addr.checked_add(u64::try_from(len).unwrap_or(u64::MAX)) else {
            return false;
        };
        let reg_end = self
            .guest_addr
            .saturating_add(u64::try_from(self.len).unwrap_or(u64::MAX));
        addr >= self.guest_addr && end <= reg_end
    }

    fn allows(self, need_write: bool) -> bool {
        if need_write {
            self.prot & VM_PROT_WRITE != 0
        } else {
            self.prot & (VM_PROT_READ | VM_PROT_WRITE) != 0
        }
    }
}

thread_local! {
    static LAST_RANGE: Cell<Option<RangeCache>> = const { Cell::new(None) };
}

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
    /// When true, [`AddressSpace::clear`] / `munmap` will `munmap` the host pages.
    owned: bool,
}

// SAFETY: regions are only mutated while the owning `AddressSpace` is locked
// (active slot mutex or exclusive local borrow); pointers uniquely refer to
// live maps for the single guest process model.
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

/// Tracked guest VA ranges for one process (borrowed images + owned mmaps).
///
/// Independent of the active trap slot: build and test locally, then
/// [`install_active`] before jumping to guest code.
#[derive(Debug, Default)]
pub struct AddressSpace {
    regions: Vec<RegRegion>,
}

// SAFETY: regions are only mutated under the active write lock; concurrent
// readers only call pure range checks. Raw host pointers are not shared for
// mutation across threads without that lock.
unsafe impl Sync for AddressSpace {}

impl AddressSpace {
    /// Empty address space (no tracked regions).
    #[must_use]
    pub const fn new() -> Self {
        Self {
            regions: Vec::new(),
        }
    }

    /// True when at least one region is registered.
    #[must_use]
    pub fn is_active(&self) -> bool {
        !self.regions.is_empty()
    }

    /// Clears all regions. Owned mappings are `munmap`'d; borrowed ones are not.
    pub fn clear(&mut self) {
        for region in self.regions.drain(..) {
            if region.owned {
                let _ = host::munmap(region.ptr, region.len);
            }
        }
    }

    /// Registers a borrowed region (image / stack). Does not take ownership.
    pub fn register_borrowed(&mut self, region: &MappedRegion) {
        self.regions.push(RegRegion {
            guest_addr: region.guest_addr,
            len: region.host_len(),
            ptr: host_ptr_from_addr(region.host_addr()),
            prot: region.prot,
            owned: false,
        });
    }

    /// Registers an owned mapping created by a guest `mmap`.
    pub fn register_owned(&mut self, guest_addr: u64, ptr: *mut u8, len: usize, prot: u32) {
        self.regions.push(RegRegion {
            guest_addr,
            len,
            ptr,
            prot,
            owned: true,
        });
    }

    /// Validates that `[addr, addr+len)` lies in a registered region with the
    /// requested access. When empty (unit tests without maps), returns `true`
    /// so pure dispatch tests do not need a full map setup.
    #[must_use]
    pub fn check_range(&self, addr: u64, len: usize, need_write: bool) -> bool {
        if len == 0 {
            return true;
        }
        if addr == 0 {
            return false;
        }
        if self.regions.is_empty() {
            return true;
        }
        for region in &self.regions {
            if !region.contains_range(addr, len) {
                continue;
            }
            if need_write {
                return region.prot & VM_PROT_WRITE != 0;
            }
            // Readable if any of R/W is set (writable maps are readable for load).
            return region.prot & (VM_PROT_READ | VM_PROT_WRITE) != 0;
        }
        false
    }

    /// Finds the region that fully contains `[addr, addr+len)`, if any.
    #[must_use]
    pub fn find_covering(&self, addr: u64, len: usize) -> Option<RegRegionSnapshot> {
        for region in &self.regions {
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

    /// Updates protection bits on the region covering `addr`.
    pub fn update_prot(&mut self, addr: u64, len: usize, prot: u32) -> bool {
        for region in &mut self.regions {
            if region.contains_range(addr, len) {
                region.prot = prot;
                return true;
            }
        }
        false
    }

    /// Removes and optionally unmaps an owned region that fully covers the range.
    ///
    /// Borrowed regions are removed from tracking **without** `munmap`.
    pub fn remove_range(&mut self, addr: u64, len: usize) -> RemoveOutcome {
        let idx = self
            .regions
            .iter()
            .position(|r| r.contains_range(addr, len));
        let Some(i) = idx else {
            return RemoveOutcome::NotFound;
        };
        let region = self.regions.remove(i);
        if region.owned {
            if host::munmap(region.ptr, region.len) {
                RemoveOutcome::Unmapped
            } else {
                RemoveOutcome::UnmapFailed
            }
        } else {
            RemoveOutcome::Untracked
        }
    }

    /// Test/helper: push a raw region (used by unit tests for RX-only maps).
    #[cfg(test)]
    fn push_raw(&mut self, region: RegRegion) {
        self.regions.push(region);
    }
}

impl Drop for AddressSpace {
    fn drop(&mut self) {
        self.clear();
    }
}

/// Active address space for the trap / syscall path (single guest process).
///
/// `RwLock`: concurrent `check_range` on the I/O hot path must not serialize
/// all guest threads behind a single exclusive mutex.
static ACTIVE: RwLock<AddressSpace> = RwLock::new(AddressSpace::new());

/// Installs `space` as the active trap-path address space.
///
/// Returns the previous active space (caller may drop it to unmap owned regions).
pub fn install_active(space: AddressSpace) -> AddressSpace {
    match ACTIVE.write() {
        Ok(mut guard) => std::mem::replace(&mut *guard, space),
        Err(poisoned) => {
            let mut guard = poisoned.into_inner();
            std::mem::replace(&mut *guard, space)
        }
    }
}

/// Takes the active address space, leaving an empty one installed.
#[must_use]
pub fn take_active() -> AddressSpace {
    install_active(AddressSpace::new())
}

/// Runs `f` with exclusive access to the active address space.
pub fn with_active_mut<R>(f: impl FnOnce(&mut AddressSpace) -> R) -> R {
    match ACTIVE.write() {
        Ok(mut guard) => f(&mut guard),
        Err(poisoned) => f(&mut poisoned.into_inner()),
    }
}

/// Runs `f` with shared access to the active address space.
pub fn with_active<R>(f: impl FnOnce(&AddressSpace) -> R) -> R {
    match ACTIVE.read() {
        Ok(guard) => f(&guard),
        Err(poisoned) => f(&poisoned.into_inner()),
    }
}

/// Clears the active address space. Owned mappings are `munmap`'d.
pub fn clear() {
    LAST_RANGE.with(|c| c.set(None));
    with_active_mut(AddressSpace::clear);
}

/// Registers a borrowed region on the active address space.
pub fn register_borrowed(region: &MappedRegion) {
    with_active_mut(|space| space.register_borrowed(region));
}

/// Registers an owned anonymous mapping on the active address space.
pub fn register_owned(guest_addr: u64, ptr: *mut u8, len: usize, prot: u32) {
    with_active_mut(|space| space.register_owned(guest_addr, ptr, len, prot));
}

/// True when the active space has at least one region.
#[must_use]
pub fn is_active() -> bool {
    with_active(AddressSpace::is_active)
}

/// Validates a range against the active address space.
///
/// Hot path: thread-local last-hit cache (no `RwLock`) for sequential
/// read/write into the same mapping.
#[must_use]
pub fn check_range(addr: u64, len: usize, need_write: bool) -> bool {
    if len == 0 {
        return true;
    }
    if addr == 0 {
        return false;
    }
    if LAST_RANGE.with(|c| {
        c.get()
            .is_some_and(|r| r.contains(addr, len) && r.allows(need_write))
    }) {
        return true;
    }
    with_active(|space| {
        if space.regions.is_empty() {
            return true;
        }
        for region in &space.regions {
            if !region.contains_range(addr, len) {
                continue;
            }
            let ok = if need_write {
                region.prot & VM_PROT_WRITE != 0
            } else {
                region.prot & (VM_PROT_READ | VM_PROT_WRITE) != 0
            };
            if ok {
                LAST_RANGE.with(|c| {
                    c.set(Some(RangeCache {
                        guest_addr: region.guest_addr,
                        len: region.len,
                        prot: region.prot,
                    }));
                });
            }
            return ok;
        }
        false
    })
}

/// Finds a covering region in the active address space.
#[must_use]
pub fn find_covering(addr: u64, len: usize) -> Option<RegRegionSnapshot> {
    with_active(|space| space.find_covering(addr, len))
}

/// Updates protection on a region in the active address space.
pub fn update_prot(addr: u64, len: usize, prot: u32) -> bool {
    with_active_mut(|space| space.update_prot(addr, len, prot))
}

/// Removes a range from the active address space.
pub fn remove_range(addr: u64, len: usize) -> RemoveOutcome {
    with_active_mut(|space| space.remove_range(addr, len))
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
    /// Owned by the address space.
    pub owned: bool,
}

// SAFETY: snapshot is a POD copy of pointers managed under the active mutex
// during the syscall that uses it.
unsafe impl Send for RegRegionSnapshot {}

/// Result of [`AddressSpace::remove_range`] / [`remove_range`].
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

/// Serializes tests that mutate process-wide active space / process state.
#[cfg(test)]
pub(crate) fn test_lock() -> std::sync::MutexGuard<'static, ()> {
    crate::process::test_lock()
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use crate::mem::HostPageSize;
    use crate::mem::map::{VM_PROT_EXECUTE, map_stack};

    #[test]
    fn empty_local_space_allows_checks() {
        let space = AddressSpace::new();
        assert!(!space.is_active());
        assert!(space.check_range(0x1000, 16, false));
    }

    #[test]
    fn empty_active_registry_allows_checks() {
        let _g = test_lock();
        clear();
        assert!(!is_active());
        assert!(check_range(0x1000, 16, false));
    }

    #[test]
    fn local_stack_region_validates() {
        let host = HostPageSize::detect().expect("host page");
        let stack = map_stack(host, 64 * 1024).expect("stack");
        let mut space = AddressSpace::new();
        space.register_borrowed(&stack);
        assert!(space.is_active());
        let base = stack.guest_addr;
        assert!(space.check_range(base, 64, true));
        assert!(space.check_range(base, 64, false));
        assert!(!space.check_range(0, 8, false));
        let outside = base.wrapping_add(u64::try_from(stack.host_len()).unwrap_or(0));
        assert!(!space.check_range(outside, 8, false));
        space.clear();
        drop(stack);
    }

    #[test]
    fn stack_region_validates_via_active() {
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
        let outside = base.wrapping_add(u64::try_from(stack.host_len()).unwrap_or(0));
        assert!(!check_range(outside, 8, false));
        clear();
        drop(stack);
    }

    #[test]
    fn execute_only_not_writable() {
        let host = HostPageSize::detect().expect("host page");
        let stack = map_stack(host, u64::from(host.bytes())).expect("stack");
        let mut space = AddressSpace::new();
        space.push_raw(RegRegion {
            guest_addr: stack.guest_addr,
            len: stack.host_len(),
            ptr: host_ptr_from_addr(stack.host_addr()),
            prot: VM_PROT_READ | VM_PROT_EXECUTE,
            owned: false,
        });
        assert!(space.check_range(stack.guest_addr, 8, false));
        assert!(!space.check_range(stack.guest_addr, 8, true));
        space.clear();
        drop(stack);
    }

    #[test]
    fn install_active_swaps_spaces() {
        let _g = test_lock();
        clear();
        let host = HostPageSize::detect().expect("host page");
        let stack = map_stack(host, 64 * 1024).expect("stack");
        let mut space = AddressSpace::new();
        space.register_borrowed(&stack);
        let prev = install_active(space);
        assert!(!prev.is_active());
        assert!(is_active());
        assert!(check_range(stack.guest_addr, 8, false));
        let taken = take_active();
        assert!(taken.is_active());
        assert!(!is_active());
        drop(taken);
        drop(stack);
    }
}
