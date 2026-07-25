//! Guest virtual memory backed by host `mmap` / `mprotect` / `munmap`.
//!
//! Mapping policy:
//! - Lengths and host addresses are rounded to the **host** page size.
//! - Preferred guest VAs are tried first (`MAP_FIXED_NOREPLACE` on Linux);
//!   on failure the first region is placed by the kernel and a uniform slide
//!   is applied to the rest.
//! - `__PAGEZERO`-style regions (no access, no file, huge span) are skipped.
//! - File-backed content is copied into private anonymous pages (simpler than
//!   partial-page `MAP_PRIVATE` file maps). Executable pages start RW, then
//!   `mprotect` applies final permissions (W^X friendly).

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::ptr;

use thiserror::Error;

use crate::host;

use super::layout::{HostPageSize, PageLayout};

/// Darwin `VM_PROT_*` bits (same numeric values as XNU).
pub const VM_PROT_READ: u32 = 0x1;
pub const VM_PROT_WRITE: u32 = 0x2;
pub const VM_PROT_EXECUTE: u32 = 0x4;

/// One mapped guest region (host-owned).
#[derive(Debug)]
pub struct MappedRegion {
    /// Segment / region name (for diagnostics).
    pub name: String,
    /// Guest virtual address (preferred + slide).
    pub guest_addr: u64,
    /// Host mapping base pointer.
    ptr: *mut u8,
    /// Host mapping length in bytes (host-page multiple).
    len: usize,
    /// Final protection bits (Darwin `VM_PROT_*`).
    pub prot: u32,
    /// File bytes copied into the mapping (0 for pure BSS / anonymous).
    pub file_bytes: u64,
    /// Virtual size requested by the image (may be smaller than host map).
    pub vmsize: u64,
}

// SAFETY: `MappedRegion` uniquely owns the mapping; the pointer is never shared
// across threads without external synchronization. `Send` is required so
// `GuestMemory` can move between threads before execution starts.
unsafe impl Send for MappedRegion {}

impl MappedRegion {
    /// Host base as a mutable byte slice covering the whole mapping.
    #[must_use]
    pub fn host_bytes_mut(&mut self) -> &mut [u8] {
        // SAFETY: we own this mapping for `len` bytes; it is RW until final
        // protect, and callers only use this before RX mprotect or on RW pages.
        unsafe { std::slice::from_raw_parts_mut(self.ptr, self.len) }
    }

    /// Host base as an immutable byte slice.
    #[must_use]
    pub fn host_bytes(&self) -> &[u8] {
        // SAFETY: mapping is live and owned; length is exact.
        unsafe { std::slice::from_raw_parts(self.ptr, self.len) }
    }

    /// Host virtual address of the mapping base.
    #[must_use]
    pub fn host_addr(&self) -> u64 {
        host::ptr_addr_u64(self.ptr)
    }

    /// Host mapping length.
    #[must_use]
    pub const fn host_len(&self) -> usize {
        self.len
    }
}

impl Drop for MappedRegion {
    fn drop(&mut self) {
        if !self.ptr.is_null() && self.len > 0 {
            if !host::munmap(self.ptr, self.len) {
                tracing::warn!(
                    name = %self.name,
                    len = self.len,
                    "munmap failed during MappedRegion drop"
                );
            }
            self.ptr = ptr::null_mut();
        }
    }
}

/// Request to map one segment-like region from a Mach-O image.
#[derive(Debug, Clone)]
pub struct MapRequest {
    /// Segment name.
    pub name: String,
    /// Preferred guest VA (slide 0).
    pub preferred_va: u64,
    /// Virtual size (`vmsize`).
    pub vmsize: u64,
    /// File offset of the first mapped byte (`fileoff`).
    pub fileoff: u64,
    /// Bytes to load from the file (`filesize`).
    pub filesize: u64,
    /// Initial protection (`initprot`, Darwin bits).
    pub initprot: u32,
    /// Maximum protection (`maxprot`, Darwin bits).
    pub maxprot: u32,
}

impl MapRequest {
    /// True when this region should not be mapped (null-catch / empty).
    #[must_use]
    pub fn should_skip(&self) -> bool {
        if self.vmsize == 0 {
            return true;
        }
        let is_pagezero = self.name == "__PAGEZERO"
            || (self.initprot == 0 && self.fileoff == 0 && self.filesize == 0);
        // PAGEZERO is typically 4 GiB — never materialize it.
        is_pagezero
    }
}

/// Fully mapped guest image address space (slide applied).
#[derive(Debug)]
pub struct GuestMemory {
    regions: Vec<MappedRegion>,
    /// Byte slide applied to preferred guest VAs (`actual = preferred + slide`).
    slide: u64,
    host: HostPageSize,
    preferred_base: u64,
}

/// Errors while mapping guest memory.
#[derive(Debug, Error)]
pub enum MapError {
    /// Invalid argument (zero length, overflow, …).
    #[error("invalid map request: {0}")]
    Invalid(&'static str),

    /// `mmap` / `mprotect` failed.
    #[error("mmap/mprotect failed for {name}: {source}")]
    Sys {
        /// Region name.
        name: String,
        /// Underlying OS error.
        #[source]
        source: std::io::Error,
    },

    /// File I/O while filling a mapping.
    #[error("file I/O while mapping {name}: {source}")]
    File {
        /// Region name.
        name: String,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },

    /// Could not place the image (fixed and slid attempts failed).
    #[error("could not place guest image in host VA space")]
    PlacementFailed,
}

impl GuestMemory {
    /// Maps all non-skipped requests into the host address space.
    ///
    /// Tries preferred addresses first; on failure unmaps and retries with a
    /// kernel-chosen base for the first region and a uniform slide.
    pub fn map_image(
        host: HostPageSize,
        preferred_base: u64,
        requests: &[MapRequest],
        file: &mut File,
    ) -> Result<Self, MapError> {
        let active: Vec<&MapRequest> = requests.iter().filter(|r| !r.should_skip()).collect();
        if active.is_empty() {
            return Ok(Self {
                regions: Vec::new(),
                slide: 0,
                host,
                preferred_base,
            });
        }

        // Attempt 1: preferred VAs (slide = 0).
        match Self::try_map_all(host, preferred_base, 0, &active, file, true) {
            Ok(regions) => {
                return Ok(Self {
                    regions,
                    slide: 0,
                    host,
                    preferred_base,
                });
            }
            Err(err) => {
                tracing::debug!(error = %err, "preferred-base map failed; trying slid placement");
            }
        }

        // Attempt 2: kernel places first region, then fixed relative slide.
        // Identity model: guest VA == host VA after placement.
        let first = active
            .first()
            .copied()
            .ok_or(MapError::Invalid("no active regions"))?;
        let first_map = map_one(host, first, first.preferred_va, file, false)?;
        // Non-fixed map_one sets guest_addr to the host address it received.
        let slide = first_map.guest_addr.wrapping_sub(first.preferred_va);

        let mut regions = vec![first_map];
        for req in active.iter().skip(1) {
            let target = req.preferred_va.wrapping_add(slide);
            match map_one(host, req, target, file, true) {
                Ok(region) => regions.push(region),
                Err(err) => {
                    drop(regions);
                    tracing::debug!(error = %err, "slid fixed map failed");
                    return Err(MapError::PlacementFailed);
                }
            }
        }

        Ok(Self {
            regions,
            slide,
            host,
            preferred_base,
        })
    }

    fn try_map_all(
        host: HostPageSize,
        preferred_base: u64,
        slide: u64,
        active: &[&MapRequest],
        file: &mut File,
        fixed: bool,
    ) -> Result<Vec<MappedRegion>, MapError> {
        let mut regions = Vec::with_capacity(active.len());
        for req in active {
            let target = req.preferred_va.wrapping_add(slide);
            match map_one(host, req, target, file, fixed) {
                Ok(region) => regions.push(region),
                Err(err) => {
                    drop(regions);
                    return Err(err);
                }
            }
        }
        let _ = preferred_base;
        Ok(regions)
    }

    /// Applied slide in bytes.
    #[must_use]
    pub const fn slide(&self) -> u64 {
        self.slide
    }

    /// Preferred base used when planning.
    #[must_use]
    pub const fn preferred_base(&self) -> u64 {
        self.preferred_base
    }

    /// Host page size policy.
    #[must_use]
    pub const fn host(&self) -> HostPageSize {
        self.host
    }

    /// Mapped regions in plan order (skips omitted).
    #[must_use]
    pub fn regions(&self) -> &[MappedRegion] {
        &self.regions
    }

    /// Mutable access to regions (e.g. SVC rewrite before protect).
    pub fn regions_mut(&mut self) -> &mut [MappedRegion] {
        &mut self.regions
    }

    /// Translates a guest VA to a host pointer if it falls in a mapped region.
    #[must_use]
    pub fn guest_to_host(&self, guest_va: u64) -> Option<*const u8> {
        for region in &self.regions {
            let start = region.guest_addr;
            let end = start.saturating_add(region.vmsize);
            if guest_va >= start && guest_va < end {
                let offset = usize::try_from(guest_va.saturating_sub(start)).ok()?;
                if offset >= region.len {
                    return None;
                }
                // SAFETY: offset < len, pointer derived from owned mapping base.
                return Some(unsafe { region.ptr.add(offset) });
            }
        }
        None
    }

    /// Translates guest VA to a mutable host pointer.
    #[must_use]
    pub fn guest_to_host_mut(&mut self, guest_va: u64) -> Option<*mut u8> {
        for region in &mut self.regions {
            let start = region.guest_addr;
            let end = start.saturating_add(region.vmsize);
            if guest_va >= start && guest_va < end {
                let offset = usize::try_from(guest_va.saturating_sub(start)).ok()?;
                if offset >= region.len {
                    return None;
                }
                return Some(unsafe { region.ptr.add(offset) });
            }
        }
        None
    }

    /// Reads a little-endian `u64` from a mapped guest VA.
    #[must_use]
    pub fn read_u64_le(&self, guest_va: u64) -> Option<u64> {
        let mut buf = [0_u8; 8];
        self.read_exact(guest_va, &mut buf)?;
        Some(u64::from_le_bytes(buf))
    }

    /// Writes a little-endian `u64` to a mapped guest VA.
    ///
    /// Caller must ensure the region is writable (`mprotect_rw` if needed).
    pub fn write_u64_le(&mut self, guest_va: u64, value: u64) -> Option<()> {
        self.write_exact(guest_va, &value.to_le_bytes())
    }

    /// Copies `buf.len()` bytes from a mapped guest VA into `buf`.
    pub fn read_exact(&self, guest_va: u64, buf: &mut [u8]) -> Option<()> {
        if buf.is_empty() {
            return Some(());
        }
        for region in &self.regions {
            let start = region.guest_addr;
            let end = start.saturating_add(region.vmsize);
            if guest_va >= start && guest_va < end {
                let offset = usize::try_from(guest_va.saturating_sub(start)).ok()?;
                let need = buf.len();
                let avail = region.len.saturating_sub(offset);
                if need > avail {
                    return None;
                }
                let host = region.host_bytes();
                let src = host.get(offset..offset.saturating_add(need))?;
                buf.copy_from_slice(src);
                return Some(());
            }
        }
        None
    }

    /// Copies `buf` into a mapped guest VA (region must be host-writable).
    pub fn write_exact(&mut self, guest_va: u64, buf: &[u8]) -> Option<()> {
        if buf.is_empty() {
            return Some(());
        }
        for region in &mut self.regions {
            let start = region.guest_addr;
            let end = start.saturating_add(region.vmsize);
            if guest_va >= start && guest_va < end {
                let offset = usize::try_from(guest_va.saturating_sub(start)).ok()?;
                let need = buf.len();
                let avail = region.len.saturating_sub(offset);
                if need > avail {
                    return None;
                }
                let host = region.host_bytes_mut();
                let dst = host.get_mut(offset..offset.saturating_add(need))?;
                dst.copy_from_slice(buf);
                return Some(());
            }
        }
        None
    }

    /// Testing helper: pretends the image was slid by `delta` without remapping.
    ///
    /// Updates [`Self::slide`] and each region's `guest_addr`. Host pointers are
    /// unchanged (identity is intentionally broken). Used by loader unit tests when
    /// true preferred-base collisions are unavailable (macOS `MAP_FIXED` clobbers
    /// blockers). Not for production load paths.
    #[doc(hidden)]
    pub fn test_offset_guest_vas(&mut self, delta: u64) {
        self.slide = self.slide.wrapping_add(delta);
        for region in &mut self.regions {
            region.guest_addr = region.guest_addr.wrapping_add(delta);
        }
    }
}

fn map_one(
    host: HostPageSize,
    req: &MapRequest,
    target_guest: u64,
    file: &mut File,
    fixed: bool,
) -> Result<MappedRegion, MapError> {
    let host_page = host.bytes();
    let map_len_u64 = PageLayout::align_up(req.vmsize, host_page)
        .ok_or(MapError::Invalid("vmsize align overflow"))?;
    let map_len =
        usize::try_from(map_len_u64).map_err(|_| MapError::Invalid("vmsize too large"))?;
    if map_len == 0 {
        return Err(MapError::Invalid("zero map length"));
    }

    let mut flags = libc::MAP_PRIVATE | libc::MAP_ANONYMOUS;
    if fixed {
        flags |= fixed_map_flag();
    }

    // Map RW first so we can fill file content; tighten with mprotect after.
    let prot_rw = libc::PROT_READ | libc::PROT_WRITE;
    let fixed_addr = if fixed { Some(target_guest) } else { None };

    let Some(base) = host::mmap(fixed_addr, map_len, prot_rw, flags, -1, 0) else {
        return Err(MapError::Sys {
            name: req.name.clone(),
            source: std::io::Error::last_os_error(),
        });
    };

    let actual_host = host::ptr_addr_u64(base);
    // For non-fixed maps, guest VA becomes the host address (identity slide).
    let guest_addr = if fixed { target_guest } else { actual_host };

    let mut region = MappedRegion {
        name: req.name.clone(),
        guest_addr,
        ptr: base,
        len: map_len,
        prot: req.initprot,
        file_bytes: 0,
        vmsize: req.vmsize,
    };

    // Copy file-backed bytes into the mapping.
    if req.filesize > 0 {
        let copy_len = usize::try_from(req.filesize.min(req.vmsize))
            .map_err(|_| MapError::Invalid("filesize too large"))?;
        if copy_len > map_len {
            return Err(MapError::Invalid("filesize exceeds map length"));
        }
        file.seek(SeekFrom::Start(req.fileoff))
            .map_err(|source| MapError::File {
                name: req.name.clone(),
                source,
            })?;
        let dst = region.host_bytes_mut();
        let Some(slice) = dst.get_mut(..copy_len) else {
            return Err(MapError::Invalid("copy slice out of range"));
        };
        file.read_exact(slice).map_err(|source| MapError::File {
            name: req.name.clone(),
            source,
        })?;
        region.file_bytes = u64::try_from(copy_len).unwrap_or(0);
    }

    // Apply final protection. Empty initprot → PROT_NONE.
    let host_prot = darwin_to_host_prot(req.initprot);
    if !host::mprotect(base, map_len, host_prot) {
        return Err(MapError::Sys {
            name: req.name.clone(),
            source: std::io::Error::last_os_error(),
        });
    }

    // When fixed, require exact placement.
    if fixed && actual_host != target_guest {
        return Err(MapError::Sys {
            name: req.name.clone(),
            source: std::io::Error::new(
                std::io::ErrorKind::AddrNotAvailable,
                format!("kernel placed map at {actual_host:#x}, wanted {target_guest:#x}"),
            ),
        });
    }

    Ok(region)
}

fn fixed_map_flag() -> libc::c_int {
    host::fixed_map_flag()
}

/// Converts Darwin `VM_PROT_*` to host `PROT_*`.
#[must_use]
pub const fn darwin_to_host_prot(darwin: u32) -> libc::c_int {
    if darwin == 0 {
        return libc::PROT_NONE;
    }
    let mut prot = 0;
    if darwin & VM_PROT_READ != 0 {
        prot |= libc::PROT_READ;
    }
    if darwin & VM_PROT_WRITE != 0 {
        prot |= libc::PROT_WRITE;
    }
    if darwin & VM_PROT_EXECUTE != 0 {
        prot |= libc::PROT_EXEC;
    }
    prot
}

/// Maps an anonymous RW stack region (guest VA == host VA, kernel-chosen).
///
/// `size` is rounded up to the host page size. The returned region's
/// `guest_addr` is the low address of the mapping; the stack pointer should be
/// near `guest_addr + vmsize`.
pub fn map_stack(host: HostPageSize, size: u64) -> Result<MappedRegion, MapError> {
    let host_page = host.bytes();
    let map_len_u64 =
        PageLayout::align_up(size.max(1), host_page).ok_or(MapError::Invalid("stack align"))?;
    let map_len = usize::try_from(map_len_u64).map_err(|_| MapError::Invalid("stack too large"))?;

    let flags = libc::MAP_PRIVATE | libc::MAP_ANONYMOUS;
    let prot = libc::PROT_READ | libc::PROT_WRITE;
    let Some(base) = host::mmap(None, map_len, prot, flags, -1, 0) else {
        return Err(MapError::Sys {
            name: "__STACK".into(),
            source: std::io::Error::last_os_error(),
        });
    };
    Ok(MappedRegion {
        name: "__STACK".into(),
        guest_addr: host::ptr_addr_u64(base),
        ptr: base,
        len: map_len,
        prot: VM_PROT_READ | VM_PROT_WRITE,
        file_bytes: 0,
        vmsize: map_len_u64,
    })
}

/// Temporarily makes a region read/write (for SVC patching).
pub fn mprotect_rw(region: &MappedRegion) -> Result<(), MapError> {
    if host::mprotect(region.ptr, region.len, libc::PROT_READ | libc::PROT_WRITE) {
        Ok(())
    } else {
        Err(MapError::Sys {
            name: region.name.clone(),
            source: std::io::Error::last_os_error(),
        })
    }
}

/// Restores Darwin-derived host protection on a region.
pub fn mprotect_darwin(region: &MappedRegion, darwin_prot: u32) -> Result<(), MapError> {
    let host_prot = darwin_to_host_prot(darwin_prot);
    if host::mprotect(region.ptr, region.len, host_prot) {
        Ok(())
    } else {
        Err(MapError::Sys {
            name: region.name.clone(),
            source: std::io::Error::last_os_error(),
        })
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::io::{Seek, SeekFrom, Write};
    use std::path::PathBuf;

    fn temp_file_with(bytes: &[u8]) -> (File, PathBuf) {
        use std::fs::OpenOptions;
        let path = std::env::temp_dir().join(format!(
            "kh-map-test-{}-{}",
            std::process::id(),
            bytes.len()
        ));
        let mut f = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&path)
            .expect("create temp");
        f.write_all(bytes).expect("write");
        f.seek(SeekFrom::Start(0)).expect("seek");
        (f, path)
    }

    #[test]
    fn skip_pagezero() {
        let req = MapRequest {
            name: "__PAGEZERO".into(),
            preferred_va: 0,
            vmsize: 0x1_0000_0000,
            fileoff: 0,
            filesize: 0,
            initprot: 0,
            maxprot: 0,
        };
        assert!(req.should_skip());
    }

    #[test]
    fn map_anonymous_rw_region() {
        let host = HostPageSize::detect().expect("host page");
        let page = u64::from(host.bytes());
        let payload = b"hello-guest-map";
        let (mut file, path) = temp_file_with(payload);

        // Prefer a high VA; may fail and slide — both OK for this test.
        let preferred = 0x0000_0001_0000_0000_u64;
        let reqs = [MapRequest {
            name: "__TEST".into(),
            preferred_va: preferred,
            vmsize: page,
            fileoff: 0,
            filesize: u64::try_from(payload.len()).unwrap(),
            initprot: VM_PROT_READ | VM_PROT_WRITE,
            maxprot: VM_PROT_READ | VM_PROT_WRITE,
        }];

        let mem = GuestMemory::map_image(host, preferred, &reqs, &mut file).expect("map");
        assert_eq!(mem.regions().len(), 1);
        let region = mem.regions().first().expect("region");
        assert!(region.host_len() >= payload.len());
        let got = region.host_bytes().get(..payload.len()).expect("bytes");
        assert_eq!(got, payload);
        assert_eq!(region.file_bytes, u64::try_from(payload.len()).unwrap());
        drop(mem);
        drop(std::fs::remove_file(path));
    }

    #[test]
    fn prot_conversion() {
        assert_eq!(darwin_to_host_prot(0), libc::PROT_NONE);
        assert_eq!(darwin_to_host_prot(VM_PROT_READ), libc::PROT_READ);
        assert_eq!(
            darwin_to_host_prot(VM_PROT_READ | VM_PROT_EXECUTE),
            libc::PROT_READ | libc::PROT_EXEC
        );
    }
}
