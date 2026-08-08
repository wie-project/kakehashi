//! Guest virtual memory backed by host `mmap` / `mprotect` / `munmap`.
//!
//! Mapping policy:
//! - Lengths and host addresses are rounded to the **host** page size.
//! - Preferred guest VAs are tried first (`MAP_FIXED_NOREPLACE` on Linux).
//! - On failure, a **contiguous host span** covering the whole image is
//!   reserved, a uniform slide is derived, and each segment is placed with
//!   `MAP_FIXED` inside that span. (Placing only the first segment free and
//!   then `MAP_FIXED_NOREPLACE` neighbours fails on Linux when ASLR put the
//!   first mapping next to another VMA — common for preferred base `0` dylibs.)
//! - `__PAGEZERO`-style regions (no access, no file, huge span) are skipped.
//! - File-backed content: **host-page-aligned** full segments map the file
//!   once with final prot (no anon+overlay, no bulk I-cache flush). Partial
//!   edge pages still copy into an anon map. BSS beyond `filesize` stays
//!   anonymous zeros. Interiors that are only page-aligned still use
//!   `MAP_PRIVATE` file remap over anon (CoW on first write).
//! - I-cache flush only after **userspace stores** into RX (edge fills /
//!   residual `svc`→`brk` patches) — pure file maps stay demand-paged.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::os::fd::AsRawFd;
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
    /// Relative `(offset, len)` within [`Self::file_bytes`] for residual `svc`
    /// scan (instruction sections). Empty → scan whole `file_bytes`.
    pub svc_scan_ranges: Vec<(u64, u64)>,
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
    /// Relative `(offset, len)` ranges within mapped file content to scan for
    /// residual Darwin `svc` (instruction sections only).
    ///
    /// Empty → trap backend falls back to the whole `filesize` span (fixtures
    /// without section flags, or unknown layout).
    pub svc_scan_ranges: Vec<(u64, u64)>,
}

impl MapRequest {
    /// True when this region should not be mapped (null-catch / empty).
    #[must_use]
    pub fn should_skip(&self) -> bool {
        if self.vmsize == 0 {
            return true;
        }
        // PAGEZERO is typically 4 GiB — never materialize it.
        self.name == "__PAGEZERO"
            || (self.initprot == 0 && self.fileoff == 0 && self.filesize == 0)
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

/// Upper bound on a single slid reservation (guards sparse / pathological layouts).
const MAX_SLIDE_SPAN: u64 = 512 * 1024 * 1024; // 512 MiB

impl GuestMemory {
    /// Maps all non-skipped requests into the host address space.
    ///
    /// Tries preferred addresses first; on failure reserves a contiguous host
    /// span for the whole image and places each segment with a uniform slide
    /// (guest VA == host VA after placement).
    pub fn map_image(
        host: HostPageSize,
        preferred_base: u64,
        requests: &[MapRequest],
        file: &mut File,
    ) -> Result<Self, MapError> {
        let mut src = SegmentSource::File(file);
        Self::map_image_with(host, preferred_base, requests, &mut src)
    }

    /// Like [`Self::map_image`], but fills segments from an in-memory container
    /// (same bytes already read for Mach-O parse). Avoids a second disk pass
    /// for large tools (any guest, not tool-specific).
    pub fn map_image_bytes(
        host: HostPageSize,
        preferred_base: u64,
        requests: &[MapRequest],
        bytes: &[u8],
    ) -> Result<Self, MapError> {
        let mut src = SegmentSource::Bytes(bytes);
        Self::map_image_with(host, preferred_base, requests, &mut src)
    }

    fn map_image_with(
        host: HostPageSize,
        preferred_base: u64,
        requests: &[MapRequest],
        src: &mut SegmentSource<'_>,
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

        // Attempt 1: preferred VAs (slide = 0, never clobber host maps).
        match Self::try_map_all(host, preferred_base, 0, &active, src, FixedMode::NoReplace) {
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

        // Attempt 2: reserve full image span, slide every segment into it.
        match Self::try_map_slid_reserved(host, preferred_base, &active, src) {
            Ok(mem) => return Ok(mem),
            Err(err) => {
                tracing::debug!(error = %err, "reserved-span slid map failed; trying first-region slide");
            }
        }

        // Attempt 3 (legacy): free-place first region, fixed-relative rest.
        // Works when the image is a single segment or the kernel left a hole.
        Self::try_map_slid_first_region(host, preferred_base, &active, src)
    }

    /// Kernel-chosen contiguous span for the whole image, then `MAP_FIXED` each segment.
    fn try_map_slid_reserved(
        host: HostPageSize,
        preferred_base: u64,
        active: &[&MapRequest],
        src: &mut SegmentSource<'_>,
    ) -> Result<Self, MapError> {
        let (span_lo, span_hi) = image_preferred_span(host, active)?;
        let span_len_u64 = span_hi.saturating_sub(span_lo);
        if span_len_u64 == 0 {
            return Err(MapError::Invalid("empty image span"));
        }
        if span_len_u64 > MAX_SLIDE_SPAN {
            return Err(MapError::Invalid(
                "image span too large for slid reservation",
            ));
        }
        let span_len =
            usize::try_from(span_len_u64).map_err(|_| MapError::Invalid("span too large"))?;

        // Reserve with PROT_NONE so the VA range cannot be stolen before we carve it.
        let flags = libc::MAP_PRIVATE | libc::MAP_ANONYMOUS;
        let Some(reserve_ptr) = host::mmap(None, span_len, libc::PROT_NONE, flags, -1, 0) else {
            return Err(MapError::Sys {
                name: "__RESERVE".into(),
                source: std::io::Error::last_os_error(),
            });
        };
        let reserve_base = host::ptr_addr_u64(reserve_ptr);
        let slide = reserve_base.wrapping_sub(span_lo);

        tracing::debug!(
            span_lo = format_args!("{span_lo:#x}"),
            span_hi = format_args!("{span_hi:#x}"),
            reserve = format_args!("{reserve_base:#x}"),
            slide = format_args!("{slide:#x}"),
            "reserved contiguous host span for slid image"
        );

        // Carve segments with MAP_FIXED (replaces PROT_NONE pages in place).
        match Self::try_map_all(
            host,
            preferred_base,
            slide,
            active,
            src,
            FixedMode::Replace,
        ) {
            Ok(regions) => {
                // Carve-outs leave PROT_NONE residue in gaps; release it so the
                // address space does not retain untracked maps.
                unmap_span_gaps(reserve_base, span_len_u64, &regions);
                Ok(Self {
                    regions,
                    slide,
                    host,
                    preferred_base,
                })
            }
            Err(err) => {
                // Successful segment maps were already dropped by `try_map_all`.
                // Drop any leftover PROT_NONE from the original reservation.
                // (May no-op for ranges already replaced+dropped.)
                let _ = host::munmap(reserve_ptr, span_len);
                Err(err)
            }
        }
    }

    /// Free-place the first region; map the rest at preferred + slide (fixed, no-replace).
    fn try_map_slid_first_region(
        host: HostPageSize,
        preferred_base: u64,
        active: &[&MapRequest],
        src: &mut SegmentSource<'_>,
    ) -> Result<Self, MapError> {
        let first = active
            .first()
            .copied()
            .ok_or(MapError::Invalid("no active regions"))?;
        let first_map = map_one(host, first, first.preferred_va, src, FixedMode::Free)?;
        let slide = first_map.guest_addr.wrapping_sub(first.preferred_va);

        let mut regions = vec![first_map];
        for req in active.iter().skip(1) {
            let target = req.preferred_va.wrapping_add(slide);
            match map_one(host, req, target, src, FixedMode::NoReplace) {
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
        src: &mut SegmentSource<'_>,
        fixed: FixedMode,
    ) -> Result<Vec<MappedRegion>, MapError> {
        let mut regions = Vec::with_capacity(active.len());
        for req in active {
            let target = req.preferred_va.wrapping_add(slide);
            match map_one(host, req, target, src, fixed) {
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

    /// Reads a little-endian `u32` from a mapped guest VA.
    #[must_use]
    pub fn read_u32_le(&self, guest_va: u64) -> Option<u32> {
        let mut buf = [0_u8; 4];
        self.read_exact(guest_va, &mut buf)?;
        Some(u32::from_le_bytes(buf))
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

/// How to place a single region relative to a preferred / slid guest VA.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FixedMode {
    /// Kernel chooses address (`guest_addr` becomes host base).
    Free,
    /// Fixed address; do not clobber existing maps (`MAP_FIXED_NOREPLACE` on Linux).
    NoReplace,
    /// Fixed address; replace any mapping already at that VA (`MAP_FIXED`).
    /// Used after a PROT_NONE span reservation so carve-outs succeed.
    Replace,
}

/// Where segment file content comes from (disk or already-read container).
enum SegmentSource<'a> {
    File(&'a mut File),
    Bytes(&'a [u8]),
}

impl SegmentSource<'_> {
    fn copy_into(
        &mut self,
        fileoff: u64,
        dst: &mut [u8],
        region_name: &str,
    ) -> Result<(), MapError> {
        match self {
            SegmentSource::File(file) => {
                file.seek(SeekFrom::Start(fileoff))
                    .map_err(|source| MapError::File {
                        name: region_name.to_owned(),
                        source,
                    })?;
                file.read_exact(dst).map_err(|source| MapError::File {
                    name: region_name.to_owned(),
                    source,
                })
            }
            SegmentSource::Bytes(bytes) => {
                let start = usize::try_from(fileoff).map_err(|_| MapError::Invalid("fileoff"))?;
                let end = start
                    .checked_add(dst.len())
                    .ok_or(MapError::Invalid("file range overflow"))?;
                let Some(src) = bytes.get(start..end) else {
                    return Err(MapError::Invalid("fileoff past container end"));
                };
                dst.copy_from_slice(src);
                Ok(())
            }
        }
    }
}

fn map_one(
    host: HostPageSize,
    req: &MapRequest,
    target_guest: u64,
    src: &mut SegmentSource<'_>,
    mode: FixedMode,
) -> Result<MappedRegion, MapError> {
    let host_page = host.bytes();
    let map_len_u64 = PageLayout::align_up(req.vmsize, host_page)
        .ok_or(MapError::Invalid("vmsize align overflow"))?;
    let map_len =
        usize::try_from(map_len_u64).map_err(|_| MapError::Invalid("vmsize too large"))?;
    if map_len == 0 {
        return Err(MapError::Invalid("zero map length"));
    }

    let fixed = matches!(mode, FixedMode::NoReplace | FixedMode::Replace);
    let fixed_addr = if fixed { Some(target_guest) } else { None };

    // Fast path: whole host map is one host-page-aligned file image.
    // CLT tools (clang __TEXT ~100+ MiB) hit this — avoid anon+overlay and
    // bulk I-cache flush so the guest stays demand-paged until first use.
    if let SegmentSource::File(file) = src
        && let Some(region) =
            try_map_pure_file(host, req, target_guest, file, mode, map_len, fixed)
    {
        return Ok(region);
    }

    let mut flags = libc::MAP_PRIVATE | libc::MAP_ANONYMOUS;
    match mode {
        FixedMode::Free => {}
        FixedMode::NoReplace => flags |= host::fixed_map_flag(),
        FixedMode::Replace => flags |= libc::MAP_FIXED,
    }

    // Map RW first so we can fill file content; tighten with mprotect after.
    let prot_rw = libc::PROT_READ | libc::PROT_WRITE;

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
        svc_scan_ranges: req.svc_scan_ranges.clone(),
    };

    // True when userspace stores wrote instruction (or any) bytes into the map.
    let mut dirtied = false;

    // Fill file-backed bytes: prefer page-aligned file MAP_PRIVATE (any guest).
    if req.filesize > 0 {
        let copy_len = usize::try_from(req.filesize.min(req.vmsize))
            .map_err(|_| MapError::Invalid("filesize too large"))?;
        if copy_len > map_len {
            return Err(MapError::Invalid("filesize exceeds map length"));
        }
        let fill = match src {
            SegmentSource::File(file) => fill_segment_file(
                file,
                base,
                map_len,
                req.fileoff,
                copy_len,
                host_page,
                &req.name,
            )?,
            SegmentSource::Bytes(bytes) => {
                fill_segment_bytes(bytes, base, map_len, req.fileoff, copy_len, host_page)?
            }
        };
        if fill.ok {
            dirtied = fill.dirtied;
        } else {
            let dst = region.host_bytes_mut();
            let Some(slice) = dst.get_mut(..copy_len) else {
                return Err(MapError::Invalid("copy slice out of range"));
            };
            src.copy_into(req.fileoff, slice, &req.name)?;
            dirtied = true;
        }
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

    // aarch64: only flush after userspace wrote executable bytes. Pure file
    // MAP_PRIVATE overlays leave D/I coherent for demand faults; flushing a
    // 100+ MiB TEXT forced every page into RSS at load (any large guest).
    if dirtied && req.initprot & VM_PROT_EXECUTE != 0 {
        let flush_len = if region.file_bytes == 0 {
            let page = usize::try_from(host_page).unwrap_or(4096);
            map_len.min(page).max(4)
        } else {
            usize::try_from(region.file_bytes)
                .unwrap_or(0)
                .min(map_len)
                .max(4)
        };
        clear_icache(base, flush_len);
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

/// Map a whole segment as one `MAP_PRIVATE` file image with final prot.
///
/// Requires host-page-aligned `fileoff`, file bytes covering the full host map
/// length (no BSS tail), and fixed guest VA page-aligned when fixed.
fn try_map_pure_file(
    host: HostPageSize,
    req: &MapRequest,
    target_guest: u64,
    file: &File,
    mode: FixedMode,
    map_len: usize,
    fixed: bool,
) -> Option<MappedRegion> {
    let host_page = u64::from(host.bytes());
    if host_page == 0 {
        return None;
    }
    let copy_u64 = req.filesize.min(req.vmsize);
    if copy_u64 == 0 {
        return None;
    }
    let Ok(copy_len) = usize::try_from(copy_u64) else {
        return None;
    };
    // Full host mapping must be file-backed (no zero tail beyond filesize).
    if copy_len != map_len {
        return None;
    }
    if !req.fileoff.is_multiple_of(host_page) {
        return None;
    }
    if fixed && !target_guest.is_multiple_of(host_page) {
        return None;
    }

    let mut flags = libc::MAP_PRIVATE;
    match mode {
        FixedMode::Free => {}
        FixedMode::NoReplace => flags |= host::fixed_map_flag(),
        FixedMode::Replace => flags |= libc::MAP_FIXED,
    }
    let host_prot = darwin_to_host_prot(req.initprot);
    let fixed_addr = if fixed { Some(target_guest) } else { None };
    let fd = file.as_raw_fd();
    let Ok(file_off) = i64::try_from(req.fileoff) else {
        return None;
    };
    let Some(base) = host::mmap(fixed_addr, map_len, host_prot, flags, fd, file_off) else {
        // Preferred-base collision etc. — caller falls back to anon+fill.
        return None;
    };
    let actual_host = host::ptr_addr_u64(base);
    if fixed && actual_host != target_guest {
        let _ = host::munmap(base, map_len);
        return None;
    }
    let guest_addr = if fixed { target_guest } else { actual_host };
    Some(MappedRegion {
        name: req.name.clone(),
        guest_addr,
        ptr: base,
        len: map_len,
        prot: req.initprot,
        file_bytes: copy_u64,
        vmsize: req.vmsize,
        svc_scan_ranges: req.svc_scan_ranges.clone(),
    })
}

/// Read `dst.len()` bytes from `file` at absolute `off`.
fn read_file_range(file: &File, off: u64, dst: &mut [u8], name: &str) -> Result<(), MapError> {
    let mut clone = file.try_clone().map_err(|source| MapError::File {
        name: name.to_owned(),
        source,
    })?;
    clone
        .seek(SeekFrom::Start(off))
        .map_err(|source| MapError::File {
            name: name.to_owned(),
            source,
        })?;
    clone.read_exact(dst).map_err(|source| MapError::File {
        name: name.to_owned(),
        source,
    })
}

/// Result of filling a segment mapping from file or bytes.
struct FillOutcome {
    /// Fill completed (false → caller should fall back to full `copy_into`).
    ok: bool,
    /// Userspace stores touched the mapping (edge copies / memcpy).
    dirtied: bool,
}

/// Fill `[0, copy_len)` of an anonymous mapping from a host file.
///
/// Host-page-aligned interior is remapped `MAP_PRIVATE` from the file (no
/// full-TEXT `memcpy`). Partial edge pages are still copied.
fn fill_segment_file(
    file: &File,
    base: *mut u8,
    map_len: usize,
    fileoff: u64,
    copy_len: usize,
    host_page: u32,
    name: &str,
) -> Result<FillOutcome, MapError> {
    let page = u64::from(host_page);
    if page == 0 || copy_len == 0 || copy_len > map_len {
        return Ok(FillOutcome {
            ok: false,
            dirtied: false,
        });
    }

    let content_lo = fileoff;
    let content_hi = fileoff.saturating_add(u64::try_from(copy_len).unwrap_or(0));
    // Full host pages strictly inside [content_lo, content_hi).
    let aligned_lo = content_lo.div_ceil(page).saturating_mul(page);
    let aligned_hi = content_hi
        .checked_div(page)
        .unwrap_or(0)
        .saturating_mul(page);

    // Mapping-relative offsets.
    let lead = usize::try_from(aligned_lo.saturating_sub(content_lo)).unwrap_or(0);
    let trail_off = usize::try_from(aligned_hi.saturating_sub(content_lo)).unwrap_or(0);
    let mut dirtied = false;

    // Interior: file-backed MAP_PRIVATE (kernel page cache / CoW).
    if aligned_hi > aligned_lo {
        let mid_len = usize::try_from(aligned_hi.saturating_sub(aligned_lo)).unwrap_or(0);
        if mid_len == 0 || lead.saturating_add(mid_len) > map_len {
            return Ok(FillOutcome {
                ok: false,
                dirtied: false,
            });
        }
        // SAFETY: dest is within the anon mapping we just created.
        let dest = unsafe { base.add(lead) };
        let fd = file.as_raw_fd();
        let flags = libc::MAP_PRIVATE | libc::MAP_FIXED;
        let Some(mapped) = host::mmap(
            Some(host::ptr_addr_u64(dest)),
            mid_len,
            libc::PROT_READ | libc::PROT_WRITE,
            flags,
            fd,
            i64::try_from(aligned_lo).unwrap_or(0),
        ) else {
            return Err(MapError::Sys {
                name: name.to_owned(),
                source: std::io::Error::last_os_error(),
            });
        };
        if mapped != dest {
            let _ = host::munmap(mapped, mid_len);
            return Err(MapError::Sys {
                name: name.to_owned(),
                source: std::io::Error::new(
                    std::io::ErrorKind::AddrNotAvailable,
                    "file-backed MAP_FIXED moved",
                ),
            });
        }
    }

    // No full pages: whole range is partial — one copy.
    if aligned_hi <= aligned_lo {
        // SAFETY: base..base+copy_len inside map_len.
        let dst = unsafe { std::slice::from_raw_parts_mut(base, copy_len) };
        read_file_range(file, fileoff, dst, name)?;
        return Ok(FillOutcome {
            ok: true,
            dirtied: true,
        });
    }

    // Leading partial page.
    if lead > 0 {
        let n = lead.min(copy_len);
        // SAFETY: lead < map_len when interior was validated (or no interior).
        let dst = unsafe { std::slice::from_raw_parts_mut(base, n) };
        read_file_range(file, fileoff, dst, name)?;
        dirtied = true;
    }
    // Trailing partial page.
    if trail_off < copy_len {
        let n = copy_len.saturating_sub(trail_off);
        if n > 0 && trail_off < map_len {
            let len = n.min(map_len.saturating_sub(trail_off));
            // SAFETY: trail_off+len <= map_len.
            let dst = unsafe { std::slice::from_raw_parts_mut(base.add(trail_off), len) };
            let seek_at = fileoff.saturating_add(u64::try_from(trail_off).unwrap_or(0));
            read_file_range(file, seek_at, dst, name)?;
            dirtied = true;
        }
    }

    Ok(FillOutcome {
        ok: true,
        dirtied,
    })
}

/// Fill from an in-memory container (mmap of the same file or heap).
///
/// Uses the same partial-page policy: full host pages are still `memcpy` from
/// the container (already demand-paged); edges match. Avoids a second disk
/// path when the loader holds `FileImage`.
fn fill_segment_bytes(
    bytes: &[u8],
    base: *mut u8,
    map_len: usize,
    fileoff: u64,
    copy_len: usize,
    _host_page: u32,
) -> Result<FillOutcome, MapError> {
    let start = usize::try_from(fileoff).map_err(|_| MapError::Invalid("fileoff"))?;
    let end = start
        .checked_add(copy_len)
        .ok_or(MapError::Invalid("file range overflow"))?;
    let Some(src) = bytes.get(start..end) else {
        return Err(MapError::Invalid("fileoff past container end"));
    };
    if copy_len > map_len {
        return Err(MapError::Invalid("filesize exceeds map length"));
    }
    let dst = unsafe { std::slice::from_raw_parts_mut(base, copy_len) };
    dst.copy_from_slice(src);
    Ok(FillOutcome {
        ok: true,
        dirtied: true,
    })
}

// libgcc / compiler-rt — same symbol as hypercall tramp setup.
#[cfg(all(target_arch = "aarch64", target_os = "linux"))]
unsafe extern "C" {
    fn __clear_cache(start: *mut libc::c_void, end: *mut libc::c_void);
}

/// Flush D/I caches after writing executable guest code (aarch64 requirement).
#[cfg(all(target_arch = "aarch64", target_os = "linux"))]
fn clear_icache(ptr: *mut u8, len: usize) {
    if ptr.is_null() || len == 0 {
        return;
    }
    // SAFETY: range is the live mapping we just wrote and mprotected.
    unsafe {
        let start = ptr.cast::<libc::c_void>();
        let end = ptr.wrapping_add(len).cast::<libc::c_void>();
        __clear_cache(start, end);
    }
}

#[cfg(not(all(target_arch = "aarch64", target_os = "linux")))]
fn clear_icache(_ptr: *mut u8, _len: usize) {}

/// Preferred VA span covering every active segment (host-page aligned ends).
fn image_preferred_span(
    host: HostPageSize,
    active: &[&MapRequest],
) -> Result<(u64, u64), MapError> {
    let host_page = host.bytes();
    let mut lo = u64::MAX;
    let mut hi = 0_u64;
    for req in active {
        lo = lo.min(req.preferred_va);
        let end = req
            .preferred_va
            .checked_add(
                PageLayout::align_up(req.vmsize, host_page)
                    .ok_or(MapError::Invalid("vmsize align overflow"))?,
            )
            .ok_or(MapError::Invalid("segment end overflow"))?;
        hi = hi.max(end);
    }
    if lo == u64::MAX || hi <= lo {
        return Err(MapError::Invalid("no span from active segments"));
    }
    // Align span start down so MAP_FIXED bases stay host-page aligned when preferred is.
    let lo = PageLayout::align_down(lo, host_page).unwrap_or(lo);
    Ok((lo, hi))
}

/// Best-effort: release PROT_NONE pages left in the reserved span outside mapped segments.
fn unmap_span_gaps(reserve_base: u64, span_len: u64, regions: &[MappedRegion]) {
    if span_len == 0 || regions.is_empty() {
        return;
    }
    let span_end = reserve_base.saturating_add(span_len);
    let mut covered: Vec<(u64, u64)> = regions
        .iter()
        .map(|r| {
            let start = r.guest_addr;
            let end = start.saturating_add(u64::try_from(r.len).unwrap_or(0));
            (start, end)
        })
        .collect();
    covered.sort_by_key(|(s, _)| *s);

    let mut cursor = reserve_base;
    for (start, end) in covered {
        if start > cursor && start <= span_end {
            let gap_len = start.saturating_sub(cursor);
            if let Ok(len) = usize::try_from(gap_len)
                && len > 0
            {
                let ptr = host::u64_as_void_ptr(cursor).cast::<u8>();
                let _ = host::munmap(ptr, len);
            }
        }
        cursor = cursor.max(end);
    }
    if cursor < span_end {
        let gap_len = span_end.saturating_sub(cursor);
        if let Ok(len) = usize::try_from(gap_len)
            && len > 0
        {
            let ptr = host::u64_as_void_ptr(cursor).cast::<u8>();
            let _ = host::munmap(ptr, len);
        }
    }
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
        svc_scan_ranges: Vec::new(),
    })
}

/// Temporarily makes a region read/write (for SVC patching / bind writes).
///
/// No-op when Darwin `prot` already includes write (host mapping is already RW).
pub fn mprotect_rw(region: &MappedRegion) -> Result<(), MapError> {
    if region.prot & VM_PROT_WRITE != 0 {
        return Ok(());
    }
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
            svc_scan_ranges: Vec::new(),
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
            svc_scan_ranges: Vec::new(),
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

    /// Real `kh-libsystem` ships with preferred base 0 (`__TEXT` at 0, BSS DATA,
    /// LINKEDIT). Preferred fixed maps fail on Linux; slid reserved-span must work.
    #[test]
    fn map_base0_multi_segment_like_libsystem() {
        let host = HostPageSize::detect().expect("host page");
        let page = u64::from(host.bytes());
        // Layout mirrors staged libSystem.B.dylib (16 KiB TEXT + ~272 KiB DATA BSS + LINKEDIT).
        let text_sz = page.max(0x4000);
        let data_sz = 0x4_4000_u64;
        let link_sz = page.max(0x4000);
        let text_va = 0_u64;
        let data_va = text_sz;
        let link_va = data_va + data_sz;

        let payload = b"base0-text-payload";
        let (mut file, path) = temp_file_with(payload);

        let reqs = [
            MapRequest {
                name: "__TEXT".into(),
                preferred_va: text_va,
                vmsize: text_sz,
                fileoff: 0,
                filesize: u64::try_from(payload.len()).unwrap(),
                initprot: VM_PROT_READ | VM_PROT_EXECUTE,
                maxprot: VM_PROT_READ | VM_PROT_EXECUTE,
                svc_scan_ranges: Vec::new(),
            },
            MapRequest {
                name: "__DATA".into(),
                preferred_va: data_va,
                vmsize: data_sz,
                fileoff: 0,
                filesize: 0,
                initprot: VM_PROT_READ | VM_PROT_WRITE,
                maxprot: VM_PROT_READ | VM_PROT_WRITE,
                svc_scan_ranges: Vec::new(),
            },
            MapRequest {
                name: "__LINKEDIT".into(),
                preferred_va: link_va,
                vmsize: link_sz,
                fileoff: 0,
                filesize: 0,
                initprot: VM_PROT_READ,
                maxprot: VM_PROT_READ,
                svc_scan_ranges: Vec::new(),
            },
        ];

        let mem = GuestMemory::map_image(host, 0, &reqs, &mut file).expect("map base0 image");
        assert_eq!(mem.regions().len(), 3);
        // Relative layout must be preserved under slide.
        let text = mem.regions().first().expect("text");
        let data = mem.regions().get(1).expect("data");
        let link = mem.regions().get(2).expect("link");
        assert_eq!(
            data.guest_addr.wrapping_sub(text.guest_addr),
            data_va.wrapping_sub(text_va)
        );
        assert_eq!(
            link.guest_addr.wrapping_sub(text.guest_addr),
            link_va.wrapping_sub(text_va)
        );
        let got = text.host_bytes().get(..payload.len()).expect("text bytes");
        assert_eq!(got, payload);
        // Preferred base 0 never sticks on Linux; slide may be 0 only if the
        // kernel actually accepted fixed maps at 0 (rare). Either is fine.
        let _ = mem.slide();
        drop(mem);
        drop(std::fs::remove_file(path));
    }

    #[test]
    fn image_span_covers_aligned_ends() {
        let host = HostPageSize::detect().expect("host page");
        let page = u64::from(host.bytes());
        let reqs = [
            MapRequest {
                name: "a".into(),
                preferred_va: 0,
                vmsize: page,
                fileoff: 0,
                filesize: 0,
                initprot: VM_PROT_READ,
                maxprot: VM_PROT_READ,
                svc_scan_ranges: Vec::new(),
            },
            MapRequest {
                name: "b".into(),
                preferred_va: page * 2,
                vmsize: page,
                fileoff: 0,
                filesize: 0,
                initprot: VM_PROT_READ,
                maxprot: VM_PROT_READ,
                svc_scan_ranges: Vec::new(),
            },
        ];
        let refs: Vec<&MapRequest> = reqs.iter().collect();
        let (lo, hi) = image_preferred_span(host, &refs).expect("span");
        assert_eq!(lo, 0);
        assert_eq!(hi, page * 3);
    }
}
