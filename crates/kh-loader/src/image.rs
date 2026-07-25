//! Owned Mach-O views and image planning types.

use kh_runtime::GuestPageSize;

/// High-level header summary used by `kh inspect`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)]
pub struct MachOSummary {
    /// Path that was opened (or synthetic label).
    pub path: String,
    /// True when the on-disk container was a fat binary.
    pub fat: bool,
    /// Byte offset of the arm64 thin Mach-O within the on-disk container.
    ///
    /// Zero for thin files. Segment `fileoff` values are relative to the thin
    /// header; map requests add this offset when reading the container path.
    pub file_slice_offset: u64,
    /// Architecture name (e.g. `arm64`).
    pub cpu: String,
    /// File type string (e.g. `EXECUTE`).
    pub file_type: String,
    /// Raw filetype constant.
    pub file_type_raw: u32,
    /// Header flags.
    pub flags: u32,
    /// Number of load commands.
    pub ncmds: u32,
    /// Size of all load commands in bytes.
    pub sizeofcmds: u32,
    /// Entry virtual address if known (0 means unknown / not present).
    pub entry: Option<u64>,
    /// True when entry came from `LC_UNIXTHREAD` rather than `LC_MAIN`.
    pub old_style_entry: bool,
    /// UUID if present (`LC_UUID`).
    pub uuid: Option<String>,
    /// Minimum OS version from `LC_BUILD_VERSION` / `LC_VERSION_MIN_*` if any.
    pub minos: Option<String>,
    /// Platform from `LC_BUILD_VERSION` if any.
    pub platform: Option<String>,
    /// Whether this is a 64-bit Mach-O.
    pub is_64: bool,
    /// Little-endian image.
    pub little_endian: bool,
}

/// One segment from the image.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SegmentInfo {
    /// Segment name (`__TEXT`, `__DATA`, …).
    pub name: String,
    /// Preferred virtual address.
    pub vmaddr: u64,
    /// Virtual size.
    pub vmsize: u64,
    /// File offset.
    pub fileoff: u64,
    /// Bytes mapped from file.
    pub filesize: u64,
    /// Maximum VM protection bits.
    pub maxprot: u32,
    /// Initial VM protection bits.
    pub initprot: u32,
    /// Sections contained in this segment.
    pub sections: Vec<SectionInfo>,
}

/// One section within a segment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SectionInfo {
    /// Section name.
    pub name: String,
    /// Containing segment name.
    pub segname: String,
    /// Virtual address.
    pub addr: u64,
    /// Size in bytes.
    pub size: u64,
    /// File offset.
    pub offset: u32,
    /// Alignment as power of two (`1 << align`).
    pub align: u32,
    /// Section flags.
    pub flags: u32,
}

/// Kind of dylib dependency load command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DylibKind {
    /// `LC_LOAD_DYLIB`
    Load,
    /// `LC_LOAD_WEAK_DYLIB`
    Weak,
    /// `LC_REEXPORT_DYLIB`
    Reexport,
    /// `LC_LAZY_LOAD_DYLIB`
    Lazy,
    /// `LC_LOAD_UPWARD_DYLIB`
    Upward,
    /// `LC_ID_DYLIB` (install name of this image)
    Id,
}

impl DylibKind {
    /// Stable short label for CLI output.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Load => "load",
            Self::Weak => "weak",
            Self::Reexport => "reexport",
            Self::Lazy => "lazy",
            Self::Upward => "upward",
            Self::Id => "id",
        }
    }
}

/// A dylib path referenced by a load command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DylibDep {
    /// Dependency kind.
    pub kind: DylibKind,
    /// Path string from the load command.
    pub name: String,
}

/// Compact description of one load command for dumps.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadCommandInfo {
    /// Command index (0-based).
    pub index: u32,
    /// Command name (`LC_SEGMENT_64`, …).
    pub name: String,
    /// Command size in bytes.
    pub cmdsize: u32,
    /// Optional one-line detail (segment name, dylib path, …).
    pub detail: Option<String>,
}

/// Fully parsed arm64 Mach-O (owned).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MachOImage {
    /// Header summary.
    pub summary: MachOSummary,
    /// Segments and sections.
    pub segments: Vec<SegmentInfo>,
    /// Dylib-related dependencies (and optional id).
    pub dylibs: Vec<DylibDep>,
    /// All load commands (compact).
    pub load_commands: Vec<LoadCommandInfo>,
    /// Raw rpaths.
    pub rpaths: Vec<String>,
}

impl MachOImage {
    /// Header summary.
    #[must_use]
    pub fn summary(&self) -> &MachOSummary {
        &self.summary
    }

    /// Filter dylib deps by substring (case-sensitive).
    #[must_use]
    pub fn dylibs_matching(&self, find: Option<&str>) -> Vec<&DylibDep> {
        self.dylibs
            .iter()
            .filter(|dep| find.is_none_or(|needle| dep.name.contains(needle)))
            .collect()
    }

    /// Builds a virtual-memory plan at slide 0 for the given guest page size.
    #[must_use]
    pub fn plan(&self, guest: GuestPageSize) -> ImagePlan {
        ImagePlan::from_image(self, guest)
    }
}

/// One planned mapping region (segment-level).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedMapping {
    /// Segment name.
    pub name: String,
    /// Preferred VA (slide 0).
    pub vmaddr: u64,
    /// Virtual size as declared.
    pub vmsize: u64,
    /// File offset of the first mapped byte.
    pub fileoff: u64,
    /// Bytes to load from the file.
    pub filesize: u64,
    /// `vmaddr` rounded down to guest page.
    pub guest_aligned_addr: u64,
    /// End address rounded up to guest page.
    pub guest_aligned_end: u64,
    /// Initial protection bits.
    pub initprot: u32,
    /// Maximum protection bits.
    pub maxprot: u32,
    /// True when `vmaddr` is guest-page aligned.
    pub vmaddr_guest_aligned: bool,
    /// True when `vmsize` is a guest-page multiple (or zero).
    pub vmsize_guest_aligned: bool,
}

/// Planned virtual memory layout for a loaded image (pre-mmap, slide = 0).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImagePlan {
    /// Guest page size used for alignment checks (bytes).
    pub guest_page_size: u32,
    /// Preferred base (lowest non-zero segment `vmaddr`, else 0).
    pub preferred_base: u64,
    /// Entry virtual address if known.
    pub entry: Option<u64>,
    /// Planned segment mappings.
    pub mappings: Vec<PlannedMapping>,
    /// True if every segment is guest-page aligned in addr and size.
    pub fully_guest_aligned: bool,
}

impl ImagePlan {
    /// Empty plan placeholder.
    #[inline]
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            guest_page_size: 0,
            preferred_base: 0,
            entry: None,
            mappings: Vec::new(),
            fully_guest_aligned: true,
        }
    }

    /// Builds a plan from a parsed image.
    #[must_use]
    pub fn from_image(image: &MachOImage, guest: GuestPageSize) -> Self {
        use kh_runtime::PageLayout;

        let guest_page = guest.bytes();
        let mut preferred_base = u64::MAX;
        let mut mappings = Vec::with_capacity(image.segments.len());
        let mut fully_aligned = true;

        for seg in &image.segments {
            let aligned_addr = PageLayout::align_down(seg.vmaddr, guest_page).unwrap_or(seg.vmaddr);
            let end = seg.vmaddr.saturating_add(seg.vmsize);
            let aligned_end = PageLayout::align_up(end, guest_page).unwrap_or(end);

            let vmaddr_ok = guest_page != 0 && seg.vmaddr.is_multiple_of(u64::from(guest_page));
            let vmsize_ok = guest_page != 0
                && (seg.vmsize == 0 || seg.vmsize.is_multiple_of(u64::from(guest_page)));
            if !vmaddr_ok || !vmsize_ok {
                fully_aligned = false;
            }

            // Preferred load base: lowest mapped segment that is not null-page catch.
            let is_pagezero = seg.name == "__PAGEZERO" || (seg.initprot == 0 && seg.fileoff == 0);
            if seg.vmsize > 0 && !is_pagezero && seg.vmaddr < preferred_base {
                preferred_base = seg.vmaddr;
            }

            mappings.push(PlannedMapping {
                name: seg.name.clone(),
                vmaddr: seg.vmaddr,
                vmsize: seg.vmsize,
                // On-disk offset = thin-relative fileoff + fat container slice base.
                fileoff: seg
                    .fileoff
                    .saturating_add(image.summary.file_slice_offset),
                filesize: seg.filesize,
                guest_aligned_addr: aligned_addr,
                guest_aligned_end: aligned_end,
                initprot: seg.initprot,
                maxprot: seg.maxprot,
                vmaddr_guest_aligned: vmaddr_ok,
                vmsize_guest_aligned: vmsize_ok,
            });
        }

        if preferred_base == u64::MAX {
            preferred_base = 0;
        }

        Self {
            guest_page_size: guest_page,
            preferred_base,
            entry: image.summary.entry,
            mappings,
            fully_guest_aligned: fully_aligned,
        }
    }

    /// Number of segments in the plan.
    #[must_use]
    pub fn segment_count(&self) -> usize {
        self.mappings.len()
    }
}
