//! Mach-O arm64 parsing via goblin (thin + fat).
//!
//! Fat containers are always reduced to the **arm64 thin slice** before header /
//! segment / nlist interpretation. [`MachOSummary::file_slice_offset`] records
//! where that slice sits in the on-disk container so map `fileoff` values can be
//! adjusted when reading from the original path.

use std::fs;
use std::ops::Range;
use std::path::Path;

use goblin::mach::constants::cputype::{CPU_TYPE_ARM64, CPU_TYPE_X86_64, get_arch_name_from_types};
use goblin::mach::header::filetype_to_str;
use goblin::mach::load_command::{CommandVariant, cmd_to_str};
use goblin::mach::{Mach, MachO, SingleArch};
use scroll::Pread;

use crate::error::LoadError;
use crate::image::{
    DylibDep, DylibKind, LoadCommandInfo, MachOImage, MachOSummary, SectionInfo, SegmentInfo,
};

/// Location of the arm64 thin Mach-O inside a file buffer (thin or fat).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Arm64Slice {
    /// Byte offset of the thin header within the container.
    pub offset: u64,
    /// Thin image size in bytes.
    pub size: u64,
    /// True when the container was a fat binary.
    pub was_fat: bool,
}

impl Arm64Slice {
    /// Half-open range into the container buffer.
    pub fn range(self) -> Result<Range<usize>, LoadError> {
        let start = usize::try_from(self.offset)
            .map_err(|_| LoadError::NotMachO("fat slice offset out of range".into()))?;
        let size = usize::try_from(self.size)
            .map_err(|_| LoadError::NotMachO("fat slice size out of range".into()))?;
        let end = start
            .checked_add(size)
            .ok_or_else(|| LoadError::NotMachO("fat slice end overflow".into()))?;
        Ok(start..end)
    }
}

/// Locates the arm64 thin Mach-O inside `bytes` (identity for thin arm64).
pub fn locate_arm64_slice(bytes: &[u8]) -> Result<Arm64Slice, LoadError> {
    let mach = Mach::parse(bytes).map_err(|err| LoadError::NotMachO(err.to_string()))?;
    match mach {
        Mach::Binary(macho) => {
            if !is_arm64(&macho) {
                let cputype = macho.header.cputype();
                let cpusubtype = macho.header.cpusubtype();
                let name = get_arch_name_from_types(cputype, cpusubtype)
                    .unwrap_or("unknown")
                    .to_owned();
                let hint = if cputype == CPU_TYPE_X86_64 {
                    format!("{name} (need arm64; no x86 translation in kakehashi)")
                } else {
                    name
                };
                return Err(LoadError::UnsupportedArch(hint));
            }
            Ok(Arm64Slice {
                offset: 0,
                size: u64::try_from(bytes.len()).unwrap_or(u64::MAX),
                was_fat: false,
            })
        }
        Mach::Fat(multi) => {
            if let Ok(Some(arch)) = multi.find_cputype(CPU_TYPE_ARM64) {
                return Ok(Arm64Slice {
                    offset: u64::from(arch.offset),
                    size: u64::from(arch.size),
                    was_fat: true,
                });
            }
            for entry in &multi {
                let entry = entry.map_err(|err| LoadError::NotMachO(err.to_string()))?;
                if let SingleArch::MachO(macho) = entry
                    && is_arm64(&macho)
                {
                    // MultiArch iteration does not expose offset; re-scan arches.
                    if let Ok(Some(arch)) = multi.find_cputype(macho.header.cputype()) {
                        return Ok(Arm64Slice {
                            offset: u64::from(arch.offset),
                            size: u64::from(arch.size),
                            was_fat: true,
                        });
                    }
                }
            }
            Err(LoadError::UnsupportedArch(
                "fat binary has no arm64 slice".to_owned(),
            ))
        }
    }
}

/// Returns a view of the arm64 thin Mach-O inside `bytes`.
pub fn thin_arm64_bytes(bytes: &[u8]) -> Result<&[u8], LoadError> {
    let slice = locate_arm64_slice(bytes)?;
    let range = slice.range()?;
    bytes
        .get(range)
        .ok_or_else(|| LoadError::NotMachO("fat arm64 slice out of file bounds".into()))
}

/// Reads a path and returns only the arm64 thin Mach-O bytes.
pub fn read_thin_arm64(path: &Path) -> Result<Vec<u8>, LoadError> {
    let bytes = fs::read(path)?;
    Ok(thin_arm64_bytes(&bytes)?.to_vec())
}

/// Reads and parses a Mach-O file, selecting the arm64 slice from fat images.
pub fn parse_path(path: &Path) -> Result<MachOImage, LoadError> {
    let (image, _) = parse_path_with_bytes(path)?;
    Ok(image)
}

/// Like [`parse_path`], but returns the **full on-disk container** as a
/// [`crate::FileImage`] (prefer `mmap`, demand-paged).
///
/// Callers reuse that buffer for segment fill ([`GuestMemory::map_image_bytes`])
/// and bind (via [`thin_arm64_bytes`]) so large guests avoid a second disk pass
/// and avoid forcing the entire multi‑hundred‑MiB file into RSS up front.
///
/// **Fat containers:** parse uses the full container so
/// [`MachOSummary::file_slice_offset`] stays correct for map `fileoff`.
pub fn parse_path_with_bytes(path: &Path) -> Result<(MachOImage, crate::FileImage), LoadError> {
    let file = crate::FileImage::open(path)?;
    let image = parse_bytes(file.as_slice(), &path.display().to_string())?;
    Ok((image, file))
}

/// Parses Mach-O bytes. `path_label` is stored in the summary for display.
///
/// Fat images are reduced to the arm64 thin slice; [`MachOSummary::file_slice_offset`]
/// is the container offset of that slice (0 for thin files).
pub fn parse_bytes(bytes: &[u8], path_label: &str) -> Result<MachOImage, LoadError> {
    let slice = locate_arm64_slice(bytes)?;
    let thin = thin_arm64_bytes(bytes)?;
    let mach = Mach::parse(thin).map_err(|err| LoadError::NotMachO(err.to_string()))?;
    match mach {
        Mach::Binary(macho) => {
            image_from_macho(thin, &macho, path_label, slice.was_fat, slice.offset)
        }
        Mach::Fat(_) => Err(LoadError::NotMachO(
            "nested fat image inside arm64 slice".into(),
        )),
    }
}

fn is_arm64(macho: &MachO<'_>) -> bool {
    macho.header.cputype() == CPU_TYPE_ARM64
}

fn image_from_macho(
    bytes: &[u8],
    macho: &MachO<'_>,
    path_label: &str,
    fat: bool,
    file_slice_offset: u64,
) -> Result<MachOImage, LoadError> {
    if !macho.is_64 {
        return Err(LoadError::UnsupportedArch(
            "32-bit Mach-O is not supported".to_owned(),
        ));
    }

    let cputype = macho.header.cputype();
    let cpusubtype = macho.header.cpusubtype();
    if cputype != CPU_TYPE_ARM64 {
        let name = get_arch_name_from_types(cputype, cpusubtype)
            .unwrap_or("unknown")
            .to_owned();
        let hint = if cputype == CPU_TYPE_X86_64 {
            format!("{name} (need arm64; no x86 translation in kakehashi)")
        } else {
            name
        };
        return Err(LoadError::UnsupportedArch(hint));
    }

    let cpu = get_arch_name_from_types(cputype, cpusubtype)
        .unwrap_or("arm64")
        .to_owned();
    // Capability bits live in the high byte (`CPU_SUBTYPE_MASK`); arm64e is 2.
    let is_arm64e = cpusubtype & 0x00ff_ffff == 2;

    let mut uuid = None;
    let mut minos = None;
    let mut platform = None;
    let mut dylibs = Vec::new();
    let mut load_commands = Vec::with_capacity(macho.load_commands.len());

    for (index, lc) in macho.load_commands.iter().enumerate() {
        let cmdsize = u32::try_from(lc.command.cmdsize()).unwrap_or(u32::MAX);
        let name = cmd_to_str(lc.command.cmd()).to_owned();
        let detail = command_detail(bytes, lc.offset, &lc.command);

        match &lc.command {
            CommandVariant::Uuid(u) => {
                uuid = Some(format_uuid(&u.uuid));
            }
            CommandVariant::BuildVersion(bv) => {
                minos = Some(format_packed_version(bv.minos));
                platform = Some(platform_name(bv.platform).to_owned());
            }
            CommandVariant::VersionMinMacosx(v) => {
                minos = Some(format_packed_version(v.version));
                platform = Some("macos".to_owned());
            }
            CommandVariant::VersionMinIphoneos(v) => {
                minos = Some(format_packed_version(v.version));
                platform = Some("ios".to_owned());
            }
            CommandVariant::LoadDylib(c) => {
                if let Some(path) = read_lc_string(bytes, lc.offset, c.dylib.name) {
                    dylibs.push(DylibDep {
                        kind: DylibKind::Load,
                        name: path,
                    });
                }
            }
            CommandVariant::LoadWeakDylib(c) => {
                if let Some(path) = read_lc_string(bytes, lc.offset, c.dylib.name) {
                    dylibs.push(DylibDep {
                        kind: DylibKind::Weak,
                        name: path,
                    });
                }
            }
            CommandVariant::ReexportDylib(c) => {
                if let Some(path) = read_lc_string(bytes, lc.offset, c.dylib.name) {
                    dylibs.push(DylibDep {
                        kind: DylibKind::Reexport,
                        name: path,
                    });
                }
            }
            CommandVariant::LazyLoadDylib(c) => {
                if let Some(path) = read_lc_string(bytes, lc.offset, c.dylib.name) {
                    dylibs.push(DylibDep {
                        kind: DylibKind::Lazy,
                        name: path,
                    });
                }
            }
            CommandVariant::LoadUpwardDylib(c) => {
                if let Some(path) = read_lc_string(bytes, lc.offset, c.dylib.name) {
                    dylibs.push(DylibDep {
                        kind: DylibKind::Upward,
                        name: path,
                    });
                }
            }
            CommandVariant::IdDylib(c) => {
                if let Some(path) = read_lc_string(bytes, lc.offset, c.dylib.name) {
                    dylibs.push(DylibDep {
                        kind: DylibKind::Id,
                        name: path,
                    });
                }
            }
            _ => {}
        }

        load_commands.push(LoadCommandInfo {
            index: u32::try_from(index).unwrap_or(u32::MAX),
            name,
            cmdsize,
            detail,
        });
    }

    let mut segments = Vec::with_capacity(macho.segments.len());
    for seg in &macho.segments {
        let name = seg
            .name()
            .map_err(|err| LoadError::NotMachO(format!("segment name: {err}")))?
            .to_owned();
        let mut sections = Vec::new();
        let section_pairs = seg
            .sections()
            .map_err(|err| LoadError::NotMachO(format!("sections: {err}")))?;
        for (section, _data) in section_pairs {
            let sect_name = section
                .name()
                .map_err(|err| LoadError::NotMachO(format!("section name: {err}")))?
                .to_owned();
            let segname = section
                .segname()
                .map_err(|err| LoadError::NotMachO(format!("section segname: {err}")))?
                .to_owned();
            sections.push(SectionInfo {
                name: sect_name,
                segname,
                addr: section.addr,
                size: section.size,
                offset: section.offset,
                align: section.align,
                flags: section.flags,
            });
        }
        segments.push(SegmentInfo {
            name,
            vmaddr: seg.vmaddr,
            vmsize: seg.vmsize,
            fileoff: seg.fileoff,
            filesize: seg.filesize,
            maxprot: seg.maxprot,
            initprot: seg.initprot,
            sections,
        });
    }

    let entry = if macho.entry == 0 {
        None
    } else {
        Some(macho.entry)
    };

    let summary = MachOSummary {
        path: path_label.to_owned(),
        fat,
        file_slice_offset,
        cpu,
        file_type: filetype_to_str(macho.header.filetype).to_owned(),
        file_type_raw: macho.header.filetype,
        flags: macho.header.flags,
        ncmds: u32::try_from(macho.header.ncmds).unwrap_or(u32::MAX),
        sizeofcmds: macho.header.sizeofcmds,
        entry,
        old_style_entry: macho.old_style_entry,
        uuid,
        minos,
        platform,
        is_64: macho.is_64,
        little_endian: macho.little_endian,
        is_arm64e,
    };

    let rpaths = macho.rpaths.iter().map(|s| (*s).to_owned()).collect();

    Ok(MachOImage {
        summary,
        segments,
        dylibs,
        load_commands,
        rpaths,
    })
}

fn command_detail(bytes: &[u8], offset: usize, command: &CommandVariant) -> Option<String> {
    match command {
        CommandVariant::Segment64(seg) => {
            let segname = cstr16(&seg.segname);
            Some(format!(
                "{segname} vm={:#x}+{:#x} file={:#x}+{:#x} prot={}/{}",
                seg.vmaddr, seg.vmsize, seg.fileoff, seg.filesize, seg.initprot, seg.maxprot
            ))
        }
        CommandVariant::Segment32(seg) => {
            let segname = cstr16(&seg.segname);
            Some(format!("{segname} vm={:#x}+{:#x}", seg.vmaddr, seg.vmsize))
        }
        CommandVariant::Uuid(u) => Some(format_uuid(&u.uuid)),
        CommandVariant::Main(m) => Some(format!(
            "entryoff={:#x} stacksize={:#x}",
            m.entryoff, m.stacksize
        )),
        CommandVariant::BuildVersion(bv) => Some(format!(
            "platform={} minos={} sdk={}",
            platform_name(bv.platform),
            format_packed_version(bv.minos),
            format_packed_version(bv.sdk)
        )),
        CommandVariant::LoadDylib(c)
        | CommandVariant::LoadWeakDylib(c)
        | CommandVariant::ReexportDylib(c)
        | CommandVariant::LazyLoadDylib(c)
        | CommandVariant::LoadUpwardDylib(c)
        | CommandVariant::IdDylib(c) => read_lc_string(bytes, offset, c.dylib.name),
        CommandVariant::Rpath(r) => read_lc_string(bytes, offset, r.path),
        _ => None,
    }
}

fn read_lc_string(bytes: &[u8], cmd_offset: usize, name_off: u32) -> Option<String> {
    let abs = cmd_offset.checked_add(usize::try_from(name_off).ok()?)?;
    bytes.pread::<&str>(abs).ok().map(str::to_owned)
}

fn cstr16(field: &[u8; 16]) -> String {
    let end = field.iter().position(|&b| b == 0).unwrap_or(field.len());
    String::from_utf8_lossy(field.get(..end).unwrap_or(field.as_slice())).into_owned()
}

fn format_uuid(uuid: &[u8; 16]) -> String {
    format!(
        "{:02X}{:02X}{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
        uuid[0],
        uuid[1],
        uuid[2],
        uuid[3],
        uuid[4],
        uuid[5],
        uuid[6],
        uuid[7],
        uuid[8],
        uuid[9],
        uuid[10],
        uuid[11],
        uuid[12],
        uuid[13],
        uuid[14],
        uuid[15]
    )
}

/// X.Y.Z packed as nibbles xxxx.yy.zz (Apple version encoding).
fn format_packed_version(v: u32) -> String {
    let major = v >> 16;
    let minor = (v >> 8) & 0xff;
    let patch = v & 0xff;
    format!("{major}.{minor}.{patch}")
}

fn platform_name(platform: u32) -> &'static str {
    match platform {
        1 => "macos",
        2 => "ios",
        3 => "tvos",
        4 => "watchos",
        5 => "bridgeos",
        6 => "maccatalyst",
        7 => "iossimulator",
        8 => "tvossimulator",
        9 => "watchossimulator",
        10 => "driverkit",
        11 => "visionos",
        _ => "unknown",
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn reject_garbage() {
        let err = parse_bytes(b"not a macho", "bad").unwrap_err();
        assert!(matches!(err, LoadError::NotMachO(_)));
        assert_eq!(err.exit_code(), 2);
    }
}
