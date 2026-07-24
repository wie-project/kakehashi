//! Mach-O arm64 parsing via goblin (thin + fat).

use std::fs;
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

/// Reads and parses a Mach-O file, selecting the arm64 slice from fat images.
pub fn parse_path(path: &Path) -> Result<MachOImage, LoadError> {
    let bytes = fs::read(path)?;
    parse_bytes(&bytes, &path.display().to_string())
}

/// Parses Mach-O bytes. `path_label` is stored in the summary for display.
pub fn parse_bytes(bytes: &[u8], path_label: &str) -> Result<MachOImage, LoadError> {
    let mach = Mach::parse(bytes).map_err(|err| LoadError::NotMachO(err.to_string()))?;
    match mach {
        Mach::Binary(macho) => image_from_macho(bytes, &macho, path_label, false),
        Mach::Fat(multi) => {
            if let Ok(Some(arch)) = multi.find_cputype(CPU_TYPE_ARM64) {
                let offset = usize::try_from(arch.offset).map_err(|_| {
                    LoadError::NotMachO("fat arm64 slice offset out of range".to_owned())
                })?;
                let macho = MachO::parse(bytes, offset)
                    .map_err(|err| LoadError::NotMachO(err.to_string()))?;
                return image_from_macho(bytes, &macho, path_label, true);
            }

            for entry in &multi {
                let entry = entry.map_err(|err| LoadError::NotMachO(err.to_string()))?;
                if let SingleArch::MachO(macho) = entry
                    && is_arm64(&macho)
                {
                    return image_from_macho(bytes, &macho, path_label, true);
                }
            }

            Err(LoadError::UnsupportedArch(
                "fat binary has no arm64 slice".to_owned(),
            ))
        }
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
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::fixture::minimal_arm64_execute;
    use kh_runtime::GuestPageSize;

    #[test]
    fn parse_minimal_arm64_fixture() {
        let bytes = minimal_arm64_execute();
        let image = parse_bytes(&bytes, "minimal").expect("parse");
        assert_eq!(image.summary.cpu, "arm64");
        assert_eq!(image.summary.file_type, "EXECUTE");
        assert!(!image.summary.fat);
        assert!(image.summary.is_64);
        assert!(image.summary.little_endian);
        assert_eq!(
            image.summary.uuid.as_deref(),
            Some("00112233-4455-6677-8899-AABBCCDDEEFF")
        );
        assert!(
            image
                .dylibs
                .iter()
                .any(|d| d.name == "/usr/lib/libSystem.B.dylib")
        );
        assert!(image.segments.iter().any(|s| s.name == "__TEXT"));
        assert!(image.segments.iter().any(|s| s.name == "__PAGEZERO"));
        assert!(image.summary.entry.is_some());
    }

    #[test]
    fn reject_garbage() {
        let err = parse_bytes(b"not a macho", "bad").unwrap_err();
        assert!(matches!(err, LoadError::NotMachO(_)));
        assert_eq!(err.exit_code(), 2);
    }

    #[test]
    fn image_plan_guest_16k() {
        let bytes = minimal_arm64_execute();
        let image = parse_bytes(&bytes, "minimal").expect("parse");
        let plan = image.plan(GuestPageSize::Darwin16K);
        assert_eq!(plan.guest_page_size, 16_384);
        assert!(!plan.mappings.is_empty());
        assert!(plan.segment_count() >= 2);
    }
}
