//! Mach-O static inspection.

use std::io::{self, Write};
use std::path::Path;

use anyhow::{Result, bail};
use kh_loader::{DylibKind, ImagePlan, LoadError, MachOImage, parse_path};
use kh_runtime::{GuestPageSize, HostPageSize, PageLayout};
use serde_json::{Value, json};

use super::util::{format_prot, write_line};

/// Arguments for `kh inspect`.
#[allow(clippy::struct_excessive_bools)]
pub(crate) struct InspectArgs<'a> {
    pub path: Option<&'a Path>,
    pub sections: bool,
    pub imports: bool,
    pub find: Option<&'a str>,
    pub load_commands: bool,
    pub image: bool,
    pub page_size: Option<u32>,
    pub host_page_size: bool,
    pub json: bool,
}

/// Runs the inspect command.
pub(crate) fn run(args: &InspectArgs<'_>) -> Result<()> {
    if args.host_page_size {
        return print_host_page_size(args.json);
    }

    let Some(path) = args.path else {
        bail!("a Mach-O path is required (or pass --host-page-size)");
    };

    let guest = match args.page_size {
        Some(bytes) => GuestPageSize::try_explicit(bytes).ok_or_else(|| {
            anyhow::anyhow!("invalid --page-size {bytes} (expected 4096 or 16384)")
        })?,
        None => GuestPageSize::default(),
    };

    let image = parse_path(path).map_err(anyhow::Error::new)?;
    let show_imports = args.imports || args.find.is_some();

    if args.json {
        return print_json(&image, args, guest, show_imports);
    }

    let mut out = io::stdout().lock();
    print_summary_human(&mut out, &image)?;

    if args.sections {
        print_sections_human(&mut out, &image)?;
    }
    if show_imports {
        print_imports_human(&mut out, &image, args.find)?;
    }
    if args.load_commands {
        print_load_commands_human(&mut out, &image)?;
    }
    if args.image {
        let plan = image.plan(guest);
        print_image_plan_human(&mut out, &plan)?;
    }

    Ok(())
}

fn print_host_page_size(json: bool) -> Result<()> {
    let host = HostPageSize::detect()?;
    let layout = PageLayout::new(host, GuestPageSize::default());
    let mut out = io::stdout().lock();
    if json {
        writeln!(
            out,
            r#"{{"host_page_size":{},"guest_page_size_default":{}}}"#,
            host.bytes(),
            layout.guest_bytes()
        )?;
    } else {
        let _continued = write_line(
            &mut out,
            &format!(
                "host_page_size={} guest_page_size_default={}",
                host.bytes(),
                layout.guest_bytes()
            ),
        )?;
    }
    Ok(())
}

fn print_summary_human(out: &mut impl Write, image: &MachOImage) -> Result<()> {
    let s = &image.summary;
    let entry = s
        .entry
        .map_or_else(|| "-".to_owned(), |v| format!("{v:#018x}"));
    let uuid = s.uuid.as_deref().unwrap_or("-");
    let minos = s.minos.as_deref().unwrap_or("-");
    let platform = s.platform.as_deref().unwrap_or("-");
    let fat = if s.fat { "yes" } else { "no" };
    let entry_style = if s.old_style_entry {
        "unixthread"
    } else {
        "main"
    };

    let _ = write_line(out, &format!("path:        {}", s.path))?;
    let _ = write_line(out, &format!("cpu:         {}", s.cpu))?;
    let _ = write_line(
        out,
        &format!("filetype:    {} ({})", s.file_type, s.file_type_raw),
    )?;
    let _ = write_line(out, &format!("flags:       {:#010x}", s.flags))?;
    let _ = write_line(
        out,
        &format!("ncmds:       {} (sizeofcmds={})", s.ncmds, s.sizeofcmds),
    )?;
    let _ = write_line(out, &format!("entry:       {entry} ({entry_style})"))?;
    let _ = write_line(out, &format!("uuid:        {uuid}"))?;
    let _ = write_line(out, &format!("minos:       {minos}"))?;
    let _ = write_line(out, &format!("platform:    {platform}"))?;
    let _ = write_line(out, &format!("fat:         {fat}"))?;
    let _ = write_line(
        out,
        &format!(
            "segments:    {}  dylibs: {}  rpaths: {}",
            image.segments.len(),
            image.dylibs.len(),
            image.rpaths.len()
        ),
    )?;
    Ok(())
}

fn print_sections_human(out: &mut impl Write, image: &MachOImage) -> Result<()> {
    let _ = write_line(out, "")?;
    let _ = write_line(out, "segments and sections:")?;
    for seg in &image.segments {
        let _ = write_line(
            out,
            &format!(
                "  {:16} vm={:#018x} + {:#010x}  file={:#010x} + {:#010x}  prot={}/{}",
                seg.name,
                seg.vmaddr,
                seg.vmsize,
                seg.fileoff,
                seg.filesize,
                format_prot(seg.initprot),
                format_prot(seg.maxprot)
            ),
        )?;
        for sec in &seg.sections {
            let _ = write_line(
                out,
                &format!(
                    "    {:16} addr={:#018x} size={:#010x} off={:#010x} align=2^{} flags={:#010x}",
                    sec.name, sec.addr, sec.size, sec.offset, sec.align, sec.flags
                ),
            )?;
        }
    }
    Ok(())
}

fn print_imports_human(out: &mut impl Write, image: &MachOImage, find: Option<&str>) -> Result<()> {
    let _ = write_line(out, "")?;
    let title = match find {
        Some(f) => format!("dylibs (filter={f:?}):"),
        None => "dylibs:".to_owned(),
    };
    let _ = write_line(out, &title)?;
    let deps = image.dylibs_matching(find);
    if deps.is_empty() {
        let _ = write_line(out, "  (none)")?;
        return Ok(());
    }
    for dep in deps {
        let kind = dep.kind.as_str();
        let mark = if dep.kind == DylibKind::Id { "*" } else { " " };
        let _ = write_line(out, &format!("  {mark}[{kind:8}] {}", dep.name))?;
    }
    Ok(())
}

fn print_load_commands_human(out: &mut impl Write, image: &MachOImage) -> Result<()> {
    let _ = write_line(out, "")?;
    let _ = write_line(out, "load commands:")?;
    for lc in &image.load_commands {
        match &lc.detail {
            Some(detail) => {
                let _ = write_line(
                    out,
                    &format!(
                        "  [{:>3}] {:24} size={:<4} {}",
                        lc.index, lc.name, lc.cmdsize, detail
                    ),
                )?;
            }
            None => {
                let _ = write_line(
                    out,
                    &format!("  [{:>3}] {:24} size={}", lc.index, lc.name, lc.cmdsize),
                )?;
            }
        }
    }
    Ok(())
}

fn print_image_plan_human(out: &mut impl Write, plan: &ImagePlan) -> Result<()> {
    let _ = write_line(out, "")?;
    let _ = write_line(
        out,
        &format!("image plan (slide=0, guest_page={}):", plan.guest_page_size),
    )?;
    let _ = write_line(
        out,
        &format!("  preferred_base: {:#018x}", plan.preferred_base),
    )?;
    let entry = plan
        .entry
        .map_or_else(|| "-".to_owned(), |v| format!("{v:#018x}"));
    let _ = write_line(out, &format!("  entry:          {entry}"))?;
    let _ = write_line(
        out,
        &format!("  fully_guest_aligned: {}", plan.fully_guest_aligned),
    )?;
    for m in &plan.mappings {
        let a = if m.vmaddr_guest_aligned {
            "ok"
        } else {
            "MISALIGN"
        };
        let s = if m.vmsize_guest_aligned {
            "ok"
        } else {
            "MISALIGN"
        };
        let _ = write_line(
            out,
            &format!(
                "  {:16} va={:#018x}..{:#018x} (raw +{:#x}) prot={} guest_addr={a} guest_size={s}",
                m.name,
                m.guest_aligned_addr,
                m.guest_aligned_end,
                m.vmsize,
                format_prot(m.initprot),
            ),
        )?;
    }
    Ok(())
}

fn print_json(
    image: &MachOImage,
    args: &InspectArgs<'_>,
    guest: GuestPageSize,
    show_imports: bool,
) -> Result<()> {
    let s = &image.summary;
    let mut root = json!({
        "path": s.path,
        "cpu": s.cpu,
        "filetype": s.file_type,
        "filetype_raw": s.file_type_raw,
        "flags": s.flags,
        "ncmds": s.ncmds,
        "sizeofcmds": s.sizeofcmds,
        "entry": s.entry,
        "old_style_entry": s.old_style_entry,
        "uuid": s.uuid,
        "minos": s.minos,
        "platform": s.platform,
        "fat": s.fat,
        "is_64": s.is_64,
        "little_endian": s.little_endian,
        "rpaths": image.rpaths,
    });

    let show_all = !args.sections && !show_imports && !args.load_commands && !args.image;

    let obj = root
        .as_object_mut()
        .ok_or_else(|| anyhow::anyhow!("json root must be an object"))?;

    if show_all || args.sections {
        let segs: Vec<Value> = image
            .segments
            .iter()
            .map(|seg| {
                json!({
                    "name": seg.name,
                    "vmaddr": seg.vmaddr,
                    "vmsize": seg.vmsize,
                    "fileoff": seg.fileoff,
                    "filesize": seg.filesize,
                    "initprot": seg.initprot,
                    "maxprot": seg.maxprot,
                    "sections": seg.sections.iter().map(|sec| json!({
                        "name": sec.name,
                        "segname": sec.segname,
                        "addr": sec.addr,
                        "size": sec.size,
                        "offset": sec.offset,
                        "align": sec.align,
                        "flags": sec.flags,
                    })).collect::<Vec<_>>(),
                })
            })
            .collect();
        obj.insert("segments".to_owned(), Value::Array(segs));
    }

    if show_all || show_imports {
        let deps = image.dylibs_matching(args.find);
        obj.insert(
            "dylibs".to_owned(),
            Value::Array(
                deps.iter()
                    .map(|d| {
                        json!({
                            "kind": d.kind.as_str(),
                            "name": d.name,
                        })
                    })
                    .collect(),
            ),
        );
    }

    if show_all || args.load_commands {
        obj.insert(
            "load_commands".to_owned(),
            Value::Array(
                image
                    .load_commands
                    .iter()
                    .map(|lc| {
                        json!({
                            "index": lc.index,
                            "name": lc.name,
                            "cmdsize": lc.cmdsize,
                            "detail": lc.detail,
                        })
                    })
                    .collect(),
            ),
        );
    }

    if show_all || args.image {
        let plan = image.plan(guest);
        obj.insert(
            "image_plan".to_owned(),
            json!({
                "guest_page_size": plan.guest_page_size,
                "preferred_base": plan.preferred_base,
                "entry": plan.entry,
                "fully_guest_aligned": plan.fully_guest_aligned,
                "mappings": plan.mappings.iter().map(|m| json!({
                    "name": m.name,
                    "vmaddr": m.vmaddr,
                    "vmsize": m.vmsize,
                    "guest_aligned_addr": m.guest_aligned_addr,
                    "guest_aligned_end": m.guest_aligned_end,
                    "initprot": m.initprot,
                    "maxprot": m.maxprot,
                    "vmaddr_guest_aligned": m.vmaddr_guest_aligned,
                    "vmsize_guest_aligned": m.vmsize_guest_aligned,
                })).collect::<Vec<_>>(),
            }),
        );
    }

    let mut out = io::stdout().lock();
    writeln!(out, "{root}")?;
    Ok(())
}

/// Maps a loader error to a process exit code for `main`.
pub(crate) fn exit_code_for(err: &anyhow::Error) -> u8 {
    err.downcast_ref::<LoadError>()
        .map_or(1, LoadError::exit_code)
}
