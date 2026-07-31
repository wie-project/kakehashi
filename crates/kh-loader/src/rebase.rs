//! In-place rebase of absolute pointer arrays after image slide.
//!
//! Mach-O DATA often stores preferred (slide-0) absolute VAs. After
//! [`GuestMemory::map_image`] applies a non-zero slide, those slots must be
//! updated before anything (guest code or the host init runner) treats them as
//! live addresses.
//!
//! Two mechanisms (classic dyld order, after map, before bind):
//! 1. **Section scan** — fixture-relevant pointer array section types
//!    (`S_MOD_INIT_FUNC_POINTERS`, …).
//! 2. **Classic rebase opcodes** — `LC_DYLD_INFO` / `LC_DYLD_INFO_ONLY` stream
//!    (real `libSystem` / C++ guests: `__stdinp`, vtables, …).
//!
//! Images with [`crate::chained`] fixups skip this pass (chains rewrite DATA).

use goblin::mach::Mach;
use goblin::mach::load_command::{CommandVariant, DyldInfoCommand};
use kh_runtime::GuestMemory;
use scroll::Uleb128;

use crate::bind;
use crate::error::LoadError;
use crate::image::MachOImage;
use crate::parse::{read_thin_arm64, thin_arm64_bytes};
use crate::session::{ImageLoadStatus, LoadSession, ProcessImage};

/// Section type: array of function pointers (`S_MOD_INIT_FUNC_POINTERS`).
pub const S_MOD_INIT_FUNC_POINTERS: u32 = 0x9;

/// Section type: terminators (`S_MOD_TERM_FUNC_POINTERS`).
pub const S_MOD_TERM_FUNC_POINTERS: u32 = 0xa;

/// Section type: literal pointer array (`S_LITERAL_POINTERS`).
pub const S_LITERAL_POINTERS: u32 = 0x5;

/// Section type: interposing tuples (`S_INTERPOSING`) — pairs of pointers.
pub const S_INTERPOSING: u32 = 0xd;

/// Mask for Mach-O section type bits in `flags`.
pub const SECTION_TYPE: u32 = 0xff;

// Classic dyld rebase opcodes (`mach-o/loader.h` / dyld).
const REBASE_OPCODE_MASK: u8 = 0xF0;
const REBASE_IMMEDIATE_MASK: u8 = 0x0F;
const REBASE_OPCODE_DONE: u8 = 0x00;
const REBASE_OPCODE_SET_TYPE_IMM: u8 = 0x10;
const REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB: u8 = 0x20;
const REBASE_OPCODE_ADD_ADDR_ULEB: u8 = 0x30;
const REBASE_OPCODE_ADD_ADDR_IMM_SCALED: u8 = 0x40;
const REBASE_OPCODE_DO_REBASE_IMM_TIMES: u8 = 0x50;
const REBASE_OPCODE_DO_REBASE_ULEB_TIMES: u8 = 0x60;
const REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB: u8 = 0x70;
const REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB: u8 = 0x80;
const REBASE_TYPE_POINTER: u8 = 1;
const POINTER_SIZE: u64 = 8;

/// Returns true when this section type holds preferred absolute pointer words.
#[must_use]
pub const fn is_rebasable_section_type(section_type: u32) -> bool {
    matches!(
        section_type,
        S_MOD_INIT_FUNC_POINTERS | S_MOD_TERM_FUNC_POINTERS | S_LITERAL_POINTERS | S_INTERPOSING
    )
}

/// Rebases all mapped images in the process set. No-op per image when slide is 0.
///
/// Skips images with `LC_DYLD_CHAINED_FIXUPS` (those slots are chain-encoded;
/// [`crate::chained::apply_chained_fixups`] rewrites them at bind time).
///
/// Call **after** map and **before** bind (classic dyld order).
pub fn rebase_process(session: &mut LoadSession) -> Result<usize, LoadError> {
    let mut total = 0_usize;
    // Snapshot paths first so we can re-open thin bytes for opcode streams.
    let entries: Vec<_> = session
        .images
        .iter()
        .enumerate()
        .filter(|(_, img)| matches!(img.status, ImageLoadStatus::Mapped))
        .map(|(idx, img)| (idx, img.path.clone()))
        .collect();

    for (idx, path) in entries {
        let img = session
            .images
            .get_mut(idx)
            .ok_or_else(|| LoadError::Resolve("rebase image index lost".into()))?;
        if img
            .image
            .as_ref()
            .is_some_and(crate::chained::image_has_chained_fixups)
        {
            tracing::debug!(
                path = %path.display(),
                "skip section rebase (chained fixups)"
            );
            continue;
        }
        let section_n = rebase_image(img)?;
        let opcode_n = if path.as_os_str().is_empty() {
            0
        } else {
            let bytes = read_thin_arm64(&path)?;
            apply_classic_rebase_opcodes(img, &bytes)?
        };
        total = total.saturating_add(section_n).saturating_add(opcode_n);
    }
    Ok(total)
}

/// Rebases one mapped process image (section-scan only). Returns slots rewritten.
pub fn rebase_image(img: &mut ProcessImage) -> Result<usize, LoadError> {
    let (Some(image), Some(memory)) = (img.image.as_ref(), img.memory.as_mut()) else {
        return Ok(0);
    };
    let slide = memory.slide();
    if slide == 0 {
        return Ok(0);
    }
    let path = img.path.display().to_string();
    let count = rebase_memory(image, memory, slide).map_err(|err| match err {
        LoadError::Resolve(msg) => LoadError::Resolve(format!("{path}: {msg}")),
        other => other,
    })?;
    if count > 0 {
        tracing::debug!(
            path = %img.path.display(),
            slide,
            slots = count,
            "rebased pointer slots (section scan)"
        );
    }
    Ok(count)
}

/// Applies `LC_DYLD_INFO` rebase opcodes for one mapped image.
pub fn apply_classic_rebase_opcodes(
    img: &mut ProcessImage,
    file_bytes: &[u8],
) -> Result<usize, LoadError> {
    let (Some(image), Some(memory)) = (img.image.as_ref(), img.memory.as_mut()) else {
        return Ok(0);
    };
    let slide = memory.slide();
    if slide == 0 {
        return Ok(0);
    }
    let thin = thin_arm64_bytes(file_bytes)?;
    let stream = classic_rebase_stream(thin)?;
    if stream.is_empty() {
        return Ok(0);
    }
    let seg_vms: Vec<u64> = image.segments.iter().map(|s| s.vmaddr).collect();
    let sites = collect_classic_rebase_sites(stream, &seg_vms)?;
    let mut updates: Vec<(u64, u64)> = Vec::new();
    for preferred_slot in sites {
        let slot = preferred_slot.wrapping_add(slide);
        let preferred = memory.read_u64_le(slot).ok_or_else(|| {
            LoadError::Resolve(format!(
                "classic rebase slot unreadable at {slot:#x} (preferred {preferred_slot:#x})"
            ))
        })?;
        // Slot holds preferred absolute VA (or 0); add slide.
        let actual = preferred.wrapping_add(slide);
        if actual == preferred {
            continue;
        }
        updates.push((slot, actual));
    }
    let count = updates.len();
    bind::write_slots_batched(memory, &updates)?;
    if count > 0 {
        tracing::debug!(
            path = %img.path.display(),
            slide,
            slots = count,
            "rebased pointer slots (classic opcodes)"
        );
    }
    Ok(count)
}

fn classic_rebase_stream(thin: &[u8]) -> Result<&[u8], LoadError> {
    let mach = Mach::parse(thin).map_err(|err| LoadError::Resolve(format!("mach parse: {err}")))?;
    let macho = match mach {
        Mach::Binary(m) => m,
        Mach::Fat(_) => {
            return Err(LoadError::Resolve(
                "classic rebase expects thin arm64 bytes".into(),
            ));
        }
    };
    let Some(cmd) = dyld_info_command(&macho) else {
        return Ok(&[]);
    };
    if cmd.rebase_size == 0 {
        return Ok(&[]);
    }
    let start = usize::try_from(cmd.rebase_off).unwrap_or(0);
    let len = usize::try_from(cmd.rebase_size).unwrap_or(0);
    thin.get(start..start.saturating_add(len)).ok_or_else(|| {
        LoadError::Resolve(format!(
            "rebase stream out of range off={start:#x} size={len:#x}"
        ))
    })
}

fn dyld_info_command<'a>(macho: &'a goblin::mach::MachO<'a>) -> Option<&'a DyldInfoCommand> {
    for lc in &macho.load_commands {
        if let CommandVariant::DyldInfoOnly(c) | CommandVariant::DyldInfo(c) = &lc.command {
            return Some(c);
        }
    }
    None
}

/// Preferred (slide-0) VAs of POINTER rebase slots from a classic opcode stream.
fn collect_classic_rebase_sites(stream: &[u8], seg_vms: &[u64]) -> Result<Vec<u64>, LoadError> {
    let mut out = Vec::new();
    let mut offset = 0_usize;
    let mut seg_index: u8 = 0;
    let mut seg_offset: u64 = 0;
    let mut rebase_type: u8 = REBASE_TYPE_POINTER;

    while offset < stream.len() {
        let Some(&byte) = stream.get(offset) else {
            break;
        };
        offset = offset.saturating_add(1);
        let opcode = byte & REBASE_OPCODE_MASK;
        let imm = byte & REBASE_IMMEDIATE_MASK;

        match opcode {
            REBASE_OPCODE_DONE => break,
            REBASE_OPCODE_SET_TYPE_IMM => {
                rebase_type = imm;
            }
            REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB => {
                seg_index = imm;
                seg_offset = read_uleb(stream, &mut offset)?;
            }
            REBASE_OPCODE_ADD_ADDR_ULEB => {
                let add = read_uleb(stream, &mut offset)?;
                seg_offset = seg_offset.wrapping_add(add);
            }
            REBASE_OPCODE_ADD_ADDR_IMM_SCALED => {
                seg_offset = seg_offset.wrapping_add(u64::from(imm).wrapping_mul(POINTER_SIZE));
            }
            REBASE_OPCODE_DO_REBASE_IMM_TIMES => {
                for _ in 0..imm {
                    push_rebase_site(&mut out, seg_vms, seg_index, seg_offset, rebase_type)?;
                    seg_offset = seg_offset.wrapping_add(POINTER_SIZE);
                }
            }
            REBASE_OPCODE_DO_REBASE_ULEB_TIMES => {
                let times = read_uleb(stream, &mut offset)?;
                for _ in 0..times {
                    push_rebase_site(&mut out, seg_vms, seg_index, seg_offset, rebase_type)?;
                    seg_offset = seg_offset.wrapping_add(POINTER_SIZE);
                }
            }
            REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB => {
                push_rebase_site(&mut out, seg_vms, seg_index, seg_offset, rebase_type)?;
                let add = read_uleb(stream, &mut offset)?;
                seg_offset = seg_offset.wrapping_add(POINTER_SIZE).wrapping_add(add);
            }
            REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB => {
                let times = read_uleb(stream, &mut offset)?;
                let skip = read_uleb(stream, &mut offset)?;
                for _ in 0..times {
                    push_rebase_site(&mut out, seg_vms, seg_index, seg_offset, rebase_type)?;
                    seg_offset = seg_offset.wrapping_add(POINTER_SIZE).wrapping_add(skip);
                }
            }
            _ => {
                return Err(LoadError::Resolve(format!(
                    "unknown rebase opcode {byte:#x} at stream offset {}",
                    offset.saturating_sub(1)
                )));
            }
        }
    }
    Ok(out)
}

fn push_rebase_site(
    out: &mut Vec<u64>,
    seg_vms: &[u64],
    seg_index: u8,
    seg_offset: u64,
    rebase_type: u8,
) -> Result<(), LoadError> {
    if rebase_type != REBASE_TYPE_POINTER {
        // Ignore text-absolute / other rare types for now.
        return Ok(());
    }
    let idx = usize::from(seg_index);
    let base = seg_vms.get(idx).copied().ok_or_else(|| {
        LoadError::Resolve(format!("rebase segment index {seg_index} out of range"))
    })?;
    out.push(base.wrapping_add(seg_offset));
    Ok(())
}

fn read_uleb(data: &[u8], offset: &mut usize) -> Result<u64, LoadError> {
    Uleb128::read(data, offset).map_err(|err| LoadError::Resolve(format!("rebase uleb: {err}")))
}

/// Walks rebasable sections and adds `slide` to each non-zero pointer word.
pub fn rebase_memory(
    image: &MachOImage,
    memory: &mut GuestMemory,
    slide: u64,
) -> Result<usize, LoadError> {
    if slide == 0 {
        return Ok(0);
    }

    // Collect (slot_va, new_value) then one mprotect pair per region (A5).
    let mut updates: Vec<(u64, u64)> = Vec::new();

    for seg in &image.segments {
        for sect in &seg.sections {
            let ty = sect.flags & SECTION_TYPE;
            if !is_rebasable_section_type(ty) {
                continue;
            }
            if sect.size == 0 {
                continue;
            }
            if !sect.size.is_multiple_of(8) {
                return Err(LoadError::Resolve(format!(
                    "rebase section {}/{} size {:#x} not multiple of 8",
                    sect.segname, sect.name, sect.size
                )));
            }
            let base = sect.addr.wrapping_add(slide);
            let count = usize::try_from(sect.size.saturating_div(8)).unwrap_or(0);
            for i in 0..count {
                let slot_off = u64::try_from(i).unwrap_or(0).saturating_mul(8);
                let slot = base.wrapping_add(slot_off);
                let preferred = memory.read_u64_le(slot).ok_or_else(|| {
                    LoadError::Resolve(format!(
                        "rebase slot unreadable at {slot:#x} ({}/{})",
                        sect.segname, sect.name
                    ))
                })?;
                if preferred == 0 {
                    continue;
                }
                let actual = preferred.wrapping_add(slide);
                if actual != preferred {
                    updates.push((slot, actual));
                }
            }
        }
    }

    let rewritten = updates.len();
    bind::write_slots_batched(memory, &updates)?;
    Ok(rewritten)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::fixture::{LIBKH_CTOR_TEXT_VA, arm64_dylib_ctor, ctor_main_exit};
    use crate::init::{collect_mod_init, plan_initializers};
    use crate::session::{ImageRole, LoadSession};
    use crate::test_util::map_test_lock;
    use std::io::Write;
    use std::sync::atomic::{AtomicU64, Ordering};

    #[test]
    fn rebasable_types_match_macho() {
        assert!(is_rebasable_section_type(S_MOD_INIT_FUNC_POINTERS));
        assert!(is_rebasable_section_type(S_MOD_TERM_FUNC_POINTERS));
        assert!(is_rebasable_section_type(S_LITERAL_POINTERS));
        assert!(is_rebasable_section_type(S_INTERPOSING));
        assert!(!is_rebasable_section_type(0x6)); // S_NON_LAZY_SYMBOL_POINTERS
        assert!(!is_rebasable_section_type(0x0)); // S_REGULAR
    }

    #[test]
    fn slide_zero_still_runs_mod_init_plan() {
        static N: AtomicU64 = AtomicU64::new(0);
        let _guard = map_test_lock();
        let n = N.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("kh-rebase-zero-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let main_path = dir.join("ctor_main.macho");
        let dylib_path = dir.join("libkh_ctor.dylib");
        std::fs::File::create(&main_path)
            .unwrap()
            .write_all(&ctor_main_exit())
            .unwrap();
        std::fs::File::create(&dylib_path)
            .unwrap()
            .write_all(&arm64_dylib_ctor())
            .unwrap();

        let mut session = LoadSession::open(&main_path, None).unwrap();
        let _ = session.map_process().unwrap();
        let plan = plan_initializers(session.images()).expect("plan");
        assert_eq!(plan.len(), 1, "expected one dylib ctor: {plan:?}");
        let first = plan.first().expect("one");
        assert_ne!(first.va, 0);

        drop(session);
        drop(std::fs::remove_dir_all(dir));
    }

    #[test]
    fn nonzero_slide_rewrites_mod_init_slot_in_place() {
        static N: AtomicU64 = AtomicU64::new(0);
        const DELTA: u64 = 0x1_0000;

        let _guard = map_test_lock();
        let n = N.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("kh-rebase-slide-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let main_path = dir.join("ctor_main.macho");
        let dylib_path = dir.join("libkh_ctor.dylib");
        std::fs::File::create(&main_path)
            .unwrap()
            .write_all(&ctor_main_exit())
            .unwrap();
        std::fs::File::create(&dylib_path)
            .unwrap()
            .write_all(&arm64_dylib_ctor())
            .unwrap();

        let mut session = LoadSession::open(&main_path, None).unwrap();
        let _ = session.map_process().unwrap();

        let dylib_idx = session
            .images()
            .iter()
            .position(|i| {
                i.role == ImageRole::Dylib
                    && matches!(i.status, ImageLoadStatus::Mapped)
                    && i.install_name.contains("libkh_ctor")
            })
            .expect("mapped ctor dylib");

        // Snapshot preferred pointer (file content; slide was 0 so still preferred).
        let preferred = {
            let dylib = session.images().get(dylib_idx).expect("dylib");
            let image = dylib.image.as_ref().expect("image");
            let memory = dylib.memory.as_ref().expect("memory");
            let inits =
                collect_mod_init(image, memory, dylib.preferred_base()).expect("collect preferred");
            *inits.first().expect("one init")
        };
        assert!(
            (LIBKH_CTOR_TEXT_VA..LIBKH_CTOR_TEXT_VA + 0x4000).contains(&preferred),
            "preferred ctor in TEXT: {preferred:#x}"
        );

        {
            let dylib = session.images_mut().get_mut(dylib_idx).expect("dylib mut");
            let memory = dylib.memory.as_mut().expect("memory mut");
            memory.test_offset_guest_vas(DELTA);
            assert_eq!(memory.slide(), DELTA);
            let image = dylib.image.as_ref().expect("image");
            let rewritten = rebase_memory(image, memory, DELTA).expect("rebase");
            assert_eq!(rewritten, 1, "one mod_init pointer should be rewritten");
        }

        let dylib = session.images().get(dylib_idx).expect("dylib");
        let image = dylib.image.as_ref().expect("image");
        let memory = dylib.memory.as_ref().expect("memory");
        let slide = memory.slide();
        assert_eq!(slide, DELTA);

        let sect = image
            .segments
            .iter()
            .flat_map(|s| s.sections.iter())
            .find(|s| s.flags & SECTION_TYPE == S_MOD_INIT_FUNC_POINTERS)
            .expect("mod_init sect");
        let slot = sect.addr.wrapping_add(slide);
        let slot_val = memory.read_u64_le(slot).expect("slot");
        assert_eq!(slot_val, preferred.wrapping_add(DELTA));

        let inits =
            collect_mod_init(image, memory, dylib.preferred_base()).expect("collect post-rebase");
        assert_eq!(inits, vec![preferred.wrapping_add(DELTA)]);

        drop(session);
        drop(std::fs::remove_dir_all(dir));
    }
}
