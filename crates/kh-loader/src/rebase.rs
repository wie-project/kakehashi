//! In-place rebase of absolute pointer arrays after image slide.
//!
//! Mach-O DATA often stores preferred (slide-0) absolute VAs. After
//! [`GuestMemory::map_image`] applies a non-zero slide, those slots must be
//! updated before anything (guest code or the host init runner) treats them as
//! live addresses.
//!
//! Phase 9 covers fixture-relevant section types only — not dyld rebase opcodes.
//! Images with [`crate::chained`] fixups skip this pass (chains rewrite DATA).

use kh_runtime::{GuestMemory, mprotect_darwin, mprotect_rw};

use crate::error::LoadError;
use crate::image::MachOImage;
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
    for img in &mut session.images {
        if !matches!(img.status, ImageLoadStatus::Mapped) {
            continue;
        }
        if img
            .image
            .as_ref()
            .is_some_and(crate::chained::image_has_chained_fixups)
        {
            tracing::debug!(
                path = %img.path.display(),
                "skip section rebase (chained fixups)"
            );
            continue;
        }
        total = total.saturating_add(rebase_image(img)?);
    }
    Ok(total)
}

/// Rebases one mapped process image. Returns number of pointer slots rewritten.
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
            "rebased pointer slots"
        );
    }
    Ok(count)
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

    let mut rewritten = 0_usize;
    // Collect (slot_va, new_value) first so we batch mprotect per region.
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

    for (slot, actual) in updates {
        write_slot_rw(memory, slot, actual)?;
        rewritten = rewritten.saturating_add(1);
    }
    Ok(rewritten)
}

fn write_slot_rw(memory: &mut GuestMemory, slot: u64, value: u64) -> Result<(), LoadError> {
    let region_idx = memory
        .regions()
        .iter()
        .position(|r| {
            let start = r.guest_addr;
            let end = start.saturating_add(r.vmsize);
            slot >= start && slot < end
        })
        .ok_or_else(|| {
            LoadError::Resolve(format!("rebase slot {slot:#x} outside mapped regions"))
        })?;

    let region = memory
        .regions_mut()
        .get_mut(region_idx)
        .ok_or_else(|| LoadError::Resolve(format!("rebase region missing for {slot:#x}")))?;
    let restore = region.prot;
    mprotect_rw(region).map_err(LoadError::Map)?;

    // Re-borrow after mprotect: region index still valid.
    let wrote = memory.write_u64_le(slot, value);
    let region = memory
        .regions()
        .get(region_idx)
        .ok_or_else(|| LoadError::Resolve(format!("rebase region lost for {slot:#x}")))?;
    mprotect_darwin(region, restore).map_err(LoadError::Map)?;

    if wrote.is_none() {
        return Err(LoadError::Resolve(format!(
            "rebase write failed at {slot:#x}"
        )));
    }
    Ok(())
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
            let inits = collect_mod_init(image, memory).expect("collect preferred");
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

        let inits = collect_mod_init(image, memory).expect("collect post-rebase");
        assert_eq!(inits, vec![preferred.wrapping_add(DELTA)]);

        drop(session);
        drop(std::fs::remove_dir_all(dir));
    }
}
