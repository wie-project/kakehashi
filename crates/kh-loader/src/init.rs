//! Load-time initializers (`S_MOD_INIT_FUNC_POINTERS` / `S_INIT_FUNC_OFFSETS`).
//!
//! After map + bind, dyld runs module constructors bottom-up (dependencies
//! before dependents) before transferring to `LC_MAIN`. Phase 7 implements the
//! same order for mapped images using [`kh_runtime::call_guest`].
//!
//! Modern Apple toolchains emit `__TEXT,__init_offsets` (`S_INIT_FUNC_OFFSETS`)
//! with 32-bit image-relative offsets instead of classic pointer arrays. Real
//! guests such as `7zz` use that form; classic fixtures keep `mod_init_func`.
#![allow(unsafe_code)]

use kh_runtime::{GuestMemory, call_guest};

use crate::error::LoadError;
use crate::image::MachOImage;
use crate::session::{ImageLoadStatus, ImageRole, LoadSession, ProcessImage};

/// Section type: array of function pointers run at load (`S_MOD_INIT_FUNC_POINTERS`).
pub const S_MOD_INIT_FUNC_POINTERS: u32 = 0x9;

/// Section type: 32-bit offsets to initializers (`S_INIT_FUNC_OFFSETS`).
///
/// Each entry is a little-endian `u32` offset from the image preferred load
/// address (mach_header). Actual VA = preferred_base + slide + offset.
pub const S_INIT_FUNC_OFFSETS: u32 = 0x16;

/// Mask for Mach-O section type bits in `flags`.
pub const SECTION_TYPE: u32 = 0xff;

/// One initializer to invoke (already slide-adjusted guest VA).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InitFunc {
    /// Guest VA of the function (`void (*)(void)`).
    pub va: u64,
    /// Image path for diagnostics.
    pub image_path: String,
}

/// Collects initializer VAs for one mapped image.
///
/// Supports both:
/// - classic `S_MOD_INIT_FUNC_POINTERS` (8-byte preferred pointers; post-rebase
///   they are already runnable VAs when `slide != 0`);
/// - modern `S_INIT_FUNC_OFFSETS` (4-byte offsets from preferred image base).
///
/// `preferred_base` is the image's planned preferred load address (lowest
/// non-`__PAGEZERO` segment); required for `S_INIT_FUNC_OFFSETS`.
pub fn collect_mod_init(
    image: &MachOImage,
    memory: &GuestMemory,
    preferred_base: u64,
) -> Result<Vec<u64>, LoadError> {
    let slide = memory.slide();
    let mut out = Vec::new();
    for seg in &image.segments {
        for sect in &seg.sections {
            let kind = sect.flags & SECTION_TYPE;
            if kind == S_MOD_INIT_FUNC_POINTERS {
                collect_mod_init_pointers(sect, memory, slide, &mut out)?;
            } else if kind == S_INIT_FUNC_OFFSETS {
                collect_init_func_offsets(sect, memory, preferred_base, slide, &mut out)?;
            }
        }
    }
    Ok(out)
}

fn collect_mod_init_pointers(
    sect: &crate::image::SectionInfo,
    memory: &GuestMemory,
    slide: u64,
    out: &mut Vec<u64>,
) -> Result<(), LoadError> {
    if sect.size == 0 {
        return Ok(());
    }
    if !sect.size.is_multiple_of(8) {
        return Err(LoadError::Resolve(format!(
            "mod_init section {}/{} size {:#x} not multiple of 8",
            sect.segname, sect.name, sect.size
        )));
    }
    let base = sect.addr.wrapping_add(slide);
    let count = usize::try_from(sect.size.saturating_div(8)).unwrap_or(0);
    for i in 0..count {
        let slot_off = u64::try_from(i).unwrap_or(0).saturating_mul(8);
        let slot = base.wrapping_add(slot_off);
        let va = memory.read_u64_le(slot).ok_or_else(|| {
            LoadError::Resolve(format!(
                "mod_init slot unreadable at {slot:#x} ({}/{})",
                sect.segname, sect.name
            ))
        })?;
        if va == 0 {
            continue;
        }
        out.push(va);
    }
    Ok(())
}

fn collect_init_func_offsets(
    sect: &crate::image::SectionInfo,
    memory: &GuestMemory,
    preferred_base: u64,
    slide: u64,
    out: &mut Vec<u64>,
) -> Result<(), LoadError> {
    if sect.size == 0 {
        return Ok(());
    }
    if !sect.size.is_multiple_of(4) {
        return Err(LoadError::Resolve(format!(
            "init_offsets section {}/{} size {:#x} not multiple of 4",
            sect.segname, sect.name, sect.size
        )));
    }
    let base = sect.addr.wrapping_add(slide);
    let image_load = preferred_base.wrapping_add(slide);
    let count = usize::try_from(sect.size.saturating_div(4)).unwrap_or(0);
    for i in 0..count {
        let slot_off = u64::try_from(i).unwrap_or(0).saturating_mul(4);
        let slot = base.wrapping_add(slot_off);
        let raw = memory.read_u32_le(slot).ok_or_else(|| {
            LoadError::Resolve(format!(
                "init_offsets slot unreadable at {slot:#x} ({}/{})",
                sect.segname, sect.name
            ))
        })?;
        if raw == 0 {
            continue;
        }
        let va = image_load.wrapping_add(u64::from(raw));
        out.push(va);
    }
    Ok(())
}

/// Bottom-up initializer list: mapped dylibs in reverse map order, then main.
pub fn plan_initializers(images: &[ProcessImage]) -> Result<Vec<InitFunc>, LoadError> {
    let mut plan = Vec::new();

    let dylibs: Vec<&ProcessImage> = images
        .iter()
        .filter(|i| i.role == ImageRole::Dylib && matches!(i.status, ImageLoadStatus::Mapped))
        .collect();
    for img in dylibs.into_iter().rev() {
        push_image_inits(img, &mut plan)?;
    }

    if let Some(main) = images.first()
        && main.role == ImageRole::Main
        && matches!(main.status, ImageLoadStatus::Mapped)
    {
        push_image_inits(main, &mut plan)?;
    }

    Ok(plan)
}

fn push_image_inits(img: &ProcessImage, plan: &mut Vec<InitFunc>) -> Result<(), LoadError> {
    let (Some(image), Some(memory)) = (img.image.as_ref(), img.memory.as_ref()) else {
        return Ok(());
    };
    for va in collect_mod_init(image, memory, img.preferred_base())? {
        plan.push(InitFunc {
            va,
            image_path: img.path.display().to_string(),
        });
    }
    Ok(())
}

/// Runs all planned initializers on `guest_sp` (16-byte aligned).
///
/// Returns the number of functions successfully called.
pub fn run_initializers(session: &LoadSession, guest_sp: u64) -> Result<usize, LoadError> {
    let plan = plan_initializers(session.images())?;
    let total = plan.len();
    tracing::info!(total, "mod_init plan");
    let mut ran = 0_usize;
    for init in &plan {
        tracing::info!(
            idx = ran,
            total,
            va = format_args!("{:#x}", init.va),
            image = %init.image_path,
            "run mod_init"
        );
        // SAFETY: VA comes from mapped image sections; stack is the process
        // guest stack; trap handlers installed by caller before live run.
        let _ret = unsafe {
            call_guest(init.va, guest_sp, 0)
                .map_err(|err| LoadError::PageLayout(err.to_string()))?
        };
        ran = ran.saturating_add(1);
        tracing::debug!(
            idx = ran.saturating_sub(1),
            va = format_args!("{:#x}", init.va),
            "mod_init done"
        );
    }
    Ok(ran)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::fixture::{arm64_dylib_ctor, ctor_main_exit};
    use crate::session::LoadSession;
    use crate::test_util::map_test_lock;
    use std::io::Write;
    use std::sync::atomic::{AtomicU64, Ordering};

    #[test]
    fn collect_finds_one_mod_init_in_dylib() {
        static N: AtomicU64 = AtomicU64::new(0);
        let _guard = map_test_lock();
        let n = N.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("kh-init-{}-{n}", std::process::id()));
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
        assert!(
            first.image_path.contains("libkh_ctor"),
            "ctor should be from dylib: {}",
            first.image_path
        );
        assert_ne!(first.va, 0);

        drop(session);
        drop(std::fs::remove_dir_all(dir));
    }
}
