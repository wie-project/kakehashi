//! Load-time initializers (`S_MOD_INIT_FUNC_POINTERS`).
//!
//! After map + bind, dyld runs module constructors bottom-up (dependencies
//! before dependents) before transferring to `LC_MAIN`. Phase 7 implements the
//! same order for mapped images using [`kh_runtime::call_guest`].
#![allow(unsafe_code)]

use kh_runtime::{GuestMemory, call_guest};

use crate::error::LoadError;
use crate::image::MachOImage;
use crate::session::{ImageLoadStatus, ImageRole, LoadSession, ProcessImage};

/// Section type: array of function pointers run at load (`S_MOD_INIT_FUNC_POINTERS`).
pub const S_MOD_INIT_FUNC_POINTERS: u32 = 0x9;

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
/// Expects **post-rebase** guest memory: [`crate::rebase::rebase_process`]
/// rewrites preferred pointer words in place when `slide != 0`. After that,
/// each non-zero slot is already the callable guest VA (slide 0 ⇒ preferred
/// equals actual, so no rewrite).
pub fn collect_mod_init(image: &MachOImage, memory: &GuestMemory) -> Result<Vec<u64>, LoadError> {
    let slide = memory.slide();
    let mut out = Vec::new();
    for seg in &image.segments {
        for sect in &seg.sections {
            if sect.flags & SECTION_TYPE != S_MOD_INIT_FUNC_POINTERS {
                continue;
            }
            if sect.size == 0 {
                continue;
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
        }
    }
    Ok(out)
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
    for va in collect_mod_init(image, memory)? {
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
    let mut ran = 0_usize;
    for init in &plan {
        tracing::info!(
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
