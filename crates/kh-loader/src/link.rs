//! Nlist export/import extraction and nlist→GOT fallback bind.
//!
//! Prefer classic dyld bind opcodes via [`crate::bind`] when
//! `LC_DYLD_INFO` / `LC_DYLD_INFO_ONLY` is present. This module still
//! implements the Phase 6 nlist → `__DATA,__got` path for images without
//! bind streams.

use std::collections::HashMap;

use goblin::mach::Mach;
use goblin::mach::symbols::{N_EXT, N_SECT, N_TYPE, N_UNDF, N_WEAK_REF};

use kh_runtime::{mprotect_darwin, mprotect_rw};

use crate::error::LoadError;
use crate::image::MachOImage;
use crate::parse::{read_thin_arm64, thin_arm64_bytes};
use crate::session::{ImageLoadStatus, LoadSession, ProcessImage};

/// Defined external nlist symbol (`N_SECT | N_EXT`, non-STAB).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DefinedSymbol {
    /// Exact nlist string (e.g. `_kh_add`).
    pub name: String,
    /// `n_value` at slide 0 (preferred VA).
    pub value: u64,
    /// Section ordinal (`n_sect`).
    pub sect: u8,
}

/// Undefined external nlist symbol.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UndefinedSymbol {
    /// Exact nlist string.
    pub name: String,
    /// `N_WEAK_REF` in `n_desc`.
    pub weak_ref: bool,
}

/// External defined symbols from the nlist (empty if no symtab).
///
/// Does **not** use dyld export tries or bind opcodes.
pub fn defined_exports(bytes: &[u8]) -> Result<Vec<DefinedSymbol>, LoadError> {
    let mut out = Vec::new();
    for_each_nlist(bytes, |name, nlist| {
        if nlist.is_stab() || (nlist.n_type & N_EXT) == 0 {
            return;
        }
        if nlist.n_type & N_TYPE != N_SECT {
            return;
        }
        out.push(DefinedSymbol {
            name: name.to_owned(),
            value: nlist.n_value,
            sect: u8::try_from(nlist.n_sect).unwrap_or(u8::MAX),
        });
    })?;
    Ok(out)
}

/// External undefined symbols from the nlist in table order (empty if no symtab).
///
/// Does **not** call goblin `MachO::imports()` / bind opcodes.
pub fn undefined_imports(bytes: &[u8]) -> Result<Vec<UndefinedSymbol>, LoadError> {
    let mut out = Vec::new();
    for_each_nlist(bytes, |name, nlist| {
        if nlist.is_stab() || (nlist.n_type & N_EXT) == 0 {
            return;
        }
        // N_UNDF external (and prebound-undef treated the same for Micro).
        if nlist.n_type & N_TYPE != N_UNDF {
            return;
        }
        if nlist.n_sect != 0 {
            return;
        }
        out.push(UndefinedSymbol {
            name: name.to_owned(),
            weak_ref: nlist.n_desc & N_WEAK_REF != 0,
        });
    })?;
    Ok(out)
}

/// Bind main external undefined nlist symbols into contiguous `__got` slots.
///
/// Used when no image in the process set has classic bind opcodes.
/// No-op when the main image has no external undefined nlist symbols.
pub(crate) fn bind_main_got_nlist(session: &mut LoadSession) -> Result<(), LoadError> {
    let main_path = session
        .images
        .first()
        .map(|i| i.path.clone())
        .ok_or(LoadError::NotImplemented("main missing before bind"))?;
    let main_bytes = read_thin_arm64(&main_path)?;
    let undefs = undefined_imports(&main_bytes)?;
    if undefs.is_empty() {
        return Ok(());
    }

    let main = session
        .images
        .first()
        .ok_or(LoadError::NotImplemented("main missing before bind"))?;
    // ADRP/ADR to the main image's own __got are PC-relative, so a uniform
    // main slide is fine. (Plan's ImageSlid was over-conservative; keep the
    // error variant for a future non-uniform / absolute-address case.)
    let main_slide = main.slide();

    let export_map = build_export_map(session.images());
    let (got_pref, got_size) =
        find_got_section(main.image.as_ref()).ok_or(LoadError::MissingGot {
            count: undefs.len(),
        })?;
    let need = undefs.len().checked_mul(8).ok_or(LoadError::MissingGot {
        count: undefs.len(),
    })?;
    let need_u64 = u64::try_from(need).unwrap_or(u64::MAX);
    if got_size < need_u64 {
        return Err(LoadError::MissingGot {
            count: undefs.len(),
        });
    }
    let got_va = got_pref.wrapping_add(main_slide);

    let mut values = Vec::with_capacity(undefs.len());
    for u in &undefs {
        match export_map.get(&u.name) {
            Some(&va) => {
                tracing::debug!(name = %u.name, va, "bind GOT nlist");
                values.push(va);
            }
            None if u.weak_ref => {
                tracing::debug!(name = %u.name, "weak undef → GOT 0");
                values.push(0);
            }
            None => {
                return Err(LoadError::UnresolvedSymbol {
                    name: u.name.clone(),
                });
            }
        }
    }

    write_got_slots(session, got_va, &values)?;
    Ok(())
}

pub(crate) fn fill_exports(session: &mut LoadSession) -> Result<(), LoadError> {
    for img in &mut session.images {
        if !matches!(img.status, ImageLoadStatus::Mapped) {
            img.exports.clear();
            continue;
        }
        if img.path.as_os_str().is_empty() {
            img.exports.clear();
            continue;
        }
        let bytes = read_thin_arm64(&img.path)?;
        img.exports = defined_exports(&bytes)?;
    }
    Ok(())
}

pub(crate) fn build_export_map(images: &[ProcessImage]) -> HashMap<String, u64> {
    let mut map = HashMap::new();
    for img in images {
        if !matches!(img.status, ImageLoadStatus::Mapped) {
            continue;
        }
        let slide = img.slide();
        for exp in &img.exports {
            map.entry(exp.name.clone())
                .or_insert_with(|| exp.value.wrapping_add(slide));
        }
    }
    map
}

fn find_got_section(image: Option<&MachOImage>) -> Option<(u64, u64)> {
    let image = image?;
    for seg in &image.segments {
        for sect in &seg.sections {
            if sect.name == "__got" {
                return Some((sect.addr, sect.size));
            }
        }
    }
    None
}

fn write_got_slots(
    session: &mut LoadSession,
    got_va: u64,
    values: &[u64],
) -> Result<(), LoadError> {
    let main = session
        .images
        .first_mut()
        .ok_or(LoadError::NotImplemented("main missing for GOT write"))?;
    let memory = main.memory.as_mut().ok_or(LoadError::NotImplemented(
        "main memory missing for GOT write",
    ))?;

    // Locate the region that covers the GOT, mprotect RW, write, restore.
    let region_idx = memory
        .regions()
        .iter()
        .position(|r| {
            let start = r.guest_addr;
            let end = start.saturating_add(r.vmsize);
            got_va >= start && got_va < end
        })
        .ok_or(LoadError::MissingGot {
            count: values.len(),
        })?;

    let region = memory
        .regions_mut()
        .get_mut(region_idx)
        .ok_or(LoadError::MissingGot {
            count: values.len(),
        })?;
    let region_base = region.guest_addr;
    let restore = region.prot;
    mprotect_rw(region).map_err(LoadError::Map)?;

    for (i, &va) in values.iter().enumerate() {
        let slot = got_va.saturating_add(u64::try_from(i).unwrap_or(0).saturating_mul(8));
        let offset = usize::try_from(slot.saturating_sub(region_base)).map_err(|_| {
            LoadError::MissingGot {
                count: values.len(),
            }
        })?;
        let end = offset.saturating_add(8);
        let host = region.host_bytes_mut();
        let Some(slot_bytes) = host.get_mut(offset..end) else {
            return Err(LoadError::MissingGot {
                count: values.len(),
            });
        };
        slot_bytes.copy_from_slice(&va.to_le_bytes());
    }

    mprotect_darwin(region, restore).map_err(LoadError::Map)?;
    Ok(())
}

fn for_each_nlist<F>(bytes: &[u8], mut f: F) -> Result<(), LoadError>
where
    F: FnMut(&str, goblin::mach::symbols::Nlist),
{
    // Accept fat containers: reduce to arm64 thin before nlist walk.
    let thin = thin_arm64_bytes(bytes)?;
    let macho = match Mach::parse(thin) {
        Ok(Mach::Binary(m)) => m,
        Ok(Mach::Fat(_)) => {
            return Err(LoadError::NotMachO(
                "nested fat image inside arm64 slice".into(),
            ));
        }
        Err(err) => return Err(LoadError::NotMachO(err.to_string())),
    };

    for entry in macho.symbols() {
        match entry {
            Ok((name, nlist)) => f(name, nlist),
            Err(err) => {
                return Err(LoadError::NotMachO(format!("nlist: {err}")));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::fixture::{
        KH_BOTTLE_MARK_SYMBOL, arm64_dylib_add, arm64_libsystem_stub, call_dylib_exit,
        call_libsystem_exit, minimal_arm64_execute,
    };
    use crate::session::{ImageLoadStatus, ImageRole, LoadSession};
    use crate::test_util::map_test_lock;
    use std::io::Write;
    use std::sync::atomic::{AtomicU64, Ordering};

    #[test]
    fn no_symtab_means_zero_undefs() {
        let bytes = minimal_arm64_execute();
        let undefs = undefined_imports(&bytes).expect("undefs");
        assert!(undefs.is_empty());
        let exports = defined_exports(&bytes).expect("exports");
        assert!(exports.is_empty());
    }

    #[test]
    fn fixture_export_and_import_names() {
        let dylib = arm64_dylib_add();
        let exports = defined_exports(&dylib).expect("exports");
        assert_eq!(exports.len(), 1);
        let exp = exports.first().expect("one export");
        assert_eq!(exp.name, "_kh_add");
        assert!(
            exp.value >= crate::fixture::LIBKH_ADD_TEXT_VA
                && exp.value < crate::fixture::LIBKH_ADD_TEXT_VA + 0x4000,
            "export VA in dylib TEXT: {:#x}",
            exp.value
        );

        let main = call_dylib_exit();
        let undefs = undefined_imports(&main).expect("undefs");
        assert_eq!(undefs.len(), 1);
        let und = undefs.first().expect("one undef");
        assert_eq!(und.name, "_kh_add");
        assert!(!und.weak_ref);
    }

    #[test]
    fn bind_one_got_slot() {
        static N: AtomicU64 = AtomicU64::new(0);
        let _guard = map_test_lock();
        let n = N.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("kh-bind-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let main_path = dir.join("call_dylib.macho");
        let dylib_path = dir.join("libkh_add.dylib");
        {
            let mut f = std::fs::File::create(&main_path).expect("create main");
            f.write_all(&call_dylib_exit()).expect("write main");
        }
        {
            let mut f = std::fs::File::create(&dylib_path).expect("create dylib");
            f.write_all(&arm64_dylib_add()).expect("write dylib");
        }

        let mut session = LoadSession::open(&main_path, None).expect("open");
        let _ = session.map_process().expect("map_process");
        let mapped_count = session
            .images()
            .iter()
            .filter(|i| matches!(i.status, ImageLoadStatus::Mapped))
            .count();
        assert!(
            mapped_count >= 2,
            "main + dylib should map: {:?}",
            session
                .images()
                .iter()
                .map(|i| (i.role, i.status.as_str(), i.install_name.as_str()))
                .collect::<Vec<_>>()
        );
        let main = session.images().first().expect("main");
        assert_eq!(main.role, ImageRole::Main);
        let main_slide = main.slide();

        let export_va = session
            .images()
            .iter()
            .find(|i| i.role == ImageRole::Dylib && matches!(i.status, ImageLoadStatus::Mapped))
            .and_then(|dylib| {
                dylib
                    .exports
                    .iter()
                    .find(|e| e.name == "_kh_add")
                    .map(|e| e.value.wrapping_add(dylib.slide()))
            })
            .expect("dylib export");

        let got_va = crate::fixture::CALL_DYLIB_GOT_VA.wrapping_add(main_slide);
        let main_mem = session
            .images()
            .first()
            .and_then(|i| i.memory.as_ref())
            .expect("main mem");
        let region = main_mem
            .regions()
            .iter()
            .find(|r| got_va >= r.guest_addr && got_va < r.guest_addr.saturating_add(r.vmsize))
            .expect("DATA region");
        let off = usize::try_from(got_va.saturating_sub(region.guest_addr)).unwrap();
        let end = off.saturating_add(8);
        let bytes = region.host_bytes().get(off..end).expect("got bytes");
        let mut le = [0_u8; 8];
        le.copy_from_slice(bytes);
        assert_eq!(u64::from_le_bytes(le), export_va);

        drop(session);
        drop(std::fs::remove_dir_all(dir));
    }

    #[test]
    fn libsystem_stub_export_name() {
        use crate::fixture::{
            LIBSYSTEM_EXIT_SYMBOL, LIBSYSTEM_PRINTF_SYMBOL, LIBSYSTEM_PUTS_SYMBOL,
            LIBSYSTEM_WRITE_SYMBOL,
        };

        let exports = defined_exports(&arm64_libsystem_stub()).expect("exports");
        assert_eq!(exports.len(), 5);
        let names: Vec<&str> = exports.iter().map(|e| e.name.as_str()).collect();
        assert!(names.contains(&LIBSYSTEM_WRITE_SYMBOL));
        assert!(names.contains(&LIBSYSTEM_EXIT_SYMBOL));
        assert!(names.contains(&LIBSYSTEM_PUTS_SYMBOL));
        assert!(names.contains(&LIBSYSTEM_PRINTF_SYMBOL));
        assert!(names.contains(&KH_BOTTLE_MARK_SYMBOL));
        for exp in &exports {
            assert!(
                exp.value >= crate::fixture::LIBSYSTEM_TEXT_VA
                    && exp.value < crate::fixture::LIBSYSTEM_TEXT_VA + 0x4000,
                "export VA in stub TEXT: {} @ {:#x}",
                exp.name,
                exp.value
            );
        }

        let undefs = undefined_imports(&call_libsystem_exit()).expect("undefs");
        assert_eq!(undefs.len(), 1);
        assert_eq!(undefs.first().expect("one").name, KH_BOTTLE_MARK_SYMBOL);
    }
}
