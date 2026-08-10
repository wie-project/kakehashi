//! Nlist export/import extraction and nlist→GOT fallback bind.
//!
//! Prefer classic dyld bind opcodes via [`crate::bind`] when
//! `LC_DYLD_INFO` / `LC_DYLD_INFO_ONLY` is present. This module still
//! implements the Phase 6 nlist → `__DATA,__got` path for images without
//! bind streams.

use std::collections::HashMap;
use std::ops::Range;

use goblin::mach::Mach;
use goblin::mach::load_command::CommandVariant;
use goblin::mach::symbols::{N_EXT, N_SECT, N_TYPE, N_UNDF, N_WEAK_REF, Symbols};

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
///
/// When `LC_DYSYMTAB` is present, only walks the **externally defined** range
/// (`iextdefsym`..`+nextdefsym`). Product tools like CLT `clang` have hundreds
/// of thousands of local nlists and **zero** external defs — a full table walk
/// was pure waste (~tens of ms per image). Missing dysymtab → full walk
/// (fixtures / tiny images).
pub fn defined_exports(bytes: &[u8]) -> Result<Vec<DefinedSymbol>, LoadError> {
    let thin = thin_arm64_bytes(bytes)?;
    let macho = parse_macho_binary(thin)?;
    let Some(symbols) = macho.symbols.as_ref() else {
        return Ok(Vec::new());
    };
    let mut out = Vec::new();
    match dysym_extdef_range(&macho) {
        Some(r) if r.is_empty() => return Ok(out),
        Some(r) => {
            out.reserve(r.len().min(4096));
            for_each_nlist_index(symbols, r, |name, nlist| {
                push_defined_export(&mut out, name, &nlist);
            })?;
        }
        None => {
            // No / vacuous dysymtab (many fixtures): full nlist walk.
            for entry in symbols {
                match entry {
                    Ok((name, nlist)) => push_defined_export(&mut out, name, &nlist),
                    Err(err) => return Err(LoadError::NotMachO(format!("nlist: {err}"))),
                }
            }
        }
    }
    Ok(out)
}

fn push_defined_export(
    out: &mut Vec<DefinedSymbol>,
    name: &str,
    nlist: &goblin::mach::symbols::Nlist,
) {
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
}

/// External undefined symbols from the nlist in table order (empty if no symtab).
///
/// Does **not** call goblin `MachO::imports()` / bind opcodes.
///
/// With `LC_DYSYMTAB`, only walks `iundefsym`..`+nundefsym` (skip locals/extdefs).
pub fn undefined_imports(bytes: &[u8]) -> Result<Vec<UndefinedSymbol>, LoadError> {
    let thin = thin_arm64_bytes(bytes)?;
    let macho = parse_macho_binary(thin)?;
    let Some(symbols) = macho.symbols.as_ref() else {
        return Ok(Vec::new());
    };
    let mut out = Vec::new();
    match dysym_undef_range(&macho) {
        Some(r) if r.is_empty() => return Ok(out),
        Some(r) => {
            out.reserve(r.len().min(1024));
            for_each_nlist_index(symbols, r, |name, nlist| {
                push_undefined_import(&mut out, name, &nlist);
            })?;
        }
        None => {
            for entry in symbols {
                match entry {
                    Ok((name, nlist)) => push_undefined_import(&mut out, name, &nlist),
                    Err(err) => return Err(LoadError::NotMachO(format!("nlist: {err}"))),
                }
            }
        }
    }
    Ok(out)
}

fn push_undefined_import(
    out: &mut Vec<UndefinedSymbol>,
    name: &str,
    nlist: &goblin::mach::symbols::Nlist,
) {
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

    let named_handler = export_map.get("_kh_missing_symbol_named").copied();
    let missing_stub = export_map.get("_kh_missing_symbol").copied();
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
                if let Some(handler) = named_handler {
                    match crate::missing_stub::trampoline_for(&u.name, handler) {
                        Ok(va) => {
                            tracing::warn!(
                                name = %u.name,
                                stub = format_args!("{va:#x}"),
                                "unresolved strong nlist; bound to named missing trampoline"
                            );
                            values.push(va);
                            continue;
                        }
                        Err(err) => {
                            tracing::warn!(
                                name = %u.name,
                                error = %err,
                                "missing trampoline emit failed; falling back"
                            );
                        }
                    }
                }
                if let Some(stub) = missing_stub {
                    tracing::warn!(
                        name = %u.name,
                        "unresolved strong nlist; bound to _kh_missing_symbol"
                    );
                    values.push(stub);
                } else if let Some(handler) = named_handler {
                    values.push(handler);
                } else {
                    return Err(LoadError::UnresolvedSymbol {
                        name: u.name.clone(),
                    });
                }
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
            img.export_by_name.clear();
            continue;
        }
        if img.path.as_os_str().is_empty() {
            img.exports.clear();
            img.export_by_name.clear();
            continue;
        }
        // Prefer container retained from parse (no second full-file read).
        img.exports = if let Some(container) = img.file_bytes.as_ref() {
            let thin = thin_arm64_bytes(container.as_slice())?;
            defined_exports(thin)?
        } else {
            let bytes = read_thin_arm64(&img.path)?;
            defined_exports(&bytes)?
        };
        // O(1) bind/chained lookup; same preferred VAs as `exports`.
        img.export_by_name.clear();
        img.export_by_name
            .reserve(img.exports.len().saturating_add(1));
        for exp in &img.exports {
            img.export_by_name
                .entry(exp.name.clone())
                .or_insert(exp.value);
        }
        // Darwin clients (e.g. curl) import the unadorned dyld helper name;
        // freestanding libSystem exports `_dyld_stub_binder`.
        if let Some(v) = img.export_by_name.get("_dyld_stub_binder").copied() {
            img.export_by_name
                .entry("dyld_stub_binder".into())
                .or_insert(v);
        }
    }
    Ok(())
}

/// Flat export map: first definition in load order wins (slid absolute VA).
///
/// Prefer [`crate::bind::BindResolveCache`] during bind — this rebuilds the map
/// and is kept for the nlist-GOT fallback path only.
pub(crate) fn build_export_map(images: &[ProcessImage]) -> HashMap<String, u64> {
    let mut map = HashMap::new();
    for img in images {
        if !matches!(img.status, ImageLoadStatus::Mapped) {
            continue;
        }
        let slide = img.slide();
        if img.export_by_name.is_empty() {
            for exp in &img.exports {
                map.entry(exp.name.clone())
                    .or_insert_with(|| exp.value.wrapping_add(slide));
            }
        } else {
            for (name, &pref) in &img.export_by_name {
                map.entry(name.clone())
                    .or_insert_with(|| pref.wrapping_add(slide));
            }
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

fn parse_macho_binary(thin: &[u8]) -> Result<goblin::mach::MachO<'_>, LoadError> {
    match Mach::parse(thin) {
        Ok(Mach::Binary(m)) => Ok(m),
        Ok(Mach::Fat(_)) => Err(LoadError::NotMachO(
            "nested fat image inside arm64 slice".into(),
        )),
        Err(err) => Err(LoadError::NotMachO(err.to_string())),
    }
}

/// `LC_DYSYMTAB` externally-defined range, when the command is trustworthy.
///
/// Returns `None` when there is no dysymtab **or** the command is all zeros
/// (some synthetic fixtures ship `LC_DYSYMTAB` with empty counts while still
/// having nlist symbols). Real tools (CLT `clang`: hundreds of thousands of
/// locals, `nextdefsym == 0`) keep the empty range so we skip the local walk.
fn dysym_extdef_range(macho: &goblin::mach::MachO<'_>) -> Option<Range<usize>> {
    for lc in &macho.load_commands {
        if let CommandVariant::Dysymtab(d) = &lc.command {
            if dysymtab_is_vacuous(d) {
                return None;
            }
            let start = usize::try_from(d.iextdefsym).ok()?;
            let count = usize::try_from(d.nextdefsym).ok()?;
            return Some(start..start.saturating_add(count));
        }
    }
    None
}

/// `LC_DYSYMTAB` undefined range, when the command is trustworthy.
fn dysym_undef_range(macho: &goblin::mach::MachO<'_>) -> Option<Range<usize>> {
    for lc in &macho.load_commands {
        if let CommandVariant::Dysymtab(d) = &lc.command {
            if dysymtab_is_vacuous(d) {
                return None;
            }
            let start = usize::try_from(d.iundefsym).ok()?;
            let count = usize::try_from(d.nundefsym).ok()?;
            return Some(start..start.saturating_add(count));
        }
    }
    None
}

/// True when `LC_DYSYMTAB` has no local/extdef/undef counts at all (unusable).
fn dysymtab_is_vacuous(d: &goblin::mach::load_command::DysymtabCommand) -> bool {
    d.nlocalsym == 0 && d.nextdefsym == 0 && d.nundefsym == 0
}

fn for_each_nlist_index<F>(
    symbols: &Symbols<'_>,
    range: Range<usize>,
    mut f: F,
) -> Result<(), LoadError>
where
    F: FnMut(&str, goblin::mach::symbols::Nlist),
{
    for i in range {
        match symbols.get(i) {
            Ok((name, nlist)) => f(name, nlist),
            Err(err) => {
                return Err(LoadError::NotMachO(format!("nlist[{i}]: {err}")));
            }
        }
    }
    Ok(())
}
