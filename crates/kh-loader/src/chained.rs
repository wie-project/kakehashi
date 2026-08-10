//! Dyld chained fixups (`LC_DYLD_CHAINED_FIXUPS`).
//!
//! Modern Mach-O arm64 images encode rebases and binds as compressed pointer
//! chains in DATA. Applying chains replaces classic section-array rebase and
//! classic bind opcodes for those slots.
//!
//! Phase 11 supports userspace formats:
//! - [`DYLD_CHAINED_PTR_64`] — rebase target is preferred VA
//! - [`DYLD_CHAINED_PTR_64_OFFSET`] — rebase target is offset from preferred base
//!
//! Import tables: `DYLD_CHAINED_IMPORT`, `IMPORT_ADDEND`, `IMPORT_ADDEND64`.
//! Arm64e authenticated formats and multi-start pages are rejected clearly.

use goblin::mach::Mach;
use goblin::mach::load_command::CommandVariant;
use kh_runtime::GuestMemory;

use crate::bind::{self, BindSite};
use crate::error::LoadError;
use crate::image::MachOImage;
use crate::parse::thin_arm64_bytes;
use crate::session::{LoadSession, ProcessImage};

/// `dyld_chained_fixups_header` size in bytes.
const HEADER_SIZE: usize = 28;

/// Page has no fixups.
pub const DYLD_CHAINED_PTR_START_NONE: u16 = 0xFFFF;
/// Page uses multiple starts (not implemented in Phase 11).
pub const DYLD_CHAINED_PTR_START_MULTI: u16 = 0x8000;

/// Pointer format: 64-bit, target is preferred VA (pre-slide).
pub const DYLD_CHAINED_PTR_64: u16 = 2;
/// Pointer format: 64-bit, target is offset from preferred image base.
pub const DYLD_CHAINED_PTR_64_OFFSET: u16 = 6;

/// Imports without addend (4 bytes each).
pub const DYLD_CHAINED_IMPORT: u32 = 1;
/// Imports with 32-bit addend (8 bytes each).
pub const DYLD_CHAINED_IMPORT_ADDEND: u32 = 2;
/// Imports with 64-bit addend (16 bytes each).
pub const DYLD_CHAINED_IMPORT_ADDEND64: u32 = 3;

/// One import from the chained imports table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainedImport {
    /// Library ordinal (0 self, −1 main, −2 flat, or 1-based dylib index).
    pub lib_ordinal: i16,
    /// Weak import → resolve to 0 when missing.
    pub weak: bool,
    /// Symbol name.
    pub name: String,
    /// Addend from the import table (before per-pointer addend).
    pub addend: i64,
}

/// Result of decoding one chain pointer word.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainDecode {
    /// Absolute pointer after slide.
    Rebase {
        /// Final absolute VA.
        value: u64,
    },
    /// Import table bind.
    Bind {
        /// Index into imports table.
        import_ordinal: usize,
        /// 0..255 addend from the pointer word (`PTR_64`).
        ptr_addend: i64,
    },
}

/// True when the parsed image lists `LC_DYLD_CHAINED_FIXUPS`.
#[must_use]
pub fn image_has_chained_fixups(image: &MachOImage) -> bool {
    image
        .load_commands
        .iter()
        .any(|lc| lc.name == "LC_DYLD_CHAINED_FIXUPS")
}

/// True when file bytes contain `LC_DYLD_CHAINED_FIXUPS`.
pub fn bytes_have_chained_fixups(bytes: &[u8]) -> Result<bool, LoadError> {
    Ok(chained_linkedit_range(bytes)?.is_some())
}

/// Apply chained fixups for one mapped image (rebase + bind into guest memory).
///
/// Returns the number of pointer slots rewritten.
///
/// `cache` is process-wide (export index, install-name map) — built once in
/// `bind_process` so each site is O(1) rather than rebuilding a flat map.
pub fn apply_chained_fixups(
    session: &mut LoadSession,
    image_idx: usize,
    bytes: &[u8],
    cache: &bind::BindResolveCache,
) -> Result<usize, LoadError> {
    // Offsets in LC_DYLD_CHAINED_FIXUPS are thin-relative.
    let thin = thin_arm64_bytes(bytes)?;
    let preferred_base = session
        .images
        .get(image_idx)
        .map_or(0, ProcessImage::preferred_base);
    let slide = session.images.get(image_idx).map_or(0, ProcessImage::slide);

    let Some((dataoff, datasize)) = chained_linkedit_range(thin)? else {
        return Ok(0);
    };
    let blob = thin
        .get(dataoff..dataoff.saturating_add(datasize))
        .ok_or_else(|| LoadError::Resolve("chained fixups blob OOB".into()))?;

    let header = parse_header(blob)?;
    let imports = parse_imports(blob, &header)?;

    // Collect (slot, kind) while we have immutable guest memory.
    let pending = {
        let memory = session
            .images
            .get(image_idx)
            .and_then(|img| img.memory.as_ref())
            .ok_or(LoadError::NotImplemented(
                "memory missing for chained fixups",
            ))?;
        collect_pending(memory, blob, &header, preferred_base, slide)?
    };

    let mut writes: Vec<(u64, u64)> = Vec::with_capacity(pending.len());
    for (slot_va, decoded) in pending {
        let value = match decoded {
            ChainDecode::Rebase { value } => value,
            ChainDecode::Bind {
                import_ordinal,
                ptr_addend,
            } => {
                let import = imports.get(import_ordinal).ok_or_else(|| {
                    LoadError::Resolve(format!(
                        "chained bind ordinal {import_ordinal} out of range ({})",
                        imports.len()
                    ))
                })?;
                let site = BindSite {
                    name: import.name.clone(),
                    preferred_va: 0,
                    addend: import.addend.saturating_add(ptr_addend),
                    weak: import.weak,
                    bind_type: 1,
                    lib_ordinal: import.lib_ordinal,
                    is_lazy: false,
                };
                let resolved =
                    bind::resolve_bind_symbol(cache, session.images(), image_idx, &site)?;
                if site.addend == 0 {
                    resolved
                } else {
                    resolved.wrapping_add(site.addend.cast_unsigned())
                }
            }
        };
        tracing::debug!(slot = slot_va, value, "chained fixup");
        writes.push((slot_va, value));
    }

    bind::write_pointer_slots(session, image_idx, &writes)?;
    Ok(writes.len())
}

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

struct FixupsHeader {
    starts_offset: u32,
    imports_offset: u32,
    symbols_offset: u32,
    imports_count: u32,
    imports_format: u32,
    symbols_format: u32,
}

fn chained_linkedit_range(bytes: &[u8]) -> Result<Option<(usize, usize)>, LoadError> {
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
    for lc in &macho.load_commands {
        if let CommandVariant::DyldChainedFixups(cmd) = &lc.command {
            let off = usize::try_from(cmd.dataoff)
                .map_err(|_| LoadError::Resolve("chained dataoff overflow".into()))?;
            let size = usize::try_from(cmd.datasize)
                .map_err(|_| LoadError::Resolve("chained datasize overflow".into()))?;
            return Ok(Some((off, size)));
        }
    }
    Ok(None)
}

fn parse_header(blob: &[u8]) -> Result<FixupsHeader, LoadError> {
    if blob.len() < HEADER_SIZE {
        return Err(LoadError::Resolve("chained fixups header truncated".into()));
    }
    let version = read_u32(blob, 0)?;
    if version != 0 {
        return Err(LoadError::Resolve(format!(
            "unsupported chained fixups_version {version}"
        )));
    }
    Ok(FixupsHeader {
        starts_offset: read_u32(blob, 4)?,
        imports_offset: read_u32(blob, 8)?,
        symbols_offset: read_u32(blob, 12)?,
        imports_count: read_u32(blob, 16)?,
        imports_format: read_u32(blob, 20)?,
        symbols_format: read_u32(blob, 24)?,
    })
}

fn parse_imports(blob: &[u8], header: &FixupsHeader) -> Result<Vec<ChainedImport>, LoadError> {
    if header.symbols_format != 0 {
        return Err(LoadError::NotImplemented(
            "zlib-compressed chained symbol strings",
        ));
    }
    let count = usize::try_from(header.imports_count)
        .map_err(|_| LoadError::Resolve("imports_count overflow".into()))?;
    let imports_off = usize::try_from(header.imports_offset)
        .map_err(|_| LoadError::Resolve("imports_offset overflow".into()))?;
    let symbols_off = usize::try_from(header.symbols_offset)
        .map_err(|_| LoadError::Resolve("symbols_offset overflow".into()))?;

    let entry_size = match header.imports_format {
        DYLD_CHAINED_IMPORT => 4_usize,
        DYLD_CHAINED_IMPORT_ADDEND => 8,
        DYLD_CHAINED_IMPORT_ADDEND64 => 16,
        other => {
            return Err(LoadError::Resolve(format!(
                "unsupported chained imports_format {other}"
            )));
        }
    };

    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        let base = imports_off
            .checked_add(i.saturating_mul(entry_size))
            .ok_or_else(|| LoadError::Resolve("import entry OOB".into()))?;
        let (lib_ordinal, weak, name_offset, addend) = match header.imports_format {
            DYLD_CHAINED_IMPORT => {
                let raw = read_u32(blob, base)?;
                let lib = raw & 0xff;
                let weak = (raw >> 8) & 1 != 0;
                let name_off = raw >> 9;
                (sign_extend_lib_ordinal_8(lib), weak, name_off, 0_i64)
            }
            DYLD_CHAINED_IMPORT_ADDEND => {
                let raw = read_u32(blob, base)?;
                let add = read_i32(blob, base.saturating_add(4))?;
                let lib = raw & 0xff;
                let weak = (raw >> 8) & 1 != 0;
                let name_off = raw >> 9;
                (
                    sign_extend_lib_ordinal_8(lib),
                    weak,
                    name_off,
                    i64::from(add),
                )
            }
            DYLD_CHAINED_IMPORT_ADDEND64 => {
                let raw = read_u64(blob, base)?;
                let add = read_u64(blob, base.saturating_add(8))?.cast_signed();
                let lib = u32::try_from(raw & 0xffff).unwrap_or(0);
                let weak = (raw >> 16) & 1 != 0;
                let name_off = u32::try_from(raw >> 32).unwrap_or(0);
                (sign_extend_lib_ordinal_16(lib), weak, name_off, add)
            }
            other => {
                return Err(LoadError::Resolve(format!(
                    "unsupported chained imports_format {other}"
                )));
            }
        };
        let name = read_symbol_name(blob, symbols_off, name_offset)?;
        out.push(ChainedImport {
            lib_ordinal,
            weak,
            name,
            addend,
        });
    }
    Ok(out)
}

fn sign_extend_lib_ordinal_8(raw: u32) -> i16 {
    let b = u8::try_from(raw & 0xff).unwrap_or(0);
    if b > 0xF0 {
        i16::from(b.cast_signed())
    } else {
        i16::from(b)
    }
}

fn sign_extend_lib_ordinal_16(raw: u32) -> i16 {
    let v = u16::try_from(raw & 0xffff).unwrap_or(0);
    if v > 0xFFF0 {
        v.cast_signed()
    } else {
        i16::try_from(v).unwrap_or(i16::MAX)
    }
}

fn read_symbol_name(
    blob: &[u8],
    symbols_off: usize,
    name_offset: u32,
) -> Result<String, LoadError> {
    let start = symbols_off
        .checked_add(usize::try_from(name_offset).unwrap_or(usize::MAX))
        .ok_or_else(|| LoadError::Resolve("symbol name offset overflow".into()))?;
    let slice = blob
        .get(start..)
        .ok_or_else(|| LoadError::Resolve("symbol name OOB".into()))?;
    let nul = slice
        .iter()
        .position(|&b| b == 0)
        .ok_or_else(|| LoadError::Resolve("symbol name not NUL-terminated".into()))?;
    let bytes = slice
        .get(..nul)
        .ok_or_else(|| LoadError::Resolve("symbol name slice OOB".into()))?;
    std::str::from_utf8(bytes)
        .map(str::to_owned)
        .map_err(|err| LoadError::Resolve(format!("symbol utf8: {err}")))
}

// ---------------------------------------------------------------------------
// Chain walk
// ---------------------------------------------------------------------------

fn collect_pending(
    memory: &GuestMemory,
    blob: &[u8],
    header: &FixupsHeader,
    preferred_base: u64,
    slide: u64,
) -> Result<Vec<(u64, ChainDecode)>, LoadError> {
    let starts_off = usize::try_from(header.starts_offset)
        .map_err(|_| LoadError::Resolve("starts_offset overflow".into()))?;
    let starts = blob
        .get(starts_off..)
        .ok_or_else(|| LoadError::Resolve("starts_in_image OOB".into()))?;
    if starts.len() < 4 {
        return Err(LoadError::Resolve("starts_in_image truncated".into()));
    }
    let seg_count = usize::try_from(read_u32(starts, 0)?)
        .map_err(|_| LoadError::Resolve("seg_count overflow".into()))?;
    let table_end = 4_usize
        .checked_add(
            seg_count
                .checked_mul(4)
                .ok_or_else(|| LoadError::Resolve("seg table overflow".into()))?,
        )
        .ok_or_else(|| LoadError::Resolve("seg table overflow".into()))?;
    if starts.len() < table_end {
        return Err(LoadError::Resolve("seg_info_offset table truncated".into()));
    }

    let image_load = preferred_base.wrapping_add(slide);
    let mut out = Vec::new();

    for seg_i in 0..seg_count {
        let off_pos = 4_usize.saturating_add(seg_i.saturating_mul(4));
        let seg_info_rel = read_u32(starts, off_pos)?;
        if seg_info_rel == 0 {
            continue;
        }
        let seg_info_off = usize::try_from(seg_info_rel)
            .map_err(|_| LoadError::Resolve("seg_info_offset overflow".into()))?;
        let info = starts
            .get(seg_info_off..)
            .ok_or_else(|| LoadError::Resolve("seg starts OOB".into()))?;
        walk_segment(memory, info, preferred_base, image_load, slide, &mut out)?;
    }
    Ok(out)
}

fn walk_segment(
    memory: &GuestMemory,
    info: &[u8],
    preferred_base: u64,
    image_load: u64,
    slide: u64,
    out: &mut Vec<(u64, ChainDecode)>,
) -> Result<(), LoadError> {
    if info.len() < 22 {
        return Err(LoadError::Resolve(
            "chained_starts_in_segment truncated".into(),
        ));
    }
    let page_size = read_u16(info, 4)?;
    let pointer_format = read_u16(info, 6)?;
    let segment_offset = read_u64(info, 8)?;
    let page_count = usize::from(read_u16(info, 20)?);
    let stride = pointer_stride(pointer_format)?;
    let need = 22_usize.saturating_add(page_count.saturating_mul(2));
    if info.len() < need {
        return Err(LoadError::Resolve(
            "chained page_start array truncated".into(),
        ));
    }
    if page_size == 0 {
        return Err(LoadError::Resolve("chained page_size is 0".into()));
    }

    for page_i in 0..page_count {
        let start = read_u16(info, 22_usize.saturating_add(page_i.saturating_mul(2)))?;
        if start == DYLD_CHAINED_PTR_START_NONE {
            continue;
        }
        if start & DYLD_CHAINED_PTR_START_MULTI != 0 {
            return Err(LoadError::NotImplemented(
                "chained multi-start pages (DYLD_CHAINED_PTR_START_MULTI)",
            ));
        }
        let page_base = image_load.wrapping_add(segment_offset).wrapping_add(
            u64::try_from(page_i)
                .unwrap_or(0)
                .wrapping_mul(u64::from(page_size)),
        );

        let mut offset_in_page = u64::from(start);
        let mut hops = 0_u32;
        loop {
            if hops > 1_000_000 {
                return Err(LoadError::Resolve("chained fixup cycle / too long".into()));
            }
            hops = hops.saturating_add(1);
            if offset_in_page >= u64::from(page_size) {
                return Err(LoadError::Resolve(format!(
                    "chained offset {offset_in_page:#x} past page_size {page_size:#x}"
                )));
            }
            let slot_va = page_base.wrapping_add(offset_in_page);
            let raw = memory.read_u64_le(slot_va).ok_or_else(|| {
                LoadError::Resolve(format!("chained slot unreadable at {slot_va:#x}"))
            })?;
            let (next, decoded) = decode_ptr_64(raw, pointer_format, preferred_base, slide)?;
            out.push((slot_va, decoded));
            if next == 0 {
                break;
            }
            offset_in_page = offset_in_page.wrapping_add(next.wrapping_mul(stride));
        }
    }
    Ok(())
}

fn pointer_stride(format: u16) -> Result<u64, LoadError> {
    match format {
        DYLD_CHAINED_PTR_64 | DYLD_CHAINED_PTR_64_OFFSET => Ok(4),
        1 => Err(LoadError::NotImplemented("DYLD_CHAINED_PTR_ARM64E")),
        7 => Err(LoadError::NotImplemented("DYLD_CHAINED_PTR_ARM64E_KERNEL")),
        9 => Err(LoadError::NotImplemented(
            "DYLD_CHAINED_PTR_ARM64E_USERLAND",
        )),
        12 => Err(LoadError::NotImplemented(
            "DYLD_CHAINED_PTR_ARM64E_USERLAND24",
        )),
        _ => Err(LoadError::NotImplemented(
            "unsupported chained pointer_format",
        )),
    }
}

/// Decode a `DYLD_CHAINED_PTR_64` / `_64_OFFSET` raw word.
///
/// Returns `(next_count, decode)` where `next_count` is in stride units.
pub fn decode_ptr_64(
    raw: u64,
    format: u16,
    preferred_base: u64,
    slide: u64,
) -> Result<(u64, ChainDecode), LoadError> {
    let bind = (raw >> 63) & 1 != 0;
    let next = (raw >> 51) & 0xfff;
    if bind {
        let ordinal = raw & 0xff_ffff;
        let addend = (raw >> 24) & 0xff;
        Ok((
            next,
            ChainDecode::Bind {
                import_ordinal: usize::try_from(ordinal).unwrap_or(usize::MAX),
                ptr_addend: i64::try_from(addend).unwrap_or(0),
            },
        ))
    } else {
        let target = raw & 0xf_ffff_ffff;
        let high8 = (raw >> 36) & 0xff;
        let runtime = (high8 << 56) | target;
        let value = match format {
            DYLD_CHAINED_PTR_64 => runtime.wrapping_add(slide),
            DYLD_CHAINED_PTR_64_OFFSET => preferred_base.wrapping_add(slide).wrapping_add(runtime),
            _ => {
                return Err(LoadError::NotImplemented(
                    "decode_ptr_64: unexpected format",
                ));
            }
        };
        Ok((next, ChainDecode::Rebase { value }))
    }
}

// ---------------------------------------------------------------------------
// Encoders (unit tests / opcode smoke)
// ---------------------------------------------------------------------------

/// Encode a `DYLD_CHAINED_PTR_64` bind word.
#[must_use]
pub fn encode_ptr_64_bind(import_ordinal: u32, addend: u8, next: u16) -> u64 {
    let ord = u64::from(import_ordinal) & 0xff_ffff;
    let add = u64::from(addend);
    let nxt = u64::from(next) & 0xfff;
    ord | (add << 24) | (nxt << 51) | (1_u64 << 63)
}

/// Encode a `DYLD_CHAINED_PTR_64` / `_OFFSET` rebase word (same bit layout).
#[must_use]
pub fn encode_ptr_64_rebase(target_or_offset: u64, next: u16) -> u64 {
    let target = target_or_offset & 0xf_ffff_ffff;
    let high8 = (target_or_offset >> 56) & 0xff;
    let nxt = u64::from(next) & 0xfff;
    target | (high8 << 36) | (nxt << 51)
}

/// Build a minimal `LC_DYLD_CHAINED_FIXUPS` payload for unit tests.
///
/// One segment with starts (at `data_seg_index`), one page, one import.
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn encode_chained_fixups_blob(
    seg_count: u32,
    data_seg_index: u32,
    segment_offset: u64,
    page_size: u16,
    page_start: u16,
    pointer_format: u16,
    import_lib_ordinal: u8,
    symbol: &str,
) -> Vec<u8> {
    let mut starts = Vec::new();
    starts.extend_from_slice(&seg_count.to_le_bytes());
    let table_start = starts.len();
    for _ in 0..seg_count {
        starts.extend_from_slice(&0_u32.to_le_bytes());
    }

    let info_rel = u32::try_from(starts.len()).unwrap_or(0);
    let page_count: u16 = 1;
    let info_size: u32 = 24; // 22 + 2
    starts.extend_from_slice(&info_size.to_le_bytes());
    starts.extend_from_slice(&page_size.to_le_bytes());
    starts.extend_from_slice(&pointer_format.to_le_bytes());
    starts.extend_from_slice(&segment_offset.to_le_bytes());
    starts.extend_from_slice(&0_u32.to_le_bytes());
    starts.extend_from_slice(&page_count.to_le_bytes());
    starts.extend_from_slice(&page_start.to_le_bytes());

    let idx = usize::try_from(data_seg_index).unwrap_or(0);
    let patch_at = table_start.saturating_add(idx.saturating_mul(4));
    if let Some(slot) = starts.get_mut(patch_at..patch_at.saturating_add(4)) {
        slot.copy_from_slice(&info_rel.to_le_bytes());
    }

    let starts_offset = HEADER_SIZE;
    let imports_offset = starts_offset.saturating_add(starts.len());
    let name_offset = 0_u32;
    let import_raw: u32 = u32::from(import_lib_ordinal) | (name_offset << 9);
    let symbols_offset = imports_offset.saturating_add(4);
    let mut symbols = symbol.as_bytes().to_vec();
    symbols.push(0);

    let mut blob = Vec::with_capacity(symbols_offset.saturating_add(symbols.len()));
    blob.extend_from_slice(&0_u32.to_le_bytes());
    blob.extend_from_slice(&u32::try_from(starts_offset).unwrap_or(0).to_le_bytes());
    blob.extend_from_slice(&u32::try_from(imports_offset).unwrap_or(0).to_le_bytes());
    blob.extend_from_slice(&u32::try_from(symbols_offset).unwrap_or(0).to_le_bytes());
    blob.extend_from_slice(&1_u32.to_le_bytes());
    blob.extend_from_slice(&DYLD_CHAINED_IMPORT.to_le_bytes());
    blob.extend_from_slice(&0_u32.to_le_bytes());
    debug_assert_eq!(blob.len(), HEADER_SIZE);
    blob.extend_from_slice(&starts);
    blob.extend_from_slice(&import_raw.to_le_bytes());
    blob.extend_from_slice(&symbols);
    blob
}

// ---------------------------------------------------------------------------
// LE readers
// ---------------------------------------------------------------------------

fn read_u16(data: &[u8], off: usize) -> Result<u16, LoadError> {
    let b = data
        .get(off..off.saturating_add(2))
        .ok_or_else(|| LoadError::Resolve(format!("u16 OOB at {off}")))?;
    let mut arr = [0_u8; 2];
    arr.copy_from_slice(b);
    Ok(u16::from_le_bytes(arr))
}

fn read_u32(data: &[u8], off: usize) -> Result<u32, LoadError> {
    let b = data
        .get(off..off.saturating_add(4))
        .ok_or_else(|| LoadError::Resolve(format!("u32 OOB at {off}")))?;
    let mut arr = [0_u8; 4];
    arr.copy_from_slice(b);
    Ok(u32::from_le_bytes(arr))
}

fn read_i32(data: &[u8], off: usize) -> Result<i32, LoadError> {
    Ok(read_u32(data, off)?.cast_signed())
}

fn read_u64(data: &[u8], off: usize) -> Result<u64, LoadError> {
    let b = data
        .get(off..off.saturating_add(8))
        .ok_or_else(|| LoadError::Resolve(format!("u64 OOB at {off}")))?;
    let mut arr = [0_u8; 8];
    arr.copy_from_slice(b);
    Ok(u64::from_le_bytes(arr))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn decode_bind_and_rebase_ptr64() {
        let raw = encode_ptr_64_bind(0, 0, 0);
        let (next, dec) = decode_ptr_64(raw, DYLD_CHAINED_PTR_64, 0x1000_0000, 0).unwrap();
        assert_eq!(next, 0);
        assert_eq!(
            dec,
            ChainDecode::Bind {
                import_ordinal: 0,
                ptr_addend: 0
            }
        );

        let slide = 0x1000_u64;
        let target = 0x1000_4000_u64;
        let raw = encode_ptr_64_rebase(target, 2);
        let (next, dec) = decode_ptr_64(raw, DYLD_CHAINED_PTR_64, 0x1000_0000, slide).unwrap();
        assert_eq!(next, 2);
        assert_eq!(
            dec,
            ChainDecode::Rebase {
                value: target + slide
            }
        );

        let raw = encode_ptr_64_rebase(0x4000, 0);
        let (_, dec) = decode_ptr_64(raw, DYLD_CHAINED_PTR_64_OFFSET, 0x1000_0000, slide).unwrap();
        assert_eq!(
            dec,
            ChainDecode::Rebase {
                value: 0x1000_0000 + slide + 0x4000
            }
        );
    }

    #[test]
    fn encode_blob_parses_one_import() {
        let blob =
            encode_chained_fixups_blob(3, 2, 0x4000, 0x4000, 0, DYLD_CHAINED_PTR_64, 1, "_kh_add");
        let header = parse_header(&blob).unwrap();
        let imports = parse_imports(&blob, &header).unwrap();
        assert_eq!(imports.len(), 1);
        let imp = imports.first().expect("one import");
        assert_eq!(imp.name, "_kh_add");
        assert_eq!(imp.lib_ordinal, 1);
        assert!(!imp.weak);
    }
}
