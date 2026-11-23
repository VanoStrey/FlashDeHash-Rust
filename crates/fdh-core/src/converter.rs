use std::fs::{self, File};
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::encoding::ChunkValueEncoding;
use crate::error::{FdhError, Result};
use crate::format::{FLAG_LEGACY_ALPHABET, FdhHeader};
use crate::hash::{HashRegistry, Hasher};
use crate::search::read_elem;

#[derive(Debug, Deserialize)]
struct LegacyMetadata {
    dictionary_symbols: String,
    hash_algorithm: String,
    #[serde(default)]
    element_size: Option<serde_json::Value>,
}

#[derive(Clone, Debug)]
pub struct ConvertReport {
    pub output_path: PathBuf,
    pub header: FdhHeader,
    pub total_bytes_written: u64,
    pub warnings: Vec<String>,
}

/// Converts a legacy Java dictionary folder (`metadata.json` + `chunk_0.bin .. chunk_{N-1}.bin`)
/// into a single-file `.fdh` dictionary without re-hashing or re-sorting.
///
/// Automatically:
/// - Ignores macOS AppleDouble (`._*`) and unrelated files
/// - Parses `element_size` as either string (`"3"`) or integer (`3`)
/// - Verifies chunk sort order and auto-detects legacy Java `CSHAKE128` (which used `SHA3-256`)
pub fn convert_legacy_dir<F>(
    legacy_dir: impl AsRef<Path>,
    output_path: impl AsRef<Path>,
    mut on_chunk_copied: F,
) -> Result<ConvertReport>
where
    F: FnMut(u32, u32),
{
    let legacy_dir = legacy_dir.as_ref();
    let meta_path = legacy_dir.join("metadata.json");
    if !meta_path.exists() {
        return Err(FdhError::LegacyError(format!(
            "metadata.json not found in {}",
            legacy_dir.display()
        )));
    }

    let meta_str = fs::read_to_string(&meta_path)?;
    let meta: LegacyMetadata = serde_json::from_str(&meta_str)?;

    let element_size: u8 = match &meta.element_size {
        Some(serde_json::Value::Number(n)) => n
            .as_u64()
            .and_then(|v| u8::try_from(v).ok())
            .ok_or_else(|| FdhError::LegacyError("invalid numeric element_size".into()))?,
        Some(serde_json::Value::String(s)) => s
            .trim()
            .parse::<u8>()
            .map_err(|_| FdhError::LegacyError(format!("invalid string element_size '{}'", s)))?,
        None => 3,
        _ => return Err(FdhError::LegacyError("unsupported element_size JSON type".into())),
    };

    let encoding = ChunkValueEncoding::from_raw_legacy(&meta.dictionary_symbols)?;
    let mut chunks = discover_legacy_chunks(legacy_dir)?;
    if chunks.is_empty() {
        return Err(FdhError::LegacyError(format!(
            "no chunk_<N>.bin files found in {}",
            legacy_dir.display()
        )));
    }
    chunks.sort_by_key(|(idx, _)| *idx);

    let start_chunk_index = chunks[0].0;
    for (slot, (idx, _)) in chunks.iter().enumerate() {
        let expected_idx = start_chunk_index + slot as u32;
        if *idx != expected_idx {
            return Err(FdhError::LegacyError(format!(
                "non-contiguous chunk indices: expected chunk_{}.bin, found chunk_{}.bin",
                expected_idx, idx
            )));
        }
    }

    let first_len = fs::metadata(&chunks[0].1)?.len();
    if first_len == 0 || !first_len.is_multiple_of(element_size as u64) {
        return Err(FdhError::LegacyError(format!(
            "chunk file {} has invalid size {} for element_size {}",
            chunks[0].1.display(),
            first_len,
            element_size
        )));
    }
    let elems_per_chunk = first_len / (element_size as u64);
    if !elems_per_chunk.is_power_of_two() {
        return Err(FdhError::LegacyError(format!(
            "chunk element count {} is not a power of two",
            elems_per_chunk
        )));
    }
    let chunk_bits = elems_per_chunk.trailing_zeros() as u8;

    // Validate all chunks have identical byte length
    for (_, path) in &chunks {
        let len = fs::metadata(path)?.len();
        if len != first_len {
            return Err(FdhError::LegacyError(format!(
                "chunk {} has size {}, expected {}",
                path.display(),
                len,
                first_len
            )));
        }
    }

    let registry = HashRegistry::with_builtins();
    let mut warnings = Vec::new();
    let mut resolved_algo = registry.get(&meta.hash_algorithm)?;

    // Verify sort order on the first chunk & auto-detect legacy Java CSHAKE128 (SHA3-256 stub)
    if !verify_chunk_sample(
        &chunks[0].1,
        start_chunk_index,
        chunk_bits,
        element_size as usize,
        &encoding,
        resolved_algo.as_ref(),
    )? {
        if resolved_algo.name() == "CSHAKE128" {
            let sha3 = registry.get("SHA3")?;
            if verify_chunk_sample(
                &chunks[0].1,
                start_chunk_index,
                chunk_bits,
                element_size as usize,
                &encoding,
                sha3.as_ref(),
            )? {
                warnings.push(
                    "Detected legacy Java CSHAKE128 stub (actually SHA3-256). Remapped algorithm to SHA3 for compatibility."
                        .into(),
                );
                resolved_algo = sha3;
            } else {
                warnings.push(
                    "Sample sort-order check failed for CSHAKE128; proceeding with raw copy."
                        .into(),
                );
            }
        } else {
            warnings.push(format!(
                "Sample sort-order check did not match {} on chunk_{}.bin; proceeding with raw copy.",
                resolved_algo.name(),
                start_chunk_index
            ));
        }
    }

    let flags = if encoding.has_leading_space() {
        0
    } else {
        FLAG_LEGACY_ALPHABET
    };
    if !encoding.has_leading_space() {
        warnings.push(format!(
            "Legacy alphabet {:?} has no leading space; preserved verbatim with LEGACY flag.",
            encoding.alphabet()
        ));
    }

    let header = FdhHeader::new(
        resolved_algo.name(),
        encoding.alphabet(),
        element_size,
        chunk_bits,
        chunks.len() as u32,
        start_chunk_index,
        flags,
    );

    if let Some(parent) = output_path.as_ref().parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent)?;
    }

    let out_file = File::create(output_path.as_ref())?;
    let mut writer = BufWriter::with_capacity(16 * 1024 * 1024, out_file);
    header.write_to(&mut writer)?;

    let mut copy_buf = vec![0u8; 4 * 1024 * 1024];
    let total_chunks = chunks.len() as u32;
    let mut total_written = header.data_offset;

    for (slot, (_, chunk_path)) in chunks.iter().enumerate() {
        let mut reader = BufReader::with_capacity(4 * 1024 * 1024, File::open(chunk_path)?);
        loop {
            let n = reader.read(&mut copy_buf)?;
            if n == 0 {
                break;
            }
            writer.write_all(&copy_buf[..n])?;
            total_written += n as u64;
        }
        on_chunk_copied((slot + 1) as u32, total_chunks);
    }
    writer.flush()?;

    Ok(ConvertReport {
        output_path: output_path.as_ref().to_path_buf(),
        header,
        total_bytes_written: total_written,
        warnings,
    })
}

fn discover_legacy_chunks(dir: &Path) -> Result<Vec<(u32, PathBuf)>> {
    let mut found = Vec::new();
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name_str) = name.to_str() else {
            continue;
        };
        // Strict match: `chunk_<digits>.bin` (automatically ignores macOS `._chunk_*.bin`)
        if let Some(rest) = name_str.strip_prefix("chunk_")
            && let Some(num_str) = rest.strip_suffix(".bin")
            && !num_str.is_empty()
            && num_str.bytes().all(|b| b.is_ascii_digit())
            && let Ok(idx) = num_str.parse::<u32>()
        {
            found.push((idx, entry.path()));
        }
    }
    Ok(found)
}

/// Reads the first 4 elements of a chunk file and checks they are non-decreasing by hash.
fn verify_chunk_sample(
    chunk_path: &Path,
    chunk_index: u32,
    chunk_bits: u8,
    elem_size: usize,
    encoding: &ChunkValueEncoding,
    hasher: &dyn Hasher,
) -> Result<bool> {
    let mut f = File::open(chunk_path)?;
    let sample_count = 4usize;
    let mut raw = vec![0u8; sample_count * elem_size];
    f.read_exact(&mut raw)?;

    let mut buf = [0u8; 256];
    let mut prev_hash = None;
    for i in 0..sample_count {
        let elem = read_elem(&raw, i, elem_size);
        let enc = encoding.encode_chunk_elem(chunk_index, elem, chunk_bits, &mut buf);
        let h = hasher.hash(enc);
        if let Some(prev) = prev_hash
            && h < prev
        {
            return Ok(false);
        }
        prev_hash = Some(h);
    }
    Ok(true)
}
