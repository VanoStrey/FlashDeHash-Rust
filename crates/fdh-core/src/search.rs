use std::cmp::Ordering;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};
use std::time::{Duration, Instant};

use rayon::prelude::*;

use crate::encoding::ChunkValueEncoding;
use crate::error::{FdhError, Result};
use crate::format::{FdhDictionary, FdhHeader};
use crate::hash::{HashDigest, HashRegistry, Hasher};

/// Interpolation search half-window ($\pm 4\sigma$ for $2^{24}$ elements).
pub const INTERPOLATION_RANGE: usize = 8192;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SearchHit {
    pub plaintext: String,
    pub chunk_index: u32,
    pub position: usize,
    pub elapsed: Duration,
    pub used_fallback: bool,
}

enum WindowSearchOutcome {
    Found { pos: usize },
    MissLeft,
    MissRight,
    NotPresent,
}

/// High-performance memory-mapped searcher over a single-file `.fdh` dictionary.
pub struct DictionarySearcher {
    dict: FdhDictionary,
    encoding: ChunkValueEncoding,
    hasher: Arc<dyn Hasher>,
}

impl DictionarySearcher {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let dict = FdhDictionary::open(path)?;
        let hasher = HashRegistry::with_builtins().get(&dict.header().algorithm)?;
        let encoding = ChunkValueEncoding::from_raw_legacy(&dict.header().alphabet)?;

        Ok(Self {
            dict,
            encoding,
            hasher,
        })
    }

    #[inline]
    pub fn header(&self) -> &FdhHeader {
        self.dict.header()
    }

    #[inline]
    pub fn hasher(&self) -> &dyn Hasher {
        self.hasher.as_ref()
    }

    #[inline]
    pub fn encoding(&self) -> &ChunkValueEncoding {
        &self.encoding
    }

    /// Searches for a hexadecimal hash across all chunks in parallel.
    ///
    /// Uses global interpolation prediction (`target[0..chunk_bits] ± 8192`) for ~14-probe
    /// lookups in 99.994% of cases, with an automatic zero-overhead boundary fallback that
    /// guarantees 100% recall even for hashes beyond $\pm 4\sigma$.
    pub fn search_hex(&self, hex_hash: &str) -> Result<Option<SearchHit>> {
        let target = HashDigest::from_hex(hex_hash)?;
        if target.len() != self.hasher.digest_len() {
            return Err(FdhError::InvalidHex(format!(
                "expected {} hex chars for {}, got {}",
                self.hasher.digest_len() * 2,
                self.hasher.name(),
                hex_hash.trim().len()
            )));
        }
        Ok(self.search_digest(&target))
    }

    /// Searches for a pre-parsed [`HashDigest`] across all chunks in parallel.
    pub fn search_digest(&self, target: &HashDigest) -> Option<SearchHit> {
        let t0 = Instant::now();
        let header = self.dict.header();
        let total_elems = header.elements_per_chunk();
        let chunk_bits = header.chunk_bits;
        let elem_size = header.element_size as usize;
        let chunk_count = header.chunk_count;
        if chunk_count == 0 || total_elems == 0 {
            return None;
        }

        // Compute unified interpolation window for all chunks
        let predicted = target.top_bits(chunk_bits).min(total_elems - 1);
        let range = INTERPOLATION_RANGE.min(total_elems / 2);
        let win_lo = predicted.saturating_sub(range);
        let win_hi = (predicted + range).min(total_elems - 1);

        let found = AtomicBool::new(false);

        let hit = (0..chunk_count).into_par_iter().find_map_any(|slot| {
            if found.load(AtomicOrdering::Relaxed) {
                return None;
            }
            let chunk_index = header.start_chunk_index + slot;
            let chunk_data = self.dict.chunk_slice(slot);
            let mut buf = [0u8; 256];

            match self.search_window(
                chunk_data,
                chunk_index,
                chunk_bits,
                elem_size,
                win_lo,
                win_hi,
                target,
                &mut buf,
            ) {
                WindowSearchOutcome::Found { pos } => {
                    found.store(true, AtomicOrdering::Relaxed);
                    let elem = read_elem(chunk_data, pos, elem_size);
                    let s = self.decode_elem_string(chunk_index, elem, chunk_bits, &mut buf);
                    Some((s, chunk_index, pos, false))
                }
                WindowSearchOutcome::MissLeft if win_lo > 0 => {
                    if found.load(AtomicOrdering::Relaxed) {
                        return None;
                    }
                    if let Some(pos) = self.binary_search_exact(
                        chunk_data,
                        chunk_index,
                        chunk_bits,
                        elem_size,
                        0,
                        win_lo - 1,
                        target,
                        &mut buf,
                    ) {
                        found.store(true, AtomicOrdering::Relaxed);
                        let elem = read_elem(chunk_data, pos, elem_size);
                        let s = self.decode_elem_string(chunk_index, elem, chunk_bits, &mut buf);
                        Some((s, chunk_index, pos, true))
                    } else {
                        None
                    }
                }
                WindowSearchOutcome::MissRight if win_hi + 1 < total_elems => {
                    if found.load(AtomicOrdering::Relaxed) {
                        return None;
                    }
                    if let Some(pos) = self.binary_search_exact(
                        chunk_data,
                        chunk_index,
                        chunk_bits,
                        elem_size,
                        win_hi + 1,
                        total_elems - 1,
                        target,
                        &mut buf,
                    ) {
                        found.store(true, AtomicOrdering::Relaxed);
                        let elem = read_elem(chunk_data, pos, elem_size);
                        let s = self.decode_elem_string(chunk_index, elem, chunk_bits, &mut buf);
                        Some((s, chunk_index, pos, true))
                    } else {
                        None
                    }
                }
                _ => None,
            }
        });

        hit.map(|(plaintext, chunk_index, position, used_fallback)| SearchHit {
            plaintext,
            chunk_index,
            position,
            elapsed: t0.elapsed(),
            used_fallback,
        })
    }

    #[allow(clippy::too_many_arguments)]
    #[inline]
    fn search_window(
        &self,
        chunk_data: &[u8],
        chunk_index: u32,
        chunk_bits: u8,
        elem_size: usize,
        win_lo: usize,
        win_hi: usize,
        target: &HashDigest,
        buf: &mut [u8; 256],
    ) -> WindowSearchOutcome {
        let mut lo = win_lo;
        let mut hi = win_hi;
        let mut saw_less = false;
        let mut saw_greater = false;

        while lo <= hi {
            let mid = lo + ((hi - lo) >> 1);
            let elem = read_elem(chunk_data, mid, elem_size);
            let encoded = self
                .encoding
                .encode_chunk_elem(chunk_index, elem, chunk_bits, buf);
            let h = self.hasher.hash(encoded);

            match h.cmp(target) {
                Ordering::Less => {
                    saw_less = true;
                    lo = mid + 1;
                }
                Ordering::Greater => {
                    saw_greater = true;
                    if mid == 0 {
                        break;
                    }
                    hi = mid - 1;
                }
                Ordering::Equal => return WindowSearchOutcome::Found { pos: mid },
            }
        }

        if !saw_less && saw_greater {
            WindowSearchOutcome::MissLeft
        } else if saw_less && !saw_greater {
            WindowSearchOutcome::MissRight
        } else {
            WindowSearchOutcome::NotPresent
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn binary_search_exact(
        &self,
        chunk_data: &[u8],
        chunk_index: u32,
        chunk_bits: u8,
        elem_size: usize,
        mut lo: usize,
        mut hi: usize,
        target: &HashDigest,
        buf: &mut [u8; 256],
    ) -> Option<usize> {
        while lo <= hi {
            let mid = lo + ((hi - lo) >> 1);
            let elem = read_elem(chunk_data, mid, elem_size);
            let encoded = self
                .encoding
                .encode_chunk_elem(chunk_index, elem, chunk_bits, buf);
            let h = self.hasher.hash(encoded);

            match h.cmp(target) {
                Ordering::Less => lo = mid + 1,
                Ordering::Greater => {
                    if mid == 0 {
                        break;
                    }
                    hi = mid - 1;
                }
                Ordering::Equal => return Some(mid),
            }
        }
        None
    }

    fn decode_elem_string(
        &self,
        chunk_index: u32,
        elem: u32,
        chunk_bits: u8,
        buf: &mut [u8; 256],
    ) -> String {
        let bytes = self
            .encoding
            .encode_chunk_elem(chunk_index, elem, chunk_bits, buf);
        // SAFETY: `ChunkValueEncoding` always produces valid UTF-8.
        unsafe { std::str::from_utf8_unchecked(bytes) }.to_string()
    }
}

#[inline]
pub(crate) fn read_elem(chunk_data: &[u8], index: usize, elem_size: usize) -> u32 {
    let off = index * elem_size;
    match elem_size {
        3 => {
            ((chunk_data[off] as u32) << 16)
                | ((chunk_data[off + 1] as u32) << 8)
                | (chunk_data[off + 2] as u32)
        }
        4 => u32::from_be_bytes([
            chunk_data[off],
            chunk_data[off + 1],
            chunk_data[off + 2],
            chunk_data[off + 3],
        ]),
        _ => {
            let mut val = 0u32;
            for &b in &chunk_data[off..off + elem_size] {
                val = (val << 8) | (b as u32);
            }
            val
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::generator::{GenerateOptions, append_chunks, generate_dictionary};

    #[test]
    fn test_generate_append_and_search_end_to_end() {
        let dir = std::env::temp_dir().join(format!(
            "fdh_test_{}",
            std::process::id()
        ));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("test_sha256.fdh");

        // Use chunk_bits = 12 (4096 elems/chunk) for sub-second unit test
        let mut opts = GenerateOptions::new("SHA256", "0123456789", 2);
        opts.chunk_bits = 12;
        opts.threads = 2;

        let hdr = generate_dictionary(&path, &opts, |_| {}).unwrap();
        assert_eq!(hdr.chunk_count, 2);
        assert_eq!(hdr.alphabet, " 0123456789");

        // Append 1 more chunk
        let hdr2 = append_chunks(&path, 1, 2, |_| {}).unwrap();
        assert_eq!(hdr2.chunk_count, 3);

        // Search items from all 3 chunks
        let searcher = DictionarySearcher::open(&path).unwrap();
        let enc = searcher.encoding();
        let hasher = searcher.hasher();

        for chunk_idx in 0u32..3 {
            for elem in [0u32, 1, 42, 2048, 4095] {
                let val = ((chunk_idx as u64) << 12) | (elem as u64);
                let plaintext = enc.encode_u64_to_string(val);
                let hex = hasher.hash_hex(plaintext.as_bytes());
                let hit = searcher.search_hex(&hex).unwrap().expect("hash must be found");
                assert_eq!(hit.plaintext, plaintext);
                assert_eq!(hit.chunk_index, chunk_idx);
            }
        }

        // Non-existent hash should return None
        let miss_hex = hasher.hash_hex(b"definitely_not_in_small_dict_999999999");
        assert!(searcher.search_hex(&miss_hex).unwrap().is_none());

        let _ = std::fs::remove_dir_all(&dir);
    }
}
