use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use memmap2::Mmap;

use crate::error::{FdhError, Result};

/// 8-byte magic header for `.fdh` single-file binary dictionaries.
pub const FDH_MAGIC: &[u8; 8] = b"FDH_DICT";
pub const FDH_VERSION: u16 = 1;
pub const HEADER_PAGE_SIZE: usize = 4096;

/// Flag indicating the alphabet was imported verbatim from a legacy Java dictionary
/// (e.g., without a guaranteed leading space).
pub const FLAG_LEGACY_ALPHABET: u16 = 0x0001;

/// Fixed-size binary header fields + variable metadata stored at the start of every `.fdh` file,
/// zero-padded to a 4096-byte page boundary so chunk 0 starts page-aligned for `mmap`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FdhHeader {
    pub version: u16,
    pub flags: u16,
    pub element_size: u8,
    pub chunk_bits: u8,
    pub chunk_count: u32,
    pub start_chunk_index: u32,
    pub data_offset: u64,
    pub created_unix_secs: u64,
    pub algorithm: String,
    pub alphabet: String,
}

impl FdhHeader {
    pub fn new(
        algorithm: impl Into<String>,
        alphabet: impl Into<String>,
        element_size: u8,
        chunk_bits: u8,
        chunk_count: u32,
        start_chunk_index: u32,
        flags: u16,
    ) -> Self {
        let algorithm = algorithm.into();
        let alphabet = alphabet.into();
        let raw_len = 64 + algorithm.len() + alphabet.len();
        let data_offset = raw_len.div_ceil(HEADER_PAGE_SIZE) * HEADER_PAGE_SIZE;
        let created_unix_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        Self {
            version: FDH_VERSION,
            flags,
            element_size,
            chunk_bits,
            chunk_count,
            start_chunk_index,
            data_offset: data_offset as u64,
            created_unix_secs,
            algorithm,
            alphabet,
        }
    }

    #[inline]
    pub fn elements_per_chunk(&self) -> usize {
        1usize << self.chunk_bits
    }

    #[inline]
    pub fn chunk_byte_len(&self) -> usize {
        self.elements_per_chunk() * (self.element_size as usize)
    }

    #[inline]
    pub fn total_combinations(&self) -> u128 {
        (self.chunk_count as u128) * (self.elements_per_chunk() as u128)
    }

    #[inline]
    pub fn expected_file_size(&self) -> u64 {
        self.data_offset + (self.chunk_count as u64) * (self.chunk_byte_len() as u64)
    }

    #[inline]
    pub fn is_legacy_alphabet(&self) -> bool {
        (self.flags & FLAG_LEGACY_ALPHABET) != 0
    }

    pub fn write_to<W: Write>(&self, writer: &mut W) -> Result<()> {
        let algo_bytes = self.algorithm.as_bytes();
        let alpha_bytes = self.alphabet.as_bytes();
        let needed = 64 + algo_bytes.len() + alpha_bytes.len();
        let header_size = self.data_offset as usize;
        if header_size < needed {
            return Err(FdhError::InvalidFormat(
                "data_offset smaller than metadata size".into(),
            ));
        }

        let mut buf = vec![0u8; header_size];
        buf[0..8].copy_from_slice(FDH_MAGIC);
        buf[8..10].copy_from_slice(&self.version.to_le_bytes());
        buf[10..12].copy_from_slice(&self.flags.to_le_bytes());
        buf[12] = self.element_size;
        buf[13] = self.chunk_bits;
        // 14..16 reserved = 0
        buf[16..20].copy_from_slice(&self.chunk_count.to_le_bytes());
        buf[20..24].copy_from_slice(&self.start_chunk_index.to_le_bytes());
        buf[24..32].copy_from_slice(&self.data_offset.to_le_bytes());
        buf[32..36].copy_from_slice(&(algo_bytes.len() as u32).to_le_bytes());
        buf[36..40].copy_from_slice(&(alpha_bytes.len() as u32).to_le_bytes());
        buf[40..48].copy_from_slice(&self.created_unix_secs.to_le_bytes());
        // 48..64 reserved = 0
        buf[64..64 + algo_bytes.len()].copy_from_slice(algo_bytes);
        buf[64 + algo_bytes.len()..64 + algo_bytes.len() + alpha_bytes.len()]
            .copy_from_slice(alpha_bytes);

        writer.write_all(&buf)?;
        Ok(())
    }

    pub fn read_from<R: Read>(reader: &mut R) -> Result<Self> {
        let mut fixed = [0u8; 64];
        reader.read_exact(&mut fixed)?;

        if &fixed[0..8] != FDH_MAGIC {
            return Err(FdhError::InvalidFormat(
                "invalid magic bytes (not an .fdh dictionary)".into(),
            ));
        }

        let version = u16::from_le_bytes([fixed[8], fixed[9]]);
        if version != FDH_VERSION {
            return Err(FdhError::InvalidFormat(format!(
                "unsupported .fdh version {}",
                version
            )));
        }

        let flags = u16::from_le_bytes([fixed[10], fixed[11]]);
        let element_size = fixed[12];
        let chunk_bits = fixed[13];
        let chunk_count = u32::from_le_bytes([fixed[16], fixed[17], fixed[18], fixed[19]]);
        let start_chunk_index = u32::from_le_bytes([fixed[20], fixed[21], fixed[22], fixed[23]]);
        let data_offset = u64::from_le_bytes(fixed[24..32].try_into().unwrap());
        let algo_len = u32::from_le_bytes([fixed[32], fixed[33], fixed[34], fixed[35]]) as usize;
        let alphabet_len =
            u32::from_le_bytes([fixed[36], fixed[37], fixed[38], fixed[39]]) as usize;
        let created_unix_secs = u64::from_le_bytes(fixed[40..48].try_into().unwrap());

        if !(1..=8).contains(&element_size) {
            return Err(FdhError::InvalidFormat(format!(
                "invalid element_size {}",
                element_size
            )));
        }
        if !(4..=32).contains(&chunk_bits) {
            return Err(FdhError::InvalidFormat(format!(
                "invalid chunk_bits {}",
                chunk_bits
            )));
        }
        if data_offset < (64 + algo_len + alphabet_len) as u64 {
            return Err(FdhError::InvalidFormat(
                "corrupted header: data_offset overlaps metadata".into(),
            ));
        }

        let mut algo_buf = vec![0u8; algo_len];
        reader.read_exact(&mut algo_buf)?;
        let algorithm = String::from_utf8(algo_buf)
            .map_err(|e| FdhError::InvalidFormat(format!("invalid UTF-8 in algorithm: {}", e)))?;

        let mut alpha_buf = vec![0u8; alphabet_len];
        reader.read_exact(&mut alpha_buf)?;
        let alphabet = String::from_utf8(alpha_buf)
            .map_err(|e| FdhError::InvalidFormat(format!("invalid UTF-8 in alphabet: {}", e)))?;

        Ok(Self {
            version,
            flags,
            element_size,
            chunk_bits,
            chunk_count,
            start_chunk_index,
            data_offset,
            created_unix_secs,
            algorithm,
            alphabet,
        })
    }

    pub fn read_file(path: impl AsRef<Path>) -> Result<Self> {
        let mut f = File::open(path)?;
        Self::read_from(&mut f)
    }

    /// Atomically updates only `chunk_count` (bytes 16..20) in an existing `.fdh` file.
    pub fn update_chunk_count_in_file(file: &mut File, new_chunk_count: u32) -> Result<()> {
        file.seek(SeekFrom::Start(16))?;
        file.write_all(&new_chunk_count.to_le_bytes())?;
        file.flush()?;
        Ok(())
    }
}

/// Read-only memory-mapped handle to a single-file `.fdh` dictionary.
pub struct FdhDictionary {
    path: PathBuf,
    header: FdhHeader,
    mmap: Mmap,
}

impl FdhDictionary {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let mut file = File::open(&path)?;
        let header = FdhHeader::read_from(&mut file)?;
        let file_len = file.metadata()?.len();
        let expected = header.expected_file_size();
        if file_len < expected {
            return Err(FdhError::InvalidFormat(format!(
                "truncated .fdh file: expected at least {} bytes for {} chunks, found {} bytes",
                expected, header.chunk_count, file_len
            )));
        }

        // SAFETY: The dictionary file is opened read-only for search. External concurrent
        // truncation is outside our contract; callers must not mutate a file while searching it.
        let mmap = unsafe { Mmap::map(&file)? };

        Ok(Self { path, header, mmap })
    }

    #[inline]
    pub fn path(&self) -> &Path {
        &self.path
    }

    #[inline]
    pub fn header(&self) -> &FdhHeader {
        &self.header
    }

    #[inline]
    pub fn chunk_count(&self) -> u32 {
        self.header.chunk_count
    }

    /// Returns the raw byte slice for the `slot`-th stored chunk (`0 <= slot < chunk_count`).
    /// Its logical chunk index is `header.start_chunk_index + slot`.
    #[inline]
    pub fn chunk_slice(&self, slot: u32) -> &[u8] {
        let chunk_len = self.header.chunk_byte_len();
        let start = self.header.data_offset as usize + (slot as usize) * chunk_len;
        &self.mmap[start..start + chunk_len]
    }

    /// Helper to open an existing `.fdh` file for appending new chunks.
    pub fn open_for_append(path: impl AsRef<Path>) -> Result<(File, FdhHeader)> {
        let mut file = OpenOptions::new().read(true).write(true).open(path)?;
        let header = FdhHeader::read_from(&mut file)?;
        let expected = header.expected_file_size();
        let actual = file.metadata()?.len();
        if actual < expected {
            return Err(FdhError::InvalidFormat(format!(
                "cannot append to truncated .fdh file (expected >= {} bytes, got {})",
                expected, actual
            )));
        }
        // Truncate any uncommitted trailing bytes left by an interrupted previous append
        if actual > expected {
            file.set_len(expected)?;
        }
        file.seek(SeekFrom::Start(expected))?;
        Ok((file, header))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_header_roundtrip() {
        let hdr = FdhHeader::new("SHA256", " 0123456789", 3, 24, 10, 0, 0);
        assert_eq!(hdr.data_offset, 4096);
        assert_eq!(hdr.chunk_byte_len(), 48 * 1024 * 1024);

        let mut buf = Vec::new();
        hdr.write_to(&mut buf).unwrap();
        assert_eq!(buf.len(), 4096);

        let parsed = FdhHeader::read_from(&mut Cursor::new(&buf)).unwrap();
        assert_eq!(parsed, hdr);
    }
}
