use std::collections::{HashMap, HashSet};

use crate::error::{FdhError, Result};

/// Zero-allocation positional base-N encoder/decoder compatible with Java `ChunkValueEncoding`.
///
/// For newly generated dictionaries, use [`ChunkValueEncoding::new_normalized`] which guarantees
/// that ASCII space `' '` is always placed at index `0` (with deduplication and validation),
/// so every real symbol in the user's alphabet can appear as a leading character in multi-char
/// strings.
///
/// For legacy dictionaries converted from Java (where `dictionary_symbols` may lack a leading
/// space, e.g. `"0123456789"`), use [`ChunkValueEncoding::from_raw_legacy`] to preserve exact
/// bit-for-bit compatibility.
#[derive(Clone, Debug)]
pub struct ChunkValueEncoding {
    raw: String,
    chars: Vec<char>,
    ascii_bytes: Option<Vec<u8>>,
    char_to_index: HashMap<char, usize>,
    base: u64,
    base_is_pow2: bool,
    base_log2: u32,
}

impl ChunkValueEncoding {
    /// Normalizes a user-supplied alphabet for new dictionaries:
    /// - Deduplicates characters while preserving order
    /// - Guarantees `' '` (ASCII space) is at index 0 and appears nowhere else
    /// - Rejects alphabets with fewer than 1 non-space character (total base < 2)
    pub fn new_normalized(input: &str) -> Result<Self> {
        let mut seen = HashSet::new();
        let mut normalized = String::with_capacity(input.len() + 1);
        normalized.push(' ');
        seen.insert(' ');

        for c in input.chars() {
            if seen.insert(c) {
                normalized.push(c);
            }
        }

        if normalized.chars().count() < 2 {
            return Err(FdhError::InvalidAlphabet(
                "alphabet must contain at least 1 non-space character".into(),
            ));
        }

        Self::build(normalized)
    }

    /// Creates an encoder from an exact raw alphabet string (for loading `.fdh` files or
    /// converting legacy Java dictionaries without altering symbol indices).
    pub fn from_raw_legacy(raw: &str) -> Result<Self> {
        let mut seen = HashSet::new();
        for c in raw.chars() {
            if !seen.insert(c) {
                return Err(FdhError::InvalidAlphabet(format!(
                    "duplicate character '{}' in alphabet",
                    c
                )));
            }
        }
        if seen.len() < 2 {
            return Err(FdhError::InvalidAlphabet(
                "alphabet must contain at least 2 unique characters".into(),
            ));
        }
        Self::build(raw.to_string())
    }

    fn build(raw: String) -> Result<Self> {
        let chars: Vec<char> = raw.chars().collect();
        let base = chars.len() as u64;
        debug_assert!(base >= 2);

        let ascii_bytes = if chars.iter().all(|c| c.is_ascii()) {
            Some(chars.iter().map(|&c| c as u8).collect())
        } else {
            None
        };

        let mut char_to_index = HashMap::with_capacity(chars.len());
        for (idx, &c) in chars.iter().enumerate() {
            char_to_index.insert(c, idx);
        }

        let base_is_pow2 = base.is_power_of_two();
        let base_log2 = if base_is_pow2 {
            base.trailing_zeros()
        } else {
            0
        };

        Ok(Self {
            raw,
            chars,
            ascii_bytes,
            char_to_index,
            base,
            base_is_pow2,
            base_log2,
        })
    }

    #[inline]
    pub fn alphabet(&self) -> &str {
        &self.raw
    }

    #[inline]
    pub fn base(&self) -> usize {
        self.chars.len()
    }

    #[inline]
    pub fn has_leading_space(&self) -> bool {
        self.chars.first() == Some(&' ')
    }

    /// Encodes a 48-bit (or up to 64-bit) unsigned integer into UTF-8 bytes inside `buf`
    /// with ZERO heap allocations.
    ///
    /// Buffer of 256 bytes is enough even for 64-bit binary (`base = 2`) with 4-byte UTF-8 chars.
    #[inline]
    pub fn encode_u64_to_utf8<'a>(&self, mut num: u64, buf: &'a mut [u8; 256]) -> &'a [u8] {
        if let Some(ref ascii) = self.ascii_bytes {
            let mut pos = buf.len();
            if num == 0 {
                pos -= 1;
                buf[pos] = ascii[0];
                return &buf[pos..];
            }

            if self.base_is_pow2 {
                let shift = self.base_log2;
                let mask = self.base - 1;
                while num != 0 {
                    pos -= 1;
                    buf[pos] = ascii[(num & mask) as usize];
                    num >>= shift;
                }
            } else {
                let base = self.base;
                while num != 0 {
                    let q = num / base;
                    let r = (num - q * base) as usize;
                    pos -= 1;
                    buf[pos] = ascii[r];
                    num = q;
                }
            }
            &buf[pos..]
        } else {
            self.encode_u64_unicode(num, buf)
        }
    }

    fn encode_u64_unicode<'a>(&self, mut num: u64, buf: &'a mut [u8; 256]) -> &'a [u8] {
        let mut pos = buf.len();
        let mut tmp = [0u8; 4];

        if num == 0 {
            let s = self.chars[0].encode_utf8(&mut tmp);
            pos -= s.len();
            buf[pos..pos + s.len()].copy_from_slice(s.as_bytes());
            return &buf[pos..];
        }

        let base = self.base;
        while num != 0 {
            let q = num / base;
            let r = (num - q * base) as usize;
            let s = self.chars[r].encode_utf8(&mut tmp);
            pos -= s.len();
            buf[pos..pos + s.len()].copy_from_slice(s.as_bytes());
            num = q;
        }
        &buf[pos..]
    }

    /// Combines `(chunk_index << chunk_bits) | elem` and encodes into UTF-8 bytes without allocating.
    #[inline]
    pub fn encode_chunk_elem<'a>(
        &self,
        chunk_index: u32,
        elem: u32,
        chunk_bits: u8,
        buf: &'a mut [u8; 256],
    ) -> &'a [u8] {
        let global_val = ((chunk_index as u64) << chunk_bits) | (elem as u64);
        self.encode_u64_to_utf8(global_val, buf)
    }

    /// Convenience helper returning an owned `String` for a `u64` value.
    pub fn encode_u64_to_string(&self, num: u64) -> String {
        let mut buf = [0u8; 256];
        let bytes = self.encode_u64_to_utf8(num, &mut buf);
        // SAFETY: `encode_u64_to_utf8` always writes valid UTF-8 characters.
        unsafe { std::str::from_utf8_unchecked(bytes) }.to_string()
    }

    /// Encodes an arbitrary-length big-endian unsigned byte slice into a base-N string.
    /// Equivalent to Java's `ChunkValueEncoding.convertToBaseString(byte[])`.
    pub fn encode_bytes_to_string(&self, bytes: &[u8]) -> String {
        if bytes.len() <= 8 {
            let mut val = 0u64;
            for &b in bytes {
                val = (val << 8) | (b as u64);
            }
            return self.encode_u64_to_string(val);
        }

        // Arbitrary-precision base-256 -> base-N division
        let mut digits: Vec<u8> = bytes.to_vec();
        let mut out_chars = Vec::new();
        let base = self.base as u32;

        loop {
            let mut rem: u32 = 0;
            let mut all_zero = true;
            for byte in &mut digits {
                let acc = (rem << 8) | (*byte as u32);
                let q = acc / base;
                rem = acc % base;
                *byte = q as u8;
                if q != 0 {
                    all_zero = false;
                }
            }
            out_chars.push(self.chars[rem as usize]);
            if all_zero {
                break;
            }
        }

        out_chars.reverse();
        out_chars.into_iter().collect()
    }

    /// Decodes a base-N string back into minimal big-endian unsigned bytes.
    /// Equivalent to Java's `ChunkValueEncoding.decodeFromString(String)`.
    pub fn decode_str_to_bytes(&self, encoded: &str) -> Result<Vec<u8>> {
        if encoded.is_empty() {
            return Err(FdhError::Encoding("cannot decode empty string".into()));
        }

        let base = self.base as u32;
        // Little-endian base-256 accumulator
        let mut bytes_le: Vec<u8> = vec![0];

        for c in encoded.chars() {
            let &digit = self.char_to_index.get(&c).ok_or_else(|| {
                FdhError::Encoding(format!("character '{}' is not in alphabet", c))
            })?;

            let mut carry = digit as u32;
            for b in &mut bytes_le {
                let acc = (*b as u32) * base + carry;
                *b = (acc & 0xFF) as u8;
                carry = acc >> 8;
            }
            while carry > 0 {
                bytes_le.push((carry & 0xFF) as u8);
                carry >>= 8;
            }
        }

        while bytes_le.len() > 1 && bytes_le.last() == Some(&0) {
            bytes_le.pop();
        }
        bytes_le.reverse();
        Ok(bytes_le)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalization_foolproofing() {
        let enc1 = ChunkValueEncoding::new_normalized("0123456789").unwrap();
        assert_eq!(enc1.alphabet(), " 0123456789");
        assert!(enc1.has_leading_space());

        // Already has leading space -> no double space
        let enc2 = ChunkValueEncoding::new_normalized(" 0123456789").unwrap();
        assert_eq!(enc2.alphabet(), " 0123456789");

        // Space in the middle + duplicates -> moved to index 0 and deduplicated
        let enc3 = ChunkValueEncoding::new_normalized("012 34 012").unwrap();
        assert_eq!(enc3.alphabet(), " 01234");

        // Only spaces -> error
        assert!(ChunkValueEncoding::new_normalized("   ").is_err());
        assert!(ChunkValueEncoding::new_normalized("").is_err());
    }

    #[test]
    fn test_legacy_decimal_compatibility() {
        let enc = ChunkValueEncoding::from_raw_legacy("0123456789").unwrap();
        assert_eq!(enc.encode_u64_to_string(0), "0");
        assert_eq!(enc.encode_u64_to_string(123), "123");
        assert_eq!(enc.encode_u64_to_string(16_777_215), "16777215");

        // Chunk 1, elem 0 => 1 << 24 = 16777216
        let mut buf = [0u8; 256];
        let s = enc.encode_chunk_elem(1, 0, 24, &mut buf);
        assert_eq!(s, b"16777216");
    }

    #[test]
    fn test_pow2_and_unicode_and_roundtrip() {
        let hex_enc = ChunkValueEncoding::from_raw_legacy("0123456789abcdef").unwrap();
        assert_eq!(hex_enc.encode_u64_to_string(0), "0");
        assert_eq!(hex_enc.encode_u64_to_string(0xdeadbeef), "deadbeef");

        let uni_enc = ChunkValueEncoding::new_normalized("абвг").unwrap();
        assert_eq!(uni_enc.alphabet(), " абвг");
        assert_eq!(uni_enc.encode_u64_to_string(0), " ");
        assert_eq!(uni_enc.encode_u64_to_string(1), "а");
        assert_eq!(uni_enc.encode_u64_to_string(5), "а ");
        assert_eq!(uni_enc.encode_u64_to_string(6), "аа");

        // Arbitrary-precision roundtrip (> 64 bits)
        let big_str = "абвгабвгабвгабвгабвгабвгабвгабвгабвгабвг";
        let bytes = uni_enc.decode_str_to_bytes(big_str).unwrap();
        assert_eq!(uni_enc.encode_bytes_to_string(&bytes), big_str);
    }
}
