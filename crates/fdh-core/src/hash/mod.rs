pub mod algorithms;

use std::cmp::Ordering;
use std::sync::Arc;

use crate::error::{FdhError, Result};

/// Maximum supported digest size in bytes (512 bits).
pub const MAX_HASH_LEN: usize = 64;

/// Stack-allocated hash digest (zero heap allocations on hot paths).
#[derive(Clone, Copy, Debug)]
pub struct HashDigest {
    bytes: [u8; MAX_HASH_LEN],
    len: u8,
}

impl HashDigest {
    #[inline]
    pub fn from_slice(slice: &[u8]) -> Self {
        debug_assert!(slice.len() <= MAX_HASH_LEN);
        let mut bytes = [0u8; MAX_HASH_LEN];
        bytes[..slice.len()].copy_from_slice(slice);
        Self {
            bytes,
            len: slice.len() as u8,
        }
    }

    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len as usize]
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.len as usize
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Returns the first up-to-8 bytes packed as a big-endian `u64` (zero-padded on the right
    /// for digests shorter than 8 bytes, such as 4-byte CRC32).
    /// Preserves exact unsigned lexicographical ordering of the first 8 bytes.
    #[inline]
    pub fn prefix_u64(&self) -> u64 {
        let b = &self.bytes;
        u64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
    }

    /// Returns the top `bits` bits (1..=32) of the hash as an unsigned index for interpolation.
    #[inline]
    pub fn top_bits(&self, bits: u8) -> usize {
        debug_assert!((1..=32).contains(&bits));
        let top32 = u32::from_be_bytes([self.bytes[0], self.bytes[1], self.bytes[2], self.bytes[3]]);
        (top32 >> (32 - bits)) as usize
    }

    /// Parses a hexadecimal string into a `HashDigest`.
    pub fn from_hex(hex: &str) -> Result<Self> {
        let hex = hex.trim();
        if !hex.len().is_multiple_of(2) || hex.is_empty() || hex.len() / 2 > MAX_HASH_LEN {
            return Err(FdhError::InvalidHex(format!(
                "invalid hex length {} (must be even and 2..={})",
                hex.len(),
                MAX_HASH_LEN * 2
            )));
        }

        let raw = hex.as_bytes();
        let len = raw.len() / 2;
        let mut bytes = [0u8; MAX_HASH_LEN];
        for i in 0..len {
            let hi = decode_hex_nibble(raw[i * 2])
                .ok_or_else(|| FdhError::InvalidHex(format!("invalid hex char at index {}", i * 2)))?;
            let lo = decode_hex_nibble(raw[i * 2 + 1]).ok_or_else(|| {
                FdhError::InvalidHex(format!("invalid hex char at index {}", i * 2 + 1))
            })?;
            bytes[i] = (hi << 4) | lo;
        }

        Ok(Self {
            bytes,
            len: len as u8,
        })
    }

    /// Encodes the digest as a lowercase hexadecimal string.
    pub fn to_hex(&self) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut out = String::with_capacity(self.len as usize * 2);
        for &b in self.as_bytes() {
            out.push(HEX[(b >> 4) as usize] as char);
            out.push(HEX[(b & 0x0F) as usize] as char);
        }
        out
    }
}

#[inline]
fn decode_hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

impl PartialEq for HashDigest {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.as_bytes() == other.as_bytes()
    }
}

impl Eq for HashDigest {}

impl PartialOrd for HashDigest {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for HashDigest {
    #[inline]
    fn cmp(&self, other: &Self) -> Ordering {
        self.as_bytes().cmp(other.as_bytes())
    }
}

/// Core trait for pluggable hash algorithms.
///
/// To add a new hash function:
/// 1. Define a zero-sized struct implementing `Hasher` in `hash/algorithms.rs`.
/// 2. Register it in `HashRegistry::with_builtins()`.
pub trait Hasher: Send + Sync {
    /// Canonical uppercase algorithm name stored in `.fdh` headers (e.g. `"SHA256"`).
    fn name(&self) -> &'static str;

    /// Alternative accepted names (case-insensitive), e.g. `["SHA-256"]`.
    fn aliases(&self) -> &'static [&'static str] {
        &[]
    }

    /// Digest output length in bytes (e.g. 32 for SHA-256, 4 for CRC32).
    fn digest_len(&self) -> usize;

    /// Computes the hash of `input` into `out[..self.digest_len()]` with zero heap allocations.
    fn hash_into(&self, input: &[u8], out: &mut [u8]);

    /// Convenience helper returning a stack-allocated `HashDigest`.
    #[inline]
    fn hash(&self, input: &[u8]) -> HashDigest {
        let mut bytes = [0u8; MAX_HASH_LEN];
        let len = self.digest_len();
        self.hash_into(input, &mut bytes[..len]);
        HashDigest {
            bytes,
            len: len as u8,
        }
    }

    /// Convenience helper returning lowercase hex string.
    fn hash_hex(&self, input: &[u8]) -> String {
        self.hash(input).to_hex()
    }
}

/// Registry of available hash algorithms (supports built-in + custom runtime registration).
pub struct HashRegistry {
    hashers: Vec<Arc<dyn Hasher>>,
}

impl HashRegistry {
    pub fn with_builtins() -> Self {
        let mut reg = Self {
            hashers: Vec::new(),
        };
        reg.register(Arc::new(algorithms::Sha256Hasher));
        reg.register(Arc::new(algorithms::Md5Hasher));
        reg.register(Arc::new(algorithms::Sha1Hasher));
        reg.register(Arc::new(algorithms::Sha3_256Hasher));
        reg.register(Arc::new(algorithms::Blake3Hasher));
        reg.register(Arc::new(algorithms::Shake128Hasher));
        reg.register(Arc::new(algorithms::CShake128Hasher));
        reg.register(Arc::new(algorithms::Crc32Hasher));
        reg
    }

    pub fn register(&mut self, hasher: Arc<dyn Hasher>) {
        self.hashers.push(hasher);
    }

    pub fn get(&self, name: &str) -> Result<Arc<dyn Hasher>> {
        let needle = name.trim().to_ascii_uppercase();
        for h in &self.hashers {
            if h.name().eq_ignore_ascii_case(&needle)
                || h.aliases().iter().any(|a| a.eq_ignore_ascii_case(&needle))
            {
                return Ok(Arc::clone(h));
            }
        }
        Err(FdhError::UnknownAlgorithm(name.to_string()))
    }

    pub fn list_names(&self) -> Vec<&'static str> {
        self.hashers.iter().map(|h| h.name()).collect()
    }
}

impl Default for HashRegistry {
    fn default() -> Self {
        Self::with_builtins()
    }
}

/// Shortcut to resolve a built-in hasher by name.
pub fn get_hasher(name: &str) -> Result<Arc<dyn Hasher>> {
    HashRegistry::with_builtins().get(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_builtin_known_vectors() {
        let reg = HashRegistry::with_builtins();

        assert_eq!(
            reg.get("SHA256").unwrap().hash_hex(b"123"),
            "a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3"
        );
        assert_eq!(
            reg.get("MD5").unwrap().hash_hex(b"123"),
            "202cb962ac59075b964b07152d234b70"
        );
        assert_eq!(
            reg.get("SHA1").unwrap().hash_hex(b"123"),
            "40bd001563085fc35165329ea1ff5c5ecbdbbeef"
        );
        assert_eq!(
            reg.get("SHA3").unwrap().hash_hex(b"123"),
            "a03ab19b866fc585b5cb1812a2f63ca861e7e7643ee5d43fd7106b623725fd67"
        );
        assert_eq!(
            reg.get("CRC32").unwrap().hash_hex(b"123"),
            "884863d2"
        );
        assert_eq!(reg.get("BLAKE3").unwrap().digest_len(), 32);
        assert_eq!(reg.get("SHAKE128").unwrap().digest_len(), 32);
        assert_eq!(reg.get("CSHAKE128").unwrap().digest_len(), 32);
    }

    #[test]
    fn test_digest_ordering_and_hex() {
        let a = HashDigest::from_hex("000001ff").unwrap();
        let b = HashDigest::from_hex("00000200").unwrap();
        assert!(a < b);
        assert!(a.prefix_u64() < b.prefix_u64());
        assert_eq!(a.top_bits(24), 1);
        assert_eq!(b.top_bits(24), 2);
        assert_eq!(a.to_hex(), "000001ff");
    }
}
