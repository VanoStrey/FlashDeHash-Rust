use md5::Md5;
use sha1::Sha1;
use sha2::{Digest, Sha256};
use sha3::{
    Sha3_256, Shake128,
    digest::{ExtendableOutput, Update, XofReader},
};

use super::Hasher;

pub struct Sha256Hasher;
impl Hasher for Sha256Hasher {
    fn name(&self) -> &'static str {
        "SHA256"
    }
    fn aliases(&self) -> &'static [&'static str] {
        &["SHA-256"]
    }
    fn digest_len(&self) -> usize {
        32
    }
    #[inline]
    fn hash_into(&self, input: &[u8], out: &mut [u8]) {
        let res = Sha256::digest(input);
        out.copy_from_slice(&res);
    }
}

pub struct Md5Hasher;
impl Hasher for Md5Hasher {
    fn name(&self) -> &'static str {
        "MD5"
    }
    fn digest_len(&self) -> usize {
        16
    }
    #[inline]
    fn hash_into(&self, input: &[u8], out: &mut [u8]) {
        let res = Md5::digest(input);
        out.copy_from_slice(&res);
    }
}

pub struct Sha1Hasher;
impl Hasher for Sha1Hasher {
    fn name(&self) -> &'static str {
        "SHA1"
    }
    fn aliases(&self) -> &'static [&'static str] {
        &["SHA-1"]
    }
    fn digest_len(&self) -> usize {
        20
    }
    #[inline]
    fn hash_into(&self, input: &[u8], out: &mut [u8]) {
        let res = Sha1::digest(input);
        out.copy_from_slice(&res);
    }
}

pub struct Sha3_256Hasher;
impl Hasher for Sha3_256Hasher {
    fn name(&self) -> &'static str {
        "SHA3"
    }
    fn aliases(&self) -> &'static [&'static str] {
        &["SHA3-256", "SHA3_256"]
    }
    fn digest_len(&self) -> usize {
        32
    }
    #[inline]
    fn hash_into(&self, input: &[u8], out: &mut [u8]) {
        let res = Sha3_256::digest(input);
        out.copy_from_slice(&res);
    }
}

pub struct Blake3Hasher;
impl Hasher for Blake3Hasher {
    fn name(&self) -> &'static str {
        "BLAKE3"
    }
    fn aliases(&self) -> &'static [&'static str] {
        &["BLAKE3-256"]
    }
    fn digest_len(&self) -> usize {
        32
    }
    #[inline]
    fn hash_into(&self, input: &[u8], out: &mut [u8]) {
        let res = blake3::hash(input);
        out.copy_from_slice(res.as_bytes());
    }
}

pub struct Shake128Hasher;
impl Hasher for Shake128Hasher {
    fn name(&self) -> &'static str {
        "SHAKE128"
    }
    fn digest_len(&self) -> usize {
        32
    }
    #[inline]
    fn hash_into(&self, input: &[u8], out: &mut [u8]) {
        let mut hasher = Shake128::default();
        hasher.update(input);
        let mut reader = hasher.finalize_xof();
        reader.read(out);
    }
}

/// NIST SP 800-185 cSHAKE128 with empty function-name N="" and customization S="".
/// Per NIST SP 800-185 Section 3.3, cSHAKE128(X, L, "", "") == SHAKE128(X, L).
pub struct CShake128Hasher;
impl Hasher for CShake128Hasher {
    fn name(&self) -> &'static str {
        "CSHAKE128"
    }
    fn digest_len(&self) -> usize {
        32
    }
    #[inline]
    fn hash_into(&self, input: &[u8], out: &mut [u8]) {
        let mut hasher = Shake128::default();
        hasher.update(input);
        let mut reader = hasher.finalize_xof();
        reader.read(out);
    }
}

pub struct Crc32Hasher;
impl Hasher for Crc32Hasher {
    fn name(&self) -> &'static str {
        "CRC32"
    }
    fn aliases(&self) -> &'static [&'static str] {
        &["CRC-32"]
    }
    fn digest_len(&self) -> usize {
        4
    }
    #[inline]
    fn hash_into(&self, input: &[u8], out: &mut [u8]) {
        let crc = crc32fast::hash(input);
        out.copy_from_slice(&crc.to_be_bytes());
    }
}
