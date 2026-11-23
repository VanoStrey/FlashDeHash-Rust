pub mod converter;
pub mod custom_dict;
pub mod encoding;
pub mod error;
pub mod format;
pub mod generator;
pub mod hash;
pub mod merger;
pub mod search;

pub use converter::{ConvertReport, convert_legacy_dir};
pub use encoding::ChunkValueEncoding;
pub use error::{FdhError, Result};
pub use format::{FDH_MAGIC, FDH_VERSION, FLAG_LEGACY_ALPHABET, FdhDictionary, FdhHeader};
pub use generator::{
    ChunkStats, DEFAULT_CHUNK_BITS, DEFAULT_ELEMENT_SIZE, GenerateOptions, append_chunks,
    generate_dictionary, recommended_threads,
};
pub use hash::{HashDigest, HashRegistry, Hasher, get_hasher};
pub use search::{DictionarySearcher, INTERPOLATION_RANGE, SearchHit};
