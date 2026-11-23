use std::cmp::Ordering;
use std::fs::File;
use std::io::{BufWriter, Seek, SeekFrom, Write};
use std::path::Path;
use std::sync::Arc;
use std::time::Instant;

use rayon::prelude::*;

use crate::encoding::ChunkValueEncoding;
use crate::error::{FdhError, Result};
use crate::format::{FdhDictionary, FdhHeader};
use crate::hash::{HashRegistry, Hasher};

/// Default chunk size exponent ($2^{24} = 16,777,216$ elements = 48 MiB at 3 bytes/element).
pub const DEFAULT_CHUNK_BITS: u8 = 24;
pub const DEFAULT_ELEMENT_SIZE: u8 = 3;

/// Returns a sensible default thread count (~75% of logical cores, minimum 1)
/// to maximize throughput while preventing system lag or thermal throttling.
pub fn recommended_threads() -> usize {
    let cpus = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4);
    if cpus <= 2 {
        1
    } else {
        (cpus * 3 / 4).max(1)
    }
}

#[derive(Clone, Debug)]
pub struct ChunkStats {
    pub chunk_index: u32,
    pub elements: usize,
    pub hash_ms: f64,
    pub sort_ms: f64,
    pub write_ms: f64,
    pub total_ms: f64,
}

#[derive(Clone, Debug)]
pub struct GenerateOptions {
    pub algorithm: String,
    pub alphabet: String,
    pub chunk_count: u32,
    pub chunk_bits: u8,
    pub threads: usize,
    /// When `true` (default), enforces normalized alphabet with leading space `' '`.
    /// Set to `false` only for testing legacy raw alphabets.
    pub enforce_leading_space: bool,
}

impl GenerateOptions {
    pub fn new(algorithm: impl Into<String>, alphabet: impl Into<String>, chunk_count: u32) -> Self {
        Self {
            algorithm: algorithm.into(),
            alphabet: alphabet.into(),
            chunk_count,
            chunk_bits: DEFAULT_CHUNK_BITS,
            threads: recommended_threads(),
            enforce_leading_space: true,
        }
    }
}

/// Compact 16-byte entry for flat, cache-friendly sorting (~256 MiB for $2^{24}$ elements).
#[repr(C)]
#[derive(Clone, Copy)]
struct HashEntry {
    prefix: u64,
    elem: u32,
}

/// Generates a brand-new single-file `.fdh` dictionary with `opts.chunk_count` chunks.
pub fn generate_dictionary<F>(
    output_path: impl AsRef<Path>,
    opts: &GenerateOptions,
    mut on_chunk_done: F,
) -> Result<FdhHeader>
where
    F: FnMut(&ChunkStats),
{
    if opts.chunk_count == 0 {
        return Err(FdhError::InvalidFormat(
            "chunk_count must be at least 1".into(),
        ));
    }

    let hasher = HashRegistry::with_builtins().get(&opts.algorithm)?;
    let encoding = if opts.enforce_leading_space {
        ChunkValueEncoding::new_normalized(&opts.alphabet)?
    } else {
        ChunkValueEncoding::from_raw_legacy(&opts.alphabet)?
    };

    let element_size = DEFAULT_ELEMENT_SIZE;
    if opts.chunk_bits > element_size * 8 {
        return Err(FdhError::InvalidFormat(format!(
            "chunk_bits ({}) exceeds element_size capacity ({} bits)",
            opts.chunk_bits,
            element_size * 8
        )));
    }

    let flags = if encoding.has_leading_space() {
        0
    } else {
        crate::format::FLAG_LEGACY_ALPHABET
    };

    // Write header with chunk_count = 0 initially; bump atomically after each chunk!
    let mut header = FdhHeader::new(
        hasher.name(),
        encoding.alphabet(),
        element_size,
        opts.chunk_bits,
        0,
        0,
        flags,
    );

    if let Some(parent) = output_path.as_ref().parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)?;
    }

    let mut file = File::options()
        .create(true)
        .truncate(true)
        .read(true)
        .write(true)
        .open(output_path.as_ref())?;

    header.write_to(&mut file)?;
    file.flush()?;

    let pool = build_thread_pool(opts.threads)?;
    let total_elems = header.elements_per_chunk();
    let mut entries = vec![HashEntry { prefix: 0, elem: 0 }; total_elems];

    for slot in 0..opts.chunk_count {
        let chunk_index = header.start_chunk_index + slot;
        let stats = generate_and_write_chunk(
            &pool,
            &mut file,
            &header,
            &hasher,
            &encoding,
            chunk_index,
            &mut entries,
        )?;
        header.chunk_count += 1;
        FdhHeader::update_chunk_count_in_file(&mut file, header.chunk_count)?;
        on_chunk_done(&stats);
    }

    Ok(header)
}

/// Appends `additional_chunks` new chunks to an existing `.fdh` dictionary file.
/// Safe against interruption: `chunk_count` in the header is updated only after each
/// chunk is fully written and flushed.
pub fn append_chunks<F>(
    dict_path: impl AsRef<Path>,
    additional_chunks: u32,
    threads: usize,
    mut on_chunk_done: F,
) -> Result<FdhHeader>
where
    F: FnMut(&ChunkStats),
{
    if additional_chunks == 0 {
        return Err(FdhError::InvalidFormat(
            "additional_chunks must be at least 1".into(),
        ));
    }

    let (mut file, mut header) = FdhDictionary::open_for_append(dict_path.as_ref())?;
    let hasher = HashRegistry::with_builtins().get(&header.algorithm)?;
    let encoding = ChunkValueEncoding::from_raw_legacy(&header.alphabet)?;

    let pool = build_thread_pool(threads)?;
    let total_elems = header.elements_per_chunk();
    let mut entries = vec![HashEntry { prefix: 0, elem: 0 }; total_elems];

    for _ in 0..additional_chunks {
        let chunk_index = header.start_chunk_index + header.chunk_count;
        let stats = generate_and_write_chunk(
            &pool,
            &mut file,
            &header,
            &hasher,
            &encoding,
            chunk_index,
            &mut entries,
        )?;
        header.chunk_count += 1;
        FdhHeader::update_chunk_count_in_file(&mut file, header.chunk_count)?;
        on_chunk_done(&stats);
    }

    Ok(header)
}

fn build_thread_pool(threads: usize) -> Result<rayon::ThreadPool> {
    let n = if threads == 0 {
        recommended_threads()
    } else {
        threads
    };
    rayon::ThreadPoolBuilder::new()
        .num_threads(n)
        .build()
        .map_err(|e| FdhError::InvalidFormat(format!("failed to create thread pool: {}", e)))
}

fn generate_and_write_chunk(
    pool: &rayon::ThreadPool,
    file: &mut File,
    header: &FdhHeader,
    hasher: &Arc<dyn Hasher>,
    encoding: &ChunkValueEncoding,
    chunk_index: u32,
    entries: &mut [HashEntry],
) -> Result<ChunkStats> {
    let t_total = Instant::now();
    let chunk_bits = header.chunk_bits;
    let total_elems = entries.len();

    // 1. Parallel zero-allocation hash generation
    let t_hash = Instant::now();
    let block_size = (total_elems / 256).max(1);
    pool.install(|| {
        entries
            .par_chunks_mut(block_size)
            .enumerate()
            .for_each(|(block_idx, slice)| {
                let base_elem = (block_idx * block_size) as u32;
                let mut buf = [0u8; 256];
                for (offset, entry) in slice.iter_mut().enumerate() {
                    let elem = base_elem + offset as u32;
                    let encoded = encoding.encode_chunk_elem(chunk_index, elem, chunk_bits, &mut buf);
                    let digest = hasher.hash(encoded);
                    *entry = HashEntry {
                        prefix: digest.prefix_u64(),
                        elem,
                    };
                }
            });
    });
    let hash_ms = t_hash.elapsed().as_secs_f64() * 1000.0;

    // 2. In-place 256-way American Flag MSD Radix Sort + parallel bucket sort
    let t_sort = Instant::now();
    sort_entries_in_place(pool, entries, hasher, encoding, chunk_index, chunk_bits);
    let sort_ms = t_sort.elapsed().as_secs_f64() * 1000.0;

    // 3. Stream sorted element bytes to end of `.fdh` file
    let t_write = Instant::now();
    let write_offset = header.data_offset + (header.chunk_count as u64) * (header.chunk_byte_len() as u64);
    file.seek(SeekFrom::Start(write_offset))?;

    let elem_size = header.element_size as usize;
    {
        let mut writer = BufWriter::with_capacity(4 * 1024 * 1024, &*file);
        match elem_size {
            3 => {
                for entry in entries.iter() {
                    let e = entry.elem;
                    writer.write_all(&[(e >> 16) as u8, (e >> 8) as u8, e as u8])?;
                }
            }
            4 => {
                for entry in entries.iter() {
                    writer.write_all(&entry.elem.to_be_bytes())?;
                }
            }
            _ => {
                for entry in entries.iter() {
                    let be = entry.elem.to_be_bytes();
                    writer.write_all(&be[4 - elem_size..])?;
                }
            }
        }
        writer.flush()?;
    }
    let write_ms = t_write.elapsed().as_secs_f64() * 1000.0;
    let total_ms = t_total.elapsed().as_secs_f64() * 1000.0;

    Ok(ChunkStats {
        chunk_index,
        elements: total_elems,
        hash_ms,
        sort_ms,
        write_ms,
        total_ms,
    })
}

/// In-place 256-way MSD radix partition (American Flag Sort) followed by parallel
/// comparison sort inside each bucket. Uses O(1) extra memory.
fn sort_entries_in_place(
    pool: &rayon::ThreadPool,
    entries: &mut [HashEntry],
    hasher: &Arc<dyn Hasher>,
    encoding: &ChunkValueEncoding,
    chunk_index: u32,
    chunk_bits: u8,
) {
    // Count top-byte histogram in parallel
    let counts = pool.install(|| {
        entries
            .par_chunks(65_536)
            .fold(
                || [0usize; 256],
                |mut acc, chunk| {
                    for e in chunk {
                        acc[(e.prefix >> 56) as usize] += 1;
                    }
                    acc
                },
            )
            .reduce(
                || [0usize; 256],
                |mut a, b| {
                    for i in 0..256 {
                        a[i] += b[i];
                    }
                    a
                },
            )
    });

    // Compute bucket boundaries
    let mut offsets = [0usize; 256];
    let mut ends = [0usize; 256];
    let mut sum = 0usize;
    for i in 0..256 {
        offsets[i] = sum;
        sum += counts[i];
        ends[i] = sum;
    }

    // In-place American Flag Sort permutation by top byte
    let mut cursor = offsets;
    for bucket in 0..256 {
        while cursor[bucket] < ends[bucket] {
            let idx = cursor[bucket];
            let target = (entries[idx].prefix >> 56) as usize;
            if target == bucket {
                cursor[bucket] += 1;
            } else {
                let dst = cursor[target];
                entries.swap(idx, dst);
                cursor[target] += 1;
            }
        }
    }

    // Split into 256 disjoint mutable slices and sort each bucket in parallel
    let mut buckets: Vec<&mut [HashEntry]> = Vec::with_capacity(256);
    let mut rest = entries;
    for &count in &counts {
        let (head, tail) = rest.split_at_mut(count);
        if !head.is_empty() {
            buckets.push(head);
        }
        rest = tail;
    }

    let needs_full_tiebreak = hasher.digest_len() > 8;
    pool.install(|| {
        buckets.into_par_iter().for_each(|bucket| {
            let mut buf_a = [0u8; 256];
            let mut buf_b = [0u8; 256];
            bucket.sort_unstable_by(|a, b| {
                match a.prefix.cmp(&b.prefix) {
                    Ordering::Equal => {
                        if needs_full_tiebreak {
                            let enc_a = encoding.encode_chunk_elem(
                                chunk_index,
                                a.elem,
                                chunk_bits,
                                &mut buf_a,
                            );
                            let enc_b = encoding.encode_chunk_elem(
                                chunk_index,
                                b.elem,
                                chunk_bits,
                                &mut buf_b,
                            );
                            let ha = hasher.hash(enc_a);
                            let hb = hasher.hash(enc_b);
                            ha.cmp(&hb).then_with(|| a.elem.cmp(&b.elem))
                        } else {
                            a.elem.cmp(&b.elem)
                        }
                    }
                    ord => ord,
                }
            });
        });
    });
}
