use std::cmp::Ordering;
use std::collections::BinaryHeap;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::Path;

use crate::encoding::ChunkValueEncoding;
use crate::error::{FdhError, Result};
use crate::format::{FdhDictionary, FdhHeader};
use crate::hash::{HashDigest, HashRegistry};
use crate::search::read_elem;

#[derive(Clone, Eq, PartialEq)]
struct MergeNode {
    hash: HashDigest,
    global_elem: u32,
    slot: usize,
    pos: usize,
}

// Min-heap ordering (reverse Ord for BinaryHeap)
impl Ord for MergeNode {
    fn cmp(&self, other: &Self) -> Ordering {
        other
            .hash
            .cmp(&self.hash)
            .then_with(|| other.global_elem.cmp(&self.global_elem))
    }
}

impl PartialOrd for MergeNode {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Clean Rust port of `Convert3bChunkTo4b`:
/// Performs an exact k-way merge of up to 256 sorted 3-byte chunks from a `.fdh` dictionary
/// into a single globally sorted 4-byte-per-element `.fdh` file (1 chunk of $k \times 2^{24}$
/// or power-of-two merged chunk).
pub fn merge_3b_to_4b<F>(
    input_fdh: impl AsRef<Path>,
    output_fdh: impl AsRef<Path>,
    mut on_progress: F,
) -> Result<FdhHeader>
where
    F: FnMut(u64, u64),
{
    let dict = FdhDictionary::open(input_fdh)?;
    let in_hdr = dict.header();
    if in_hdr.element_size != 3 {
        return Err(FdhError::InvalidFormat(format!(
            "merge_3b_to_4b requires element_size=3, got {}",
            in_hdr.element_size
        )));
    }
    let k = in_hdr.chunk_count as usize;
    if k == 0 || k > 256 || !k.is_power_of_two() {
        return Err(FdhError::InvalidFormat(format!(
            "merge_3b_to_4b requires a power-of-two chunk_count in 1..=256, got {}",
            k
        )));
    }

    let hasher = HashRegistry::with_builtins().get(&in_hdr.algorithm)?;
    let encoding = ChunkValueEncoding::from_raw_legacy(&in_hdr.alphabet)?;
    let elems_per_chunk = in_hdr.elements_per_chunk();
    let chunk_bits = in_hdr.chunk_bits;
    let merged_bits = chunk_bits + (k.trailing_zeros() as u8);
    let total_elems = (k as u64) * (elems_per_chunk as u64);

    let out_hdr = FdhHeader::new(
        &in_hdr.algorithm,
        &in_hdr.alphabet,
        4,
        merged_bits,
        1,
        in_hdr.start_chunk_index / (k as u32),
        in_hdr.flags,
    );

    let out_file = File::create(output_fdh)?;
    let mut writer = BufWriter::with_capacity(16 * 1024 * 1024, out_file);
    out_hdr.write_to(&mut writer)?;

    let mut heap = BinaryHeap::with_capacity(k);
    let mut buf = [0u8; 256];

    for slot in 0..k {
        let chunk_idx = in_hdr.start_chunk_index + slot as u32;
        let data = dict.chunk_slice(slot as u32);
        let elem = read_elem(data, 0, 3);
        let global_elem = ((slot as u32) << chunk_bits) | elem;
        let enc = encoding.encode_chunk_elem(chunk_idx, elem, chunk_bits, &mut buf);
        let hash = hasher.hash(enc);
        heap.push(MergeNode {
            hash,
            global_elem,
            slot,
            pos: 0,
        });
    }

    let mut written = 0u64;
    while let Some(node) = heap.pop() {
        writer.write_all(&node.global_elem.to_be_bytes())?;
        written += 1;

        if written.is_multiple_of(1_000_000) {
            on_progress(written, total_elems);
        }

        let next_pos = node.pos + 1;
        if next_pos < elems_per_chunk {
            let chunk_idx = in_hdr.start_chunk_index + node.slot as u32;
            let data = dict.chunk_slice(node.slot as u32);
            let elem = read_elem(data, next_pos, 3);
            let global_elem = ((node.slot as u32) << chunk_bits) | elem;
            let enc = encoding.encode_chunk_elem(chunk_idx, elem, chunk_bits, &mut buf);
            let hash = hasher.hash(enc);
            heap.push(MergeNode {
                hash,
                global_elem,
                slot: node.slot,
                pos: next_pos,
            });
        }
    }

    writer.flush()?;
    on_progress(written, total_elems);
    Ok(out_hdr)
}
