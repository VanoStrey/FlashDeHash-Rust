use std::collections::{BTreeMap, HashMap};
use std::fs::{self, File};
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::encoding::ChunkValueEncoding;
use crate::error::Result;

#[derive(Clone, Debug, Serialize)]
pub struct WordlistMetadata {
    pub dictionary_symbols: String,
    pub total_symbols: usize,
    pub total_lines: u64,
    pub encoded_lines: u64,
    pub byte_length_counts: BTreeMap<usize, u64>,
}

#[derive(Clone, Debug)]
pub struct WordlistStats {
    pub alphabet: String,
    pub char_frequencies: Vec<(char, u64)>,
    pub total_lines: u64,
}

/// Analyzes a plaintext wordlist (like `BIG-WPA-LIST-3`) and builds a frequency-sorted
/// alphabet with `' '` guaranteed at index 0.
/// Port of Java's `PasswordAlphabetGenerator` + `DictionaryProcessor::analyzeAlphabet`.
pub fn analyze_wordlist(path: impl AsRef<Path>) -> Result<WordlistStats> {
    let file = File::open(path)?;
    let reader = BufReader::with_capacity(1024 * 1024, file);
    let mut freq: HashMap<char, u64> = HashMap::new();
    let mut total_lines = 0u64;

    for line in reader.lines() {
        let line = line?;
        total_lines += 1;
        let cleaned = line.trim();
        if cleaned.is_empty() {
            continue;
        }
        for c in cleaned.chars() {
            if c != ' ' {
                *freq.entry(c).or_insert(0) += 1;
            }
        }
    }

    let mut sorted: Vec<(char, u64)> = freq.into_iter().collect();
    sorted.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));

    let mut alphabet = String::with_capacity(sorted.len() + 1);
    alphabet.push(' ');
    for &(c, _) in &sorted {
        alphabet.push(c);
    }

    Ok(WordlistStats {
        alphabet,
        char_frequencies: sorted,
        total_lines,
    })
}

/// Encodes a plaintext wordlist into length-bucketed binary chunk files (`chunk_<byteLen>.bin`)
/// plus `metadata.json`, using a frequency-sorted alphabet with leading `' '`.
/// Port of Java's `DictionaryProcessor` + `PasswordDecoder`.
pub fn process_wordlist(
    wordlist_path: impl AsRef<Path>,
    output_dir: impl AsRef<Path>,
) -> Result<WordlistMetadata> {
    let wordlist_path = wordlist_path.as_ref();
    let output_dir = output_dir.as_ref();
    fs::create_dir_all(output_dir)?;

    let stats = analyze_wordlist(wordlist_path)?;
    let encoding = ChunkValueEncoding::new_normalized(&stats.alphabet)?;

    let file = File::open(wordlist_path)?;
    let reader = BufReader::with_capacity(1024 * 1024, file);

    let mut writers: HashMap<usize, BufWriter<File>> = HashMap::new();
    let mut byte_length_counts: BTreeMap<usize, u64> = BTreeMap::new();
    let mut total_lines = 0u64;
    let mut encoded_lines = 0u64;

    for line in reader.lines() {
        let line = line?;
        total_lines += 1;
        let cleaned = line.trim();
        if cleaned.is_empty() {
            continue;
        }

        let bytes = encoding.decode_str_to_bytes(cleaned)?;
        let len = bytes.len();
        let writer = writers.entry(len).or_insert_with(|| {
            let chunk_path: PathBuf = output_dir.join(format!("chunk_{}.bin", len));
            let f = File::create(chunk_path).expect("failed to create custom chunk file");
            BufWriter::with_capacity(256 * 1024, f)
        });

        writer.write_all(&bytes)?;
        *byte_length_counts.entry(len).or_insert(0) += 1;
        encoded_lines += 1;
    }

    for (_, mut w) in writers {
        w.flush()?;
    }

    let meta = WordlistMetadata {
        dictionary_symbols: encoding.alphabet().to_string(),
        total_symbols: encoding.base(),
        total_lines,
        encoded_lines,
        byte_length_counts,
    };

    let meta_json = serde_json::to_string_pretty(&meta)?;
    fs::write(output_dir.join("metadata.json"), meta_json)?;

    Ok(meta)
}
