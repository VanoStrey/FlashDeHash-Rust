use std::io::{self, Write};
use std::path::PathBuf;
use std::time::Instant;

use clap::{Parser, Subcommand};
use fdh_bot::{BotConfig, format_with_dots, run_bot};
use fdh_core::{
    DEFAULT_CHUNK_BITS, DictionarySearcher, FdhHeader, GenerateOptions, HashRegistry,
    append_chunks, convert_legacy_dir, custom_dict, generate_dictionary, merger,
    recommended_threads,
};

#[derive(Parser)]
#[command(
    name = "fdh",
    version,
    about = "FlashDeHash — high-speed hash-sorted binary dictionary engine"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a new single-file `.fdh` dictionary (auto-normalizes leading space)
    Generate {
        /// Hash algorithm name (e.g. SHA256, MD5, SHA1, SHA3, BLAKE3, SHAKE128, CSHAKE128, CRC32)
        #[arg(short, long)]
        algo: String,

        /// Alphabet characters (space is automatically guaranteed at index 0)
        #[arg(short = 's', long)]
        alphabet: String,

        /// Number of chunks to generate (each 24-bit chunk = 16,777,216 entries = 48 MiB)
        #[arg(short, long)]
        chunks: u32,

        /// Output `.fdh` file path
        #[arg(short, long)]
        output: PathBuf,

        /// Worker threads (defaults to ~75% of CPU cores to prevent lag/throttling)
        #[arg(short, long, default_value_t = recommended_threads())]
        threads: usize,

        /// Log2 of elements per chunk (default: 24 => 2^24 = 16,777,216)
        #[arg(long, default_value_t = DEFAULT_CHUNK_BITS)]
        chunk_bits: u8,
    },

    /// Append additional chunks to an existing `.fdh` dictionary
    Append {
        /// Existing `.fdh` dictionary file
        #[arg(short, long)]
        dict: PathBuf,

        /// Number of new chunks to append
        #[arg(short, long)]
        chunks: u32,

        /// Worker threads (defaults to ~75% of CPU cores)
        #[arg(short, long, default_value_t = recommended_threads())]
        threads: usize,
    },

    /// Search for a hash in a `.fdh` dictionary (omit hash for interactive REPL)
    Search {
        /// Path to `.fdh` dictionary
        #[arg(short, long)]
        dict: PathBuf,

        /// Hexadecimal hash to crack (if omitted, enters interactive prompt)
        hash: Option<String>,
    },

    /// Convert a legacy Java folder (`chunk_*.bin` + `metadata.json`) into a single `.fdh` file
    Convert {
        /// Path to legacy dictionary folder
        #[arg(short, long)]
        input: PathBuf,

        /// Output `.fdh` file path
        #[arg(short, long)]
        output: PathBuf,
    },

    /// Merge power-of-two (2..=256) 3-byte chunks into 1 globally-sorted 4-byte chunk
    Merge {
        /// Input 3-byte `.fdh` dictionary
        #[arg(short, long)]
        input: PathBuf,

        /// Output 4-byte `.fdh` dictionary
        #[arg(short, long)]
        output: PathBuf,
    },

    /// Display metadata and stats for a `.fdh` dictionary
    Info {
        /// Path to `.fdh` dictionary
        dict: PathBuf,
    },

    /// Benchmark search latency and recall on random combinations inside the dictionary
    Bench {
        /// Path to `.fdh` dictionary
        #[arg(short, long)]
        dict: PathBuf,

        /// Number of random hashes to test
        #[arg(short, long, default_value_t = 100)]
        count: usize,
    },

    /// Process a plaintext wordlist into frequency-optimized binary chunks (`customChunk`)
    CustomDict {
        /// Path to plaintext wordlist file
        #[arg(short, long)]
        input: PathBuf,

        /// Output directory for `chunk_<len>.bin` and `metadata.json`
        #[arg(short, long)]
        output_dir: PathBuf,
    },

    /// Start the Telegram bot backed by a `.fdh` dictionary
    Bot {
        /// Path to `.fdh` dictionary
        #[arg(short, long)]
        dict: PathBuf,

        /// Path to `bot_config.json`
        #[arg(short, long, default_value = "bot_config.json")]
        config: PathBuf,
    },

    /// List all supported hash algorithms
    Algos,
}

fn main() {
    let cli = Cli::parse();
    if let Err(err) = run(cli) {
        eprintln!("Error: {}", err);
        std::process::exit(1);
    }
}

fn run(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    match cli.command {
        Commands::Generate {
            algo,
            alphabet,
            chunks,
            output,
            threads,
            chunk_bits,
        } => {
            let mut opts = GenerateOptions::new(algo, alphabet, chunks);
            opts.threads = threads;
            opts.chunk_bits = chunk_bits;

            println!(
                "Generating {} ({} chunks, 2^{} elems/chunk, {} threads)...",
                output.display(),
                chunks,
                chunk_bits,
                threads
            );
            let t0 = Instant::now();
            let hdr = generate_dictionary(&output, &opts, |stats| {
                println!(
                    "  [chunk #{}] hash={:.1}ms  sort={:.1}ms  write={:.1}ms  total={:.2}s",
                    stats.chunk_index,
                    stats.hash_ms,
                    stats.sort_ms,
                    stats.write_ms,
                    stats.total_ms / 1000.0
                );
            })?;
            println!(
                "Done in {:.2}s -> {} (algo={}, alphabet={:?}, combinations={})",
                t0.elapsed().as_secs_f64(),
                output.display(),
                hdr.algorithm,
                hdr.alphabet,
                format_with_dots(hdr.total_combinations())
            );
        }

        Commands::Append {
            dict,
            chunks,
            threads,
        } => {
            println!(
                "Appending {} chunk(s) to {} ({} threads)...",
                chunks,
                dict.display(),
                threads
            );
            let t0 = Instant::now();
            let hdr = append_chunks(&dict, chunks, threads, |stats| {
                println!(
                    "  [chunk #{}] hash={:.1}ms  sort={:.1}ms  write={:.1}ms  total={:.2}s",
                    stats.chunk_index,
                    stats.hash_ms,
                    stats.sort_ms,
                    stats.write_ms,
                    stats.total_ms / 1000.0
                );
            })?;
            println!(
                "Done in {:.2}s -> now {} chunks ({} combinations)",
                t0.elapsed().as_secs_f64(),
                hdr.chunk_count,
                format_with_dots(hdr.total_combinations())
            );
        }

        Commands::Search { dict, hash } => {
            let searcher = DictionarySearcher::open(&dict)?;
            if let Some(h) = hash {
                match searcher.search_hex(&h)? {
                    Some(hit) => {
                        println!(
                            "FOUND: {:?}  (chunk #{}, pos {}, {:.3} ms{})",
                            hit.plaintext,
                            hit.chunk_index,
                            hit.position,
                            hit.elapsed.as_secs_f64() * 1000.0,
                            if hit.used_fallback { ", fallback" } else { "" }
                        );
                    }
                    None => println!("NOT FOUND"),
                }
            } else {
                let hdr = searcher.header();
                println!(
                    "Interactive search: {} ({}, {} chunks, {} combinations)",
                    dict.display(),
                    hdr.algorithm,
                    hdr.chunk_count,
                    format_with_dots(hdr.total_combinations())
                );
                println!("Type a hex hash and press Enter (or 'exit' to quit):");
                let stdin = io::stdin();
                let mut line = String::new();
                loop {
                    print!("> ");
                    io::stdout().flush()?;
                    line.clear();
                    if stdin.read_line(&mut line)? == 0 {
                        break;
                    }
                    let trimmed = line.trim();
                    if trimmed.is_empty() {
                        continue;
                    }
                    if trimmed.eq_ignore_ascii_case("exit") || trimmed.eq_ignore_ascii_case("quit")
                    {
                        break;
                    }
                    let t0 = Instant::now();
                    match searcher.search_hex(trimmed) {
                        Ok(Some(hit)) => println!(
                            "  FOUND: {:?} (chunk #{}, {:.3} ms)",
                            hit.plaintext,
                            hit.chunk_index,
                            hit.elapsed.as_secs_f64() * 1000.0
                        ),
                        Ok(None) => println!(
                            "  NOT FOUND ({:.3} ms)",
                            t0.elapsed().as_secs_f64() * 1000.0
                        ),
                        Err(e) => println!("  ERROR: {}", e),
                    }
                }
            }
        }

        Commands::Convert { input, output } => {
            println!(
                "Converting legacy folder {} -> {}...",
                input.display(),
                output.display()
            );
            let t0 = Instant::now();
            let report = convert_legacy_dir(&input, &output, |done, total| {
                if done == total || done % 10 == 0 || total <= 20 {
                    println!("  copied {}/{} chunks", done, total);
                }
            })?;
            for w in &report.warnings {
                println!("  WARNING: {}", w);
            }
            println!(
                "Converted in {:.2}s ({:.2} GiB): algo={}, chunks={}, alphabet={:?}",
                t0.elapsed().as_secs_f64(),
                report.total_bytes_written as f64 / (1024.0 * 1024.0 * 1024.0),
                report.header.algorithm,
                report.header.chunk_count,
                report.header.alphabet
            );
        }

        Commands::Merge { input, output } => {
            println!(
                "Merging 3-byte chunks from {} -> 4-byte {}...",
                input.display(),
                output.display()
            );
            let t0 = Instant::now();
            let hdr = merger::merge_3b_to_4b(&input, &output, |done, total| {
                println!("  merged {} / {} ({:.1}%)", done, total, done as f64 * 100.0 / total as f64);
            })?;
            println!(
                "Merged in {:.2}s -> {} (element_size={}, 2^{} elems)",
                t0.elapsed().as_secs_f64(),
                output.display(),
                hdr.element_size,
                hdr.chunk_bits
            );
        }

        Commands::Info { dict } => {
            let hdr = FdhHeader::read_file(&dict)?;
            let size = std::fs::metadata(&dict)?.len();
            println!("File:          {}", dict.display());
            println!("Size:          {:.2} MiB ({} bytes)", size as f64 / (1024.0 * 1024.0), size);
            println!("Format:        FDH v{}", hdr.version);
            println!("Algorithm:     {}", hdr.algorithm);
            println!("Alphabet ({}): {:?}", hdr.alphabet.chars().count(), hdr.alphabet);
            println!("Legacy alpha:  {}", hdr.is_legacy_alphabet());
            println!("Element size:  {} bytes", hdr.element_size);
            println!("Chunk bits:    {} (2^{} = {} elems/chunk)", hdr.chunk_bits, hdr.chunk_bits, hdr.elements_per_chunk());
            println!("Chunks:        {} (indices {}..{})", hdr.chunk_count, hdr.start_chunk_index, hdr.start_chunk_index + hdr.chunk_count);
            println!("Combinations:  {}", format_with_dots(hdr.total_combinations()));
        }

        Commands::Bench { dict, count } => {
            let searcher = DictionarySearcher::open(&dict)?;
            let hdr = searcher.header();
            let enc = searcher.encoding();
            let hasher = searcher.hasher();
            let total_elems = hdr.elements_per_chunk() as u64;
            let total_chunks = hdr.chunk_count as u64;
            let total_space = total_chunks * total_elems;

            println!(
                "Benchmarking {} ({}, {} chunks, {} combinations, {} queries)...",
                dict.display(),
                hdr.algorithm,
                hdr.chunk_count,
                format_with_dots(hdr.total_combinations()),
                count
            );

            // Deterministic xorshift64 PRNG (zero extra dependency)
            let mut seed: u64 = 0x9e3779b97f4a7c15 ^ total_space;
            let mut next_u64 = || {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                seed
            };

            let mut samples = Vec::with_capacity(count);
            for _ in 0..count {
                let slot = (next_u64() % total_chunks) as u32;
                let elem = (next_u64() % total_elems) as u32;
                let chunk_idx = hdr.start_chunk_index + slot;
                let val = ((chunk_idx as u64) << hdr.chunk_bits) | (elem as u64);
                let plain = enc.encode_u64_to_string(val);
                let digest = hasher.hash(plain.as_bytes());
                samples.push((plain, digest));
            }

            let mut total_ns: u128 = 0;
            let mut hits = 0usize;
            let mut fallbacks = 0usize;
            for (expected, digest) in &samples {
                let t0 = Instant::now();
                let res = searcher.search_digest(digest);
                total_ns += t0.elapsed().as_nanos();
                if let Some(hit) = res {
                    if hit.plaintext == *expected || hasher.hash(hit.plaintext.as_bytes()) == *digest
                    {
                        hits += 1;
                    }
                    if hit.used_fallback {
                        fallbacks += 1;
                    }
                }
            }

            let avg_ms = (total_ns as f64 / count.max(1) as f64) / 1_000_000.0;
            println!("Recall:        {}/{} ({:.2}%)", hits, count, hits as f64 * 100.0 / count.max(1) as f64);
            println!("Fallbacks:     {}", fallbacks);
            println!("Avg latency:   {:.3} ms/hash", avg_ms);
            println!("Throughput:    {:.1} hashes/sec", 1000.0 / avg_ms.max(0.0001));
        }

        Commands::CustomDict { input, output_dir } => {
            println!("Processing wordlist {} -> {}...", input.display(), output_dir.display());
            let meta = custom_dict::process_wordlist(&input, &output_dir)?;
            println!(
                "Done: {} lines encoded ({} symbols, alphabet={:?})",
                meta.encoded_lines, meta.total_symbols, meta.dictionary_symbols
            );
            for (len, cnt) in &meta.byte_length_counts {
                println!("  {} bytes: {} entries", len, cnt);
            }
        }

        Commands::Bot { dict, config } => {
            let cfg = BotConfig::load_or_create(&config)?;
            let searcher = DictionarySearcher::open(&dict)?;
            run_bot(&cfg, &searcher)?;
        }

        Commands::Algos => {
            let reg = HashRegistry::with_builtins();
            println!("Supported hash algorithms:");
            for name in reg.list_names() {
                let h = reg.get(name)?;
                println!("  {:<12} ({} bytes / {} hex chars)", h.name(), h.digest_len(), h.digest_len() * 2);
            }
        }
    }

    Ok(())
}
