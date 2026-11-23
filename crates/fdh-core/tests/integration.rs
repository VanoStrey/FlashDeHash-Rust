use std::fs;
use std::path::PathBuf;

use fdh_core::{
    DictionarySearcher, GenerateOptions, HashRegistry, append_chunks, convert_legacy_dir,
    custom_dict, generate_dictionary, merger,
};

fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("fdh_int_{}_{}", name, std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn test_all_hash_algorithms_generate_and_search() {
    let dir = temp_dir("all_algos");
    let reg = HashRegistry::with_builtins();

    for algo in reg.list_names() {
        let path = dir.join(format!("{}.fdh", algo));
        let mut opts = GenerateOptions::new(algo, "0123456789abcdef", 2);
        opts.chunk_bits = 10; // 1024 elems/chunk
        opts.threads = 2;

        let hdr = generate_dictionary(&path, &opts, |_| {}).unwrap();
        assert_eq!(hdr.algorithm, algo);
        assert_eq!(hdr.alphabet, " 0123456789abcdef");

        let searcher = DictionarySearcher::open(&path).unwrap();
        let enc = searcher.encoding();
        let hasher = searcher.hasher();

        for chunk_idx in 0..2u32 {
            for elem in [0u32, 1, 511, 1023] {
                let val = ((chunk_idx as u64) << 10) | (elem as u64);
                let plain = enc.encode_u64_to_string(val);
                let hex = hasher.hash_hex(plain.as_bytes());
                let hit = searcher
                    .search_hex(&hex)
                    .unwrap()
                    .unwrap_or_else(|| panic!("{} failed to find {:?}", algo, plain));
                // Verify hash matches (handles rare CRC32 collisions too)
                assert_eq!(hasher.hash_hex(hit.plaintext.as_bytes()), hex);
            }
        }
    }

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_legacy_conversion_with_appledouble_and_cshake_stub_detection() {
    let dir = temp_dir("legacy_conv");
    let legacy_dir = dir.join("chunks_CSHAKE128_[0-9]");
    fs::create_dir_all(&legacy_dir).unwrap();

    // Generate a 2-chunk SHA3 dictionary with legacy raw alphabet "0123456789" (no leading space)
    let tmp_fdh = dir.join("tmp_sha3.fdh");
    let mut opts = GenerateOptions::new("SHA3", "0123456789", 2);
    opts.chunk_bits = 10;
    opts.threads = 2;
    opts.enforce_leading_space = false;
    generate_dictionary(&tmp_fdh, &opts, |_| {}).unwrap();

    // Extract raw chunks into legacy folder format with `CSHAKE128` in metadata.json
    let dict = fdh_core::FdhDictionary::open(&tmp_fdh).unwrap();
    fs::write(legacy_dir.join("chunk_0.bin"), dict.chunk_slice(0)).unwrap();
    fs::write(legacy_dir.join("chunk_1.bin"), dict.chunk_slice(1)).unwrap();
    // Add macOS AppleDouble junk file to verify converter ignores it
    fs::write(legacy_dir.join("._chunk_0.bin"), b"Mac OS X junk").unwrap();
    fs::write(
        legacy_dir.join("metadata.json"),
        r#"{
  "dictionary_symbols": "0123456789",
  "hash_algorithm": "CSHAKE128",
  "element_size": "3"
}"#,
    )
    .unwrap();

    let converted_path = dir.join("converted.fdh");
    let report = convert_legacy_dir(&legacy_dir, &converted_path, |_, _| {}).unwrap();

    // Auto-detected Java CSHAKE128 stub -> remapped to SHA3
    assert_eq!(report.header.algorithm, "SHA3");
    assert_eq!(report.header.alphabet, "0123456789");
    assert!(report.header.is_legacy_alphabet());
    assert_eq!(report.header.chunk_count, 2);
    assert!(
        report
            .warnings
            .iter()
            .any(|w| w.contains("CSHAKE128"))
    );

    // Search converted dictionary
    let searcher = DictionarySearcher::open(&converted_path).unwrap();
    let hex = searcher.hasher().hash_hex(b"123");
    let hit = searcher.search_hex(&hex).unwrap().expect("must find 123");
    assert_eq!(hit.plaintext, "123");

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_merge_3b_to_4b_and_search() {
    let dir = temp_dir("merge");
    let in_path = dir.join("in_3b.fdh");
    let out_path = dir.join("out_4b.fdh");

    let mut opts = GenerateOptions::new("SHA256", "0123456789", 4);
    opts.chunk_bits = 10; // 4 * 1024 = 4096 elems -> merged chunk_bits = 12
    opts.threads = 2;
    generate_dictionary(&in_path, &opts, |_| {}).unwrap();

    let merged_hdr = merger::merge_3b_to_4b(&in_path, &out_path, |_, _| {}).unwrap();
    assert_eq!(merged_hdr.element_size, 4);
    assert_eq!(merged_hdr.chunk_bits, 12);
    assert_eq!(merged_hdr.chunk_count, 1);

    let searcher = DictionarySearcher::open(&out_path).unwrap();
    let enc = searcher.encoding();
    let hasher = searcher.hasher();
    for val in [0u64, 7, 1024, 2048, 4095] {
        let plain = enc.encode_u64_to_string(val);
        let hex = hasher.hash_hex(plain.as_bytes());
        let hit = searcher.search_hex(&hex).unwrap().expect("must find in merged 4b dict");
        assert_eq!(hit.plaintext, plain);
    }

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_custom_wordlist_processor() {
    let dir = temp_dir("custom_dict");
    let wordlist = dir.join("passwords.txt");
    let out_dir = dir.join("chunks_out");
    fs::write(&wordlist, "password\n123456\nhello\nworld\n\n  qwerty  \n").unwrap();

    let meta = custom_dict::process_wordlist(&wordlist, &out_dir).unwrap();
    assert_eq!(meta.encoded_lines, 5);
    assert!(meta.dictionary_symbols.starts_with(' '));
    assert!(out_dir.join("metadata.json").exists());

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_append_preserves_existing_and_adds_new() {
    let dir = temp_dir("append");
    let path = dir.join("dict.fdh");

    let mut opts = GenerateOptions::new("BLAKE3", "abc", 1);
    opts.chunk_bits = 10;
    opts.threads = 2;
    generate_dictionary(&path, &opts, |_| {}).unwrap();
    append_chunks(&path, 2, 2, |_| {}).unwrap();

    let searcher = DictionarySearcher::open(&path).unwrap();
    assert_eq!(searcher.header().chunk_count, 3);
    // Element in chunk #2
    let val = (2u64 << 10) | 777;
    let plain = searcher.encoding().encode_u64_to_string(val);
    let hex = searcher.hasher().hash_hex(plain.as_bytes());
    let hit = searcher.search_hex(&hex).unwrap().expect("must find in appended chunk #2");
    assert_eq!(hit.plaintext, plain);
    assert_eq!(hit.chunk_index, 2);

    let _ = fs::remove_dir_all(&dir);
}
