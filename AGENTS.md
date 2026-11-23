# AGENTS.md — FlashDeHash (Rust) Topology & Architectural Invariants

## 1. Quick File-to-Feature Topology Map

| Feature / Area | Crate | Primary File(s) |
|---|---|---|
| **Pluggable Hasher Trait & Registry** | `fdh-core` | `crates/fdh-core/src/hash/mod.rs`, `crates/fdh-core/src/hash/algorithms.rs` |
| **Base-N Encoding & Leading-Space Normalization** | `fdh-core` | `crates/fdh-core/src/encoding.rs` |
| **Single-File `.fdh` Container Format v1** | `fdh-core` | `crates/fdh-core/src/format.rs` |
| **Low-RAM Parallel Chunk Generator & Append** | `fdh-core` | `crates/fdh-core/src/generator.rs` |
| **mmap Interpolation + Exact Fallback Search** | `fdh-core` | `crates/fdh-core/src/search.rs` |
| **Legacy Folder -> `.fdh` Converter** | `fdh-core` | `crates/fdh-core/src/converter.rs` |
| **3-byte -> 4-byte K-Way Chunk Merger** | `fdh-core` | `crates/fdh-core/src/merger.rs` |
| **Custom Wordlist Processor (`customChunk`)** | `fdh-core` | `crates/fdh-core/src/custom_dict.rs` |
| **Telegram Bot (Long-Polling)** | `fdh-bot` | `crates/fdh-bot/src/lib.rs` |
| **CLI (`fdh`)** | `fdh-cli` | `crates/fdh-cli/src/main.rs` |
| **Native Desktop GUI (`fdh-gui`)** | `fdh-gui` | `crates/fdh-gui/src/main.rs` |

---

## 2. Sacred Architectural Invariants

1. **Zero-Hash-Storage Contract**: `.fdh` files store only sorted element indices (3 bytes/entry for $2^{24}$ chunks, or 4 bytes for merged chunks), never the hashes.
2. **Alphabet Foolproofing & Legacy Compatibility**:
   - New dictionaries MUST normalize alphabets via `ChunkValueEncoding::new_normalized` (deduplicated, ASCII space `' '` guaranteed at index `0`).
   - Existing `.fdh` files and legacy Java folders MUST load via `ChunkValueEncoding::from_raw_legacy` so symbol indices remain bit-for-bit identical.
3. **100% Search Recall**: Interpolation search (`predicted ± 8192`) MUST retain its zero-overhead boundary fallback (`MissLeft` / `MissRight`) so hashes beyond $\pm 4\sigma$ are never missed.
4. **Crash-Safe Append**: `chunk_count` at header offset `16..20` is updated ONLY after a chunk is completely written and flushed.
5. **Easy Hash Extensibility**: Adding a new hash algorithm requires only implementing `Hasher` in `hash/algorithms.rs` and registering 1 line in `HashRegistry::with_builtins()`.
6. **Zero-Allocation Hot Paths**: Hashing, encoding, and binary-search probing must stay stack-allocated (`[u8; 256]`, `HashDigest`).

---

## 3. Agent Verification Suite

```bash
./scripts/agent_check.sh
```
