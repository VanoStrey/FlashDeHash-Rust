#!/usr/bin/env bash
set -eo pipefail

echo "=== [1/3] Cargo Check ==="
cargo check --workspace --message-format=short

echo "=== [2/3] Clippy ==="
cargo clippy --workspace --all-targets --message-format=short -- -D warnings

echo "=== [3/3] Tests ==="
cargo test --workspace --quiet

echo "=== All Checks Passed ==="
