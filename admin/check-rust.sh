#! /bin/sh
# III-IV
# Copyright 2026 Julio Merino

set -eu

cargo clippy -- -D warnings
cargo clippy --features=testutils -- -D warnings
cargo clippy --all-features --all-targets -- -D warnings
cargo fmt -- --check
