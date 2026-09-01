#!/usr/bin/env bash
# Runs in the course container from the submission root. Must exit 0 and leave
# the four executables in bin/. Edit to taste.
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p bin

# --- interpreted languages: nothing to build; just make the wrappers executable
chmod +x bin/* 2>/dev/null || true

# --- Go example (uncomment):  one package per tool under src/cmd/<tool>/
# for t in encrypt decrypt keylength cryptanalyze; do
#   (cd src && go build -o "../bin/vigenere-$t" "./cmd/$t")
# done

# --- Rust example (uncomment):  a cargo workspace in src/ with four binaries
# (cd src && cargo build --release)
# for t in encrypt decrypt keylength cryptanalyze; do
#   cp "src/target/release/vigenere-$t" "bin/vigenere-$t"
# done

# --- C example (uncomment)
# for t in encrypt decrypt keylength cryptanalyze; do
#   gcc -O2 -o "bin/vigenere-$t" "src/$t.c"
# done
