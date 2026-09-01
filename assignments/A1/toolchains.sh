#!/usr/bin/env bash
# Prints the toolchain versions in the course container (post this on Piazza).
for c in "python3 --version" "go version" "rustc --version" "cargo --version" \
         "gcc --version | head -1" "clang --version | head -1" "java -version 2>&1 | head -1" \
         "node --version" "ruby --version" "perl --version | sed -n 2p"; do
  printf '%-22s ' "${c%% *}"; bash -c "$c" 2>/dev/null || echo "(missing)"
done
