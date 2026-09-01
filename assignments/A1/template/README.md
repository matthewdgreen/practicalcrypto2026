# Submission template

Copy this directory, put your code in `src/`, and make `build.sh` produce the
four executables in `bin/`. Everything here is optional scaffolding — the only
things the autograder cares about are the contract in §8 of `A1.md`:

```
build.sh                      # exit 0; produces the executables below
bin/vigenere-encrypt          # <key> <file>
bin/vigenere-decrypt          # <key> <file>
bin/vigenere-keylength        # <file>            -> one integer
bin/vigenere-cryptanalyze     # <file> <keylen>   -> up to 10 keys, one per line
analysis.md  written.md  design.md  ai-usage.md
```

## Two ways to satisfy the contract

**Interpreted language (Python, Node, Ruby, …):** leave `build.sh` as is; make
each `bin/` file a shebang wrapper that `exec`s your program. Two examples are
provided (`bin/vigenere-encrypt` for Python; adapt for the others).

**Compiled language (Go, Rust, C, Java, …):** have `build.sh` compile into
`bin/` (examples for Go and Rust are commented in `build.sh`). Binaries must
not depend on files outside the submission directory.

## Test in the course container before you submit

```bash
docker build -t pcs-a1 .                      # once; uses the provided Dockerfile
docker run --rm -v "$PWD":/sub -w /sub pcs-a1 bash ./build.sh
docker run --rm -v "$PWD":/sub -w /sub pcs-a1 bin/vigenere-keylength samples/ciphertext_1.txt
docker run --rm pcs-a1 toolchains             # exact toolchain versions
```

If it doesn't build in the container, it doesn't build for the autograder,
and you can't sign up for the review lab.
