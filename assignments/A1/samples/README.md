# Sample data

Three worked examples for testing your tools (these are **not** the grading
set, which uses different texts and keys):

| files | key length | letters |
|---|---|---|
| `plaintext_1.txt` / `key_1.txt` / `ciphertext_1.txt` | see key | 20,000 |
| `plaintext_2.txt` / `key_2.txt` / `ciphertext_2.txt` | see key | 16,000 |
| `plaintext_3.txt` / `key_3.txt` / `ciphertext_3.txt` | see key | 9,000 |

`sample_plain.txt` is 30,000 letters of normalized English you may use for
your Part 4 experiments (or fetch your own from Project Gutenberg).

**Normalization** — the exact rule the autograder applies to every input and
to your output before comparing:

```bash
sed 's/[^a-zA-Z]//g' input.txt | tr 'a-z' 'A-Z' | tr -d '\n'
```

Quick self-check:

```bash
bin/vigenere-encrypt "$(cat samples/key_1.txt)" samples/plaintext_1.txt | tr -d '\n' | diff - <(tr -d '\n' < samples/ciphertext_1.txt) && echo OK
bin/vigenere-keylength samples/ciphertext_1.txt     # should print the length of key_1
bin/vigenere-cryptanalyze samples/ciphertext_1.txt "$(tr -d '\n' < samples/key_1.txt | wc -c)"
```
