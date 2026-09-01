# anon-report.py — the anonymous agent-report tool

One file, pure Python 3 (3.8+), no dependencies, no agent needed.

## Part 0 (due Fri Sep 11): make and register your key

```bash
python3 tools/anon-report.py keygen
```

This writes your **private key** to `~/.anon-report/key.json` (mode 0600 — keep
it, back it up, never share it or paste it anywhere) and your **public key** to
`./pubkey.txt`. Submit `pubkey.txt` to the Gradescope assignment
**"A1 Part 0: key registration."** That's all for now.

Lost your `pubkey.txt`? `python3 tools/anon-report.py pubkey` rewrites it.
Curious? `python3 tools/anon-report.py selftest` and `--help`.

## Later (instructions and roster published Sep 14)

```bash
python3 tools/anon-report.py sign agent-report.md --roster roster-v1.json --assignment A1
#   -> agent-report.md.sig.json   (deposit both files through the anonymous channel)
python3 tools/anon-report.py attend --roster roster-v1.json --assignment A1 --tags tags-A1.json --nonce <from Gradescope>
#   -> attendance.json            (submit under your own name; it reveals only that you deposited *a* report)
```

Anyone can check a deposit or a proof:

```bash
python3 tools/anon-report.py verify agent-report.md agent-report.md.sig.json --roster roster-v1.json
python3 tools/anon-report.py verify-attend attendance.json --roster roster-v1.json --tags tags-A1.json
```

## What it is

A **linkable ring signature** (Liu–Wei–Wong LSAG) in the 2048-bit MODP group
from RFC 3526, so it's reimplementable in any language with big integers —
which you will do later in the course. A signature proves "one of the keys in
the roster signed this" without saying which, and carries a *tag* that is the
same for all of one key's signatures within an assignment (so duplicates are
visible) but different across assignments (so your reports aren't linkable to
each other). Attendance is a Cramer–Damgård–Schoenmakers OR-proof that your
key's tag is *one of* the published tags. Ring of 150 ≈ 10 s to sign or verify.
