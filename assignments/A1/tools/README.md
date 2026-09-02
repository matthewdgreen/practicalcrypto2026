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

You need **Tor Browser** running (or a `tor` daemon); the drop box is an onion
service, so the box never learns where a report came from. Reports are
encrypted to the course key on your machine before they leave it. The roster,
the course key, and the drop box's `.onion` address are all published in one
file, `anon-report/roster.json`, in the course repository (pull first).

```bash
python3 tools/anon-report.py deposit agent-report.md --roster anon-report/roster.json --assignment A1
#   -> ACCEPTED tag ...   (a mode-0600 receipt is saved under ~/.anon-report/receipts/; re-send it with `upload` if Tor was down)
python3 tools/anon-report.py attend --roster anon-report/roster.json --assignment A1 \
    --tags anon-report/tags-A1.json --nonce <from the attendance instructions>
#   -> attendance.json    (submit under your own name; it reveals only that you deposited *a* report)
```

The box keeps the **first** deposit per key per assignment. Never use
`--direct` (it skips Tor). Anyone can check a bulletin-board entry or a proof:

```bash
python3 tools/anon-report.py verify-bundle anon-report/bulletin/A1/<tag>.json --roster anon-report/roster.json
python3 tools/anon-report.py verify-attend attendance.json --roster anon-report/roster.json --tags anon-report/tags-A1.json
```

If campus wifi blocks Tor, turn on a bridge in Tor Browser (Settings → Connection
→ Bridges; Snowflake works from most networks) and try again -- nothing else changes.
The upload performs a short anti-abuse computation before the server spends
several seconds checking the ring signature; this is expected. If course staff
must correct the roster while deposits are open, pull the correction and make a
fresh deposit: the server will replace your same-tag bundle from the old roster.

## What it is

A **linkable ring signature** (Liu–Wei–Wong LSAG) in the 2048-bit MODP group
from RFC 3526, so it's reimplementable in any language with big integers —
which you will do later in the course. A signature proves "one of the keys in
the roster signed this" without saying which, and carries a *tag* that is the
same for all of one key's signatures within an assignment (so duplicates are
visible) but different across assignments (so your reports aren't linkable to
each other). Attendance is a Cramer–Damgård–Schoenmakers OR-proof that your
key's tag is *one of* the published tags. Ring of 150 ≈ 10 s to sign or verify.
Deposits are encrypted to the course key with hashed ElGamal + HMAC-SHA256
counter mode (encrypt-then-MAC), so the server and the public board hold only
ciphertext; the instructor decrypts offline.
