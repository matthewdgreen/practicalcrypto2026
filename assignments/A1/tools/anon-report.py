#!/usr/bin/env python3
"""anon-report -- the course's anonymous agent-report tool. One file, pure
Python 3, no dependencies. You do not need an agent to run it.

STUDENT COMMANDS
  keygen                          make your key (~/.anon-report/key.json) and
                                  write pubkey.txt in the current directory
  pubkey                          rewrite pubkey.txt from your key
  sign   FILE --roster R --assignment A
                                  sign FILE with a linkable ring signature over
                                  roster R; writes FILE.sig.json
  attend --roster R --assignment A --tags T --nonce N
                                  prove you deposited a report (without saying
                                  which); writes attendance.json
  selftest                        check the group parameters and run a demo

ANYONE CAN VERIFY
  verify FILE SIG --roster R      check a signature (and print its tag)
  verify-attend PROOF --roster R --tags T
                                  check an attendance proof

COURSE STAFF
  roster DIR --version V          build roster.json from a directory of
                                  pubkey.txt files
  tags DIR --roster R --assignment A
                                  build tags.json from a directory of *.sig.json

SCHEME  Linkable ring signature (Liu-Wei-Wong LSAG) in the 2048-bit MODP
        group of RFC 3526: p a safe prime, q = (p-1)/2, generator g = 2.
        The ring base h = HashToGroup(roster || assignment) makes tags differ
        across assignments, so your reports are not linkable to each other.
        Attendance uses a Cramer-Damgard-Schoenmakers OR-proof of
        "y = g^x  and  T_j = h^x for some published tag T_j".

Your private key is yours alone. Never paste it into any note, report, chat,
or submission. Back it up; you need it all semester.
"""
import argparse, hashlib, json, os, secrets, sys
from pathlib import Path

SCHEME = "lsag-modp2048-v1"
P = int(
"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DD"
"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
"83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
"E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
"15728E5A8AACAA68FFFFFFFFFFFFFFFF", 16)
Q = (P - 1) // 2
G = 2
KEYDIR = Path(os.environ.get("ANON_REPORT_HOME", Path.home() / ".anon-report"))
KEYFILE = KEYDIR / "key.json"

# ----------------------------------------------------------------- encoding --
def enc(v: int) -> str:
    return f"{v:0512X}"

def dec(s: str) -> int:
    v = int(s, 16)
    if not (1 < v < P) or pow(v, Q, P) != 1:
        raise ValueError("group element not in the order-q subgroup")
    return v

def H(*parts) -> int:
    """Challenge hash -> integer < q. Domain-separated, length-prefixed."""
    hsh = hashlib.sha256()
    for part in parts:
        b = part if isinstance(part, bytes) else str(part).encode()
        hsh.update(len(b).to_bytes(4, "big") + b)
    return int.from_bytes(hsh.digest(), "big")

def hash_to_group(*parts) -> int:
    ctr = 0
    while True:
        hsh = hashlib.sha512()
        for part in list(parts) + [ctr]:
            b = part if isinstance(part, bytes) else str(part).encode()
            hsh.update(len(b).to_bytes(4, "big") + b)
        v = pow(int.from_bytes(hsh.digest() * 5, "big") % P, 2, P)   # square -> subgroup
        if v not in (0, 1):
            return v
        ctr += 1

def rand_scalar() -> int:
    return secrets.randbelow(Q - 1) + 1

def file_hash(path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()

# --------------------------------------------------------------------- keys --
def load_key() -> int:
    if not KEYFILE.exists():
        sys.exit(f"no key at {KEYFILE}; run:  python3 anon-report.py keygen")
    d = json.loads(KEYFILE.read_text())
    if d.get("scheme") != SCHEME:
        sys.exit(f"key at {KEYFILE} has scheme {d.get('scheme')!r}, expected {SCHEME}")
    return int(d["x"], 16)

def pk_line(y: int) -> str:
    return f"{SCHEME} {enc(y)}"

def parse_pk_line(line: str) -> int:
    parts = line.split()
    if len(parts) != 2 or parts[0] != SCHEME:
        raise ValueError(f"bad public key line (expected '{SCHEME} <512 hex digits>')")
    return dec(parts[1])

def cmd_keygen(a):
    if KEYFILE.exists():
        print(f"a key already exists at {KEYFILE}; not overwriting it.")
        print("(delete it only if you have never registered its public key.)")
        return cmd_pubkey(a)
    x = rand_scalar(); y = pow(G, x, P)
    KEYDIR.mkdir(parents=True, exist_ok=True)
    fd = os.open(KEYFILE, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump({"scheme": SCHEME, "x": f"{x:X}"}, f)
    Path("pubkey.txt").write_text(pk_line(y) + "\n")
    print(f"private key : {KEYFILE}   (keep it, back it up, never share it)")
    print(f"public key  : ./pubkey.txt   (submit this file to the Part 0 Gradescope assignment)")

def cmd_pubkey(a):
    y = pow(G, load_key(), P)
    Path("pubkey.txt").write_text(pk_line(y) + "\n")
    print(pk_line(y)); print("(written to ./pubkey.txt)")

# ------------------------------------------------------------------- roster --
def load_roster(path):
    r = json.loads(Path(path).read_text())
    if r.get("scheme") != SCHEME:
        sys.exit(f"roster scheme {r.get('scheme')!r} != {SCHEME}")
    keys = [dec(k) for k in r["keys"]]
    if keys != sorted(set(keys)):
        sys.exit("roster keys must be sorted and unique")
    return r["version"], keys, roster_hash(r["version"], r["keys"])

def roster_hash(version, keyhexes) -> str:
    return hashlib.sha256(json.dumps({"scheme": SCHEME, "version": version, "keys": keyhexes},
                                     sort_keys=True, separators=(",", ":")).encode()).hexdigest()

def cmd_roster(a):
    keys = set()
    for f in sorted(Path(a.dir).rglob("pubkey.txt")):
        for line in f.read_text().splitlines():
            if line.strip():
                keys.add(enc(parse_pk_line(line.strip())))
    keyhexes = sorted(keys)
    r = {"scheme": SCHEME, "version": a.version, "keys": keyhexes}
    Path(a.out).write_text(json.dumps(r, indent=1))
    print(f"roster {a.version}: {len(keyhexes)} keys -> {a.out}   hash {roster_hash(a.version, keyhexes)[:16]}...")

def ring_base(rhash, assignment) -> int:
    return hash_to_group(SCHEME, "ring-base", rhash, assignment)

# --------------------------------------------------------------------- LSAG --
def lsag_sign(keys, x, h, ctx, msg):
    n = len(keys); y = pow(G, x, P)
    try:
        idx = keys.index(y)
    except ValueError:
        sys.exit("your public key is not in this roster (did you register it? right roster version?)")
    tag = pow(h, x, P)
    c = [0] * n; s = [0] * n
    u = rand_scalar()
    c[(idx + 1) % n] = H(ctx, enc(tag), msg, enc(pow(G, u, P)), enc(pow(h, u, P)))
    i = (idx + 1) % n
    while i != idx:
        s[i] = rand_scalar()
        z1 = pow(G, s[i], P) * pow(keys[i], c[i], P) % P
        z2 = pow(h, s[i], P) * pow(tag, c[i], P) % P
        c[(i + 1) % n] = H(ctx, enc(tag), msg, enc(z1), enc(z2))
        i = (i + 1) % n
    s[idx] = (u - x * c[idx]) % Q
    return c[0], s, tag

def lsag_verify(keys, c0, s, tag, h, ctx, msg) -> bool:
    if len(s) != len(keys) or not (1 < tag < P) or pow(tag, Q, P) != 1:
        return False
    c = c0
    for i in range(len(keys)):
        z1 = pow(G, s[i], P) * pow(keys[i], c, P) % P
        z2 = pow(h, s[i], P) * pow(tag, c, P) % P
        c = H(ctx, enc(tag), msg, enc(z1), enc(z2))
    return c == c0

def sig_context(rhash, version, assignment) -> str:
    return f"{SCHEME}|roster:{version}:{rhash}|assignment:{assignment}"

def cmd_sign(a):
    version, keys, rhash = load_roster(a.roster)
    x = load_key()
    h = ring_base(rhash, a.assignment)
    msg = file_hash(a.file)
    c0, s, tag = lsag_sign(keys, x, h, sig_context(rhash, version, a.assignment), msg)
    out = Path(a.out or (a.file + ".sig.json"))
    out.write_text(json.dumps({"scheme": SCHEME, "roster_version": version, "roster_hash": rhash,
                               "assignment": a.assignment, "message_sha256": msg,
                               "tag": enc(tag), "c0": f"{c0:X}", "s": [f"{v:X}" for v in s]}, indent=1))
    print(f"signature -> {out}   (ring of {len(keys)}; tag {enc(tag)[:16]}...)")
    print("deposit the report and this .sig.json together through the anonymous channel")

def cmd_verify(a):
    version, keys, rhash = load_roster(a.roster)
    sig = json.loads(Path(a.sig).read_text())
    if sig.get("roster_hash") != rhash or sig.get("roster_version") != version:
        sys.exit("FAIL: signature was made over a different roster")
    if sig.get("message_sha256") != file_hash(a.file):
        sys.exit("FAIL: file does not match the signed message hash")
    h = ring_base(rhash, sig["assignment"])
    ok = lsag_verify(keys, int(sig["c0"], 16), [int(v, 16) for v in sig["s"]], dec(sig["tag"]), h,
                     sig_context(rhash, version, sig["assignment"]), sig["message_sha256"])
    print(("OK   tag " + sig["tag"][:16] + "...") if ok else "FAIL: invalid ring signature")
    sys.exit(0 if ok else 1)

def cmd_tags(a):
    version, keys, rhash = load_roster(a.roster)
    h = ring_base(rhash, a.assignment); seen = {}
    for f in sorted(Path(a.dir).rglob("*.sig.json")):
        sig = json.loads(f.read_text())
        if sig.get("roster_hash") != rhash or sig.get("assignment") != a.assignment:
            print(f"skip {f.name}: wrong roster/assignment"); continue
        ok = lsag_verify(keys, int(sig["c0"], 16), [int(v, 16) for v in sig["s"]], dec(sig["tag"]), h,
                         sig_context(rhash, version, a.assignment), sig["message_sha256"])
        if not ok:
            print(f"skip {f.name}: INVALID signature"); continue
        if sig["tag"] in seen:
            print(f"note {f.name}: duplicate tag (same signer as {seen[sig['tag']]}); keeping first"); continue
        seen[sig["tag"]] = f.name
    tags = sorted(seen)
    Path(a.out).write_text(json.dumps({"scheme": SCHEME, "assignment": a.assignment, "roster_version": version,
                                       "roster_hash": rhash, "tags": tags}, indent=1))
    print(f"{len(tags)} valid distinct tags -> {a.out}")

# --------------------------------------------------------- attendance proof --
def load_tags(path, rhash, assignment):
    t = json.loads(Path(path).read_text())
    if t.get("roster_hash") != rhash or t.get("assignment") != assignment:
        sys.exit("tags file is for a different roster/assignment")
    return [dec(v) for v in t["tags"]], hashlib.sha256(json.dumps(t["tags"]).encode()).hexdigest()

def att_context(rhash, assignment, thash, nonce, y) -> str:
    return f"{SCHEME}|attend|roster:{rhash}|assignment:{assignment}|tags:{thash}|nonce:{nonce}|pk:{enc(y)}"

def cmd_attend(a):
    version, keys, rhash = load_roster(a.roster)
    x = load_key(); y = pow(G, x, P); h = ring_base(rhash, a.assignment)
    tags, thash = load_tags(a.tags, rhash, a.assignment)
    mine = pow(h, x, P)
    if mine not in tags:
        sys.exit("your tag is not in the published tags list: no deposited report found for your key "
                 "(deposit first, or wait for the next snapshot)")
    j = tags.index(mine); m = len(tags)
    c = [0] * m; s = [0] * m; A = [0] * m; B = [0] * m
    r = rand_scalar(); A[j] = pow(G, r, P); B[j] = pow(h, r, P)
    for i in range(m):
        if i == j: continue
        c[i] = rand_scalar(); s[i] = rand_scalar()
        A[i] = pow(G, s[i], P) * pow(y, c[i], P) % P
        B[i] = pow(h, s[i], P) * pow(tags[i], c[i], P) % P
    ctx = att_context(rhash, a.assignment, thash, a.nonce, y)
    cc = H(ctx, *[enc(v) for v in A], *[enc(v) for v in B])
    c[j] = (cc - sum(c[i] for i in range(m) if i != j)) % Q
    s[j] = (r - x * c[j]) % Q
    Path(a.out).write_text(json.dumps({"scheme": SCHEME, "assignment": a.assignment, "roster_hash": rhash,
                                       "tags_sha256": thash, "nonce": a.nonce, "pubkey": pk_line(y),
                                       "c": [f"{v:X}" for v in c], "s": [f"{v:X}" for v in s]}, indent=1))
    print(f"attendance proof -> {a.out}   (over {m} tags; reveals your public key, not your report)")

def cmd_verify_attend(a):
    version, keys, rhash = load_roster(a.roster)
    pr = json.loads(Path(a.proof).read_text())
    tags, thash = load_tags(a.tags, rhash, pr["assignment"])
    if pr.get("roster_hash") != rhash or pr.get("tags_sha256") != thash:
        sys.exit("FAIL: proof is over a different roster or tags snapshot")
    y = parse_pk_line(pr["pubkey"])
    if y not in keys:
        sys.exit("FAIL: public key not in roster")
    h = ring_base(rhash, pr["assignment"])
    c = [int(v, 16) for v in pr["c"]]; s = [int(v, 16) for v in pr["s"]]
    if len(c) != len(tags) or len(s) != len(tags):
        sys.exit("FAIL: proof length does not match tags list")
    A = [pow(G, s[i], P) * pow(y, c[i], P) % P for i in range(len(tags))]
    B = [pow(h, s[i], P) * pow(tags[i], c[i], P) % P for i in range(len(tags))]
    cc = H(att_context(rhash, pr["assignment"], thash, pr["nonce"], y), *[enc(v) for v in A], *[enc(v) for v in B])
    ok = sum(c) % Q == cc % Q
    print(("OK   " + pr["pubkey"][:40] + "... submitted for " + pr["assignment"]) if ok else "FAIL: invalid attendance proof")
    sys.exit(0 if ok else 1)

# ----------------------------------------------------------------- selftest --
def cmd_selftest(a):
    hx = f"{P:X}"
    assert len(hx) == 512 and hx.startswith("FFFFFFFFFFFFFFFFC90FDAA2") and hx.endswith("FFFFFFFFFFFFFFFF")
    assert pow(G, Q, P) == 1
    xs = [rand_scalar() for _ in range(5)]; ys = sorted(pow(G, x, P) for x in xs)
    rh = roster_hash("selftest", [enc(y) for y in ys]); h = ring_base(rh, "A0")
    ctx = sig_context(rh, "selftest", "A0")
    c0, s, tag = lsag_sign(ys, xs[0], h, ctx, "msg")
    assert lsag_verify(ys, c0, s, tag, h, ctx, "msg") and not lsag_verify(ys, c0, s, tag, h, ctx, "msg2")
    c0b, sb, tagb = lsag_sign(ys, xs[0], h, ctx, "another"); assert tagb == tag        # linkable
    assert lsag_sign(ys, xs[0], ring_base(rh, "A1"), ctx, "msg")[2] != tag              # per-assignment tags
    print("selftest ok: group params, sign/verify, linkability, per-assignment tags")

# --------------------------------------------------------------------- main --
def main(argv=None):
    ap = argparse.ArgumentParser(prog="anon-report.py", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sp = ap.add_subparsers(dest="cmd")
    sp.add_parser("keygen"); sp.add_parser("pubkey"); sp.add_parser("selftest")
    p = sp.add_parser("sign"); p.add_argument("file"); p.add_argument("--roster", required=True)
    p.add_argument("--assignment", required=True); p.add_argument("--out")
    p = sp.add_parser("verify"); p.add_argument("file"); p.add_argument("sig"); p.add_argument("--roster", required=True)
    p = sp.add_parser("attend"); p.add_argument("--roster", required=True); p.add_argument("--assignment", required=True)
    p.add_argument("--tags", required=True); p.add_argument("--nonce", required=True); p.add_argument("--out", default="attendance.json")
    p = sp.add_parser("verify-attend"); p.add_argument("proof"); p.add_argument("--roster", required=True); p.add_argument("--tags", required=True)
    p = sp.add_parser("roster"); p.add_argument("dir"); p.add_argument("--version", required=True); p.add_argument("--out", default="roster.json")
    p = sp.add_parser("tags"); p.add_argument("dir"); p.add_argument("--roster", required=True)
    p.add_argument("--assignment", required=True); p.add_argument("--out", default="tags.json")
    a = ap.parse_args(argv)
    if not a.cmd:
        ap.print_help(); return
    {"keygen": cmd_keygen, "pubkey": cmd_pubkey, "selftest": cmd_selftest, "sign": cmd_sign,
     "verify": cmd_verify, "attend": cmd_attend, "verify-attend": cmd_verify_attend,
     "roster": cmd_roster, "tags": cmd_tags}[a.cmd](a)

if __name__ == "__main__":
    main()
