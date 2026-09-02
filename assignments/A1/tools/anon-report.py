#!/usr/bin/env python3
"""anon-report -- the course's anonymous agent-report tool. One file, pure
Python 3, no dependencies. You do not need an agent to run it.

STUDENT COMMANDS
  keygen                          make your key (~/.anon-report/key.json) and
                                  write pubkey.txt in the current directory
  pubkey                          rewrite pubkey.txt from your key
  deposit FILE --roster R --assignment A
                                  encrypt FILE to the course key, ring-sign it
                                  over roster R, and upload it through Tor to
                                  the drop box (the course key and the .onion
                                  address are both in the roster); saves a
                                  receipt under ~/.anon-report/receipts/
  upload RECEIPT --roster R       re-upload a saved receipt (bundle)
  attend --roster R --assignment A --tags T --nonce N
                                  prove you deposited a report (without saying
                                  which); writes attendance.json
  sign   FILE --roster R --assignment A
                                  ring-sign FILE without encrypting/uploading
  selftest                        check the group parameters and run a demo

ANYONE CAN VERIFY
  verify FILE SIG --roster R      check a signature (and print its tag)
  verify-bundle BUNDLE --roster R check a bulletin-board entry's signature
  verify-attend PROOF --roster R --tags T [--expect-pubkey F --expect-nonce N]
                                  check an attendance proof

COURSE STAFF
  coursekey --version V           make the course keypair (secret stays offline)
  roster DIR --course C --version V --coursekey course-key.json
                                  build roster.json from a directory of
                                  pubkey.txt files (one key per file)
  tags DIR --roster R --assignment A --secret S
                                  build tags.json from a directory of bundles:
                                  a tag counts only if its bundle verifies AND
                                  decrypts (garbage deposits do not count)
  decrypt DIR|BUNDLE --roster R   verify + decrypt bulletin-board bundles

Deposits go to a Tor onion service, so run Tor Browser (or tor) first. The
server verifies the ring signature, keeps the first deposit per key per
assignment, and publishes the ciphertext bundles as a public bulletin board.
Reports are encrypted to the course key on your machine (hashed ElGamal KEM +
HMAC-SHA256 counter mode, encrypt-then-MAC, fixed 16 KiB size) -- the server
never sees plaintext, and every board entry has the same length.

SCHEME  Linkable ring signature (Liu-Wei-Wong LSAG) in the 2048-bit MODP
        group of RFC 3526: p a safe prime, q = (p-1)/2, generator g = 2.
        The ring base h = HashToGroup(course || assignment) makes tags differ
        across assignments, so your reports are not linkable to each other,
        and stay stable if the roster is re-issued within an assignment.
        Attendance uses a Cramer-Damgard-Schoenmakers OR-proof of
        "y = g^x  and  T_j = h^x for some published tag T_j".

Your private key is yours alone. Never paste it into any note, report, chat,
or submission. Back it up; you need it all semester.
"""
import argparse, base64, hashlib, hmac, json, os, secrets, sys
from pathlib import Path
from collections import namedtuple

SCHEME = "lsag-modp2048-v2"
KEY_SCHEMES = (SCHEME, "lsag-modp2048-v1")   # same keys, same group; v1 bundles/rosters are not accepted
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
COURSE_SECRET = KEYDIR / "course-secret.json"
RECEIPTS = KEYDIR / "receipts"
FIXED_SIZE = 16384                 # every ciphertext is exactly this long
MAX_PLAINTEXT = FIXED_SIZE - 8     # 8-byte length prefix
MIN_TAGS = 20                      # anonymity-set floor for attendance proofs

# ----------------------------------------------------------------- encoding --
def enc(v: int) -> str:
    return f"{v:0512X}"

def dec(s: str) -> int:
    """Hex -> group element, checked to be in the order-q subgroup."""
    if not isinstance(s, str) or len(s) != 512:
        raise ValueError("group element must be 512 hex digits")
    v = int(s, 16)
    if not (1 < v < P) or pow(v, Q, P) != 1:
        raise ValueError("group element not in the order-q subgroup")
    return v

def scalar(s, bound=Q) -> int:
    """Hex -> integer in [0, bound). Length-capped BEFORE parsing so an
    attacker cannot make us exponentiate by a megabit number."""
    if not isinstance(s, str) or not (1 <= len(s) <= 512):
        raise ValueError("scalar must be 1..512 hex digits")
    v = int(s, 16)
    if not (0 <= v < bound):
        raise ValueError("scalar out of range")
    return v

def H(*parts) -> int:
    """Challenge hash -> 256-bit integer. Domain-separated, length-prefixed."""
    hsh = hashlib.sha256()
    for part in parts:
        b = part if isinstance(part, bytes) else str(part).encode()
        hsh.update(len(b).to_bytes(4, "big") + b)
    return int.from_bytes(hsh.digest(), "big")

def hash_to_group(*parts) -> int:
    """2560 bits of SHA-512 output (five counters), reduced mod p, squared
    into the order-q subgroup. Nobody knows its discrete log."""
    ctr = 0
    while True:
        buf = b""
        for i in range(5):
            hsh = hashlib.sha512()
            for part in list(parts) + [ctr, i]:
                b = part if isinstance(part, bytes) else str(part).encode()
                hsh.update(len(b).to_bytes(4, "big") + b)
            buf += hsh.digest()
        v = pow(int.from_bytes(buf, "big") % P, 2, P)
        if v not in (0, 1):
            return v
        ctr += 1

def rand_scalar() -> int:
    return secrets.randbelow(Q - 1) + 1

def file_hash(path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()

def read_json(path, what="file"):
    try:
        d = json.loads(Path(path).read_text())
    except (OSError, ValueError) as e:
        sys.exit(f"cannot read {what} {path}: {e}")
    if not isinstance(d, dict):
        sys.exit(f"{what} {path} is not a JSON object")
    return d

# --------------------------------------------------------------------- keys --
def load_key() -> int:
    if not KEYFILE.exists():
        sys.exit(f"no key at {KEYFILE}; run:  python3 anon-report.py keygen")
    d = read_json(KEYFILE, "key")
    if d.get("scheme") not in KEY_SCHEMES:
        sys.exit(f"key at {KEYFILE} has scheme {d.get('scheme')!r}, expected {SCHEME}")
    return scalar(d["x"])

def pk_line(y: int) -> str:
    return f"{SCHEME} {enc(y)}"

def parse_pk_line(line: str) -> int:
    parts = line.split()
    if len(parts) != 2 or parts[0] not in KEY_SCHEMES:
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
# The roster is the single trust root: student keys AND the course public key,
# committed together by one hash that git history makes public.
Roster = namedtuple("Roster", "course version keys Y hash url")

def roster_hash(r: dict) -> str:
    core = {k: r[k] for k in ("scheme", "course", "version", "keys", "course_key")}
    if r.get("dropbox_url"): core["dropbox_url"] = r["dropbox_url"]
    return hashlib.sha256(json.dumps(core, sort_keys=True, separators=(",", ":")).encode()).hexdigest()

def parse_roster(r: dict) -> Roster:
    if r.get("scheme") != SCHEME:
        raise ValueError(f"roster scheme {r.get('scheme')!r} != {SCHEME}")
    for k in ("course", "version"):
        if not isinstance(r.get(k), str) or not r[k]:
            raise ValueError(f"roster missing {k}")
    keys = [dec(k) for k in r["keys"]]
    if not keys:
        raise ValueError("roster has no keys")
    if keys != sorted(set(keys)):
        raise ValueError("roster keys must be sorted and unique")
    url = r.get("dropbox_url")
    if url is not None and not onion_url_ok(url):
        raise ValueError("roster dropbox_url is not http://<56-char v3 address>.onion/deposit")
    return Roster(r["course"], r["version"], keys, dec(r["course_key"]), roster_hash(r), url)

def load_roster(path) -> Roster:
    try:
        return parse_roster(read_json(path, "roster"))
    except (ValueError, KeyError, TypeError) as e:
        sys.exit(f"bad roster {path}: {e}")

def cmd_roster(a):
    ck = read_json(a.coursekey, "course key")
    if ck.get("scheme") != SCHEME or ck.get("kind") != "course-key":
        sys.exit(f"{a.coursekey} is not a {SCHEME} course public key")
    Y = dec(ck["Y"])
    seen = {}
    for f in sorted(Path(a.dir).rglob("pubkey.txt")):
        lines = [l.strip() for l in f.read_text().splitlines() if l.strip()]
        if len(lines) != 1:
            sys.exit(f"{f}: expected exactly one public key line, found {len(lines)}")
        try:
            k = enc(parse_pk_line(lines[0]))
        except ValueError as e:
            sys.exit(f"{f}: {e}")
        if k in seen:
            sys.exit(f"{f}: same public key as {seen[k]} (two students cannot share a key)")
        seen[k] = f
    keyhexes = sorted(seen)
    r = {"scheme": SCHEME, "course": a.course, "version": a.version, "keys": keyhexes, "course_key": enc(Y)}
    if a.dropbox_url:
        if not onion_url_ok(a.dropbox_url): sys.exit("--dropbox-url must be http://<56-char v3 address>.onion/deposit")
        r["dropbox_url"] = a.dropbox_url
    Path(a.out).write_text(json.dumps(r, indent=1))
    print(f"roster {a.version} for {a.course}: {len(keyhexes)} keys + course key"
          f"{' + drop-box address' if a.dropbox_url else ''} -> {a.out}")
    print(f"hash {roster_hash(r)}")

def ring_base(course, assignment) -> int:
    return hash_to_group(SCHEME, "ring-base", course, assignment)

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
    if len(s) != len(keys) or not keys:
        return False
    if not (0 <= c0 < 1 << 256) or any(not (0 <= v < Q) for v in s):
        return False
    if not (1 < tag < P) or pow(tag, Q, P) != 1:
        return False
    c = c0
    for i in range(len(keys)):
        z1 = pow(G, s[i], P) * pow(keys[i], c, P) % P
        z2 = pow(h, s[i], P) * pow(tag, c, P) % P
        c = H(ctx, enc(tag), msg, enc(z1), enc(z2))
    return c == c0

def sig_context(rhash, version, assignment) -> str:
    return f"{SCHEME}|roster:{version}:{rhash}|assignment:{assignment}"

def parse_sig(sig: dict, n: int):
    """Untrusted signature dict -> (c0, s, tag). Raises ValueError."""
    if not isinstance(sig, dict):
        raise ValueError("signature is not an object")
    s = sig.get("s")
    if not isinstance(s, list) or len(s) != n:
        raise ValueError("signature ring size does not match the roster")
    return scalar(sig.get("c0"), 1 << 256), [scalar(v) for v in s], dec(sig.get("tag"))

def sig_dict(version, rhash, assignment, msg, c0, s, tag) -> dict:
    return {"scheme": SCHEME, "roster_version": version, "roster_hash": rhash, "assignment": assignment,
            "message_sha256": msg, "tag": enc(tag), "c0": f"{c0:X}", "s": [f"{v:X}" for v in s]}

def check_sig(sig: dict, r: Roster, assignment, msg):
    """Full check of a signature dict against roster r. Returns (ok, reason)."""
    try:
        if sig.get("roster_hash") != r.hash or sig.get("roster_version") != r.version:
            return False, "signature was made over a different roster"
        if sig.get("assignment") != assignment:
            return False, "signature is for a different assignment"
        if sig.get("message_sha256") != msg:
            return False, "signature does not cover this message"
        c0, s, tag = parse_sig(sig, len(r.keys))
    except (ValueError, TypeError, AttributeError) as e:
        return False, f"malformed signature ({e})"
    ok = lsag_verify(r.keys, c0, s, tag, ring_base(r.course, assignment), sig_context(r.hash, r.version, assignment), msg)
    return (True, "ok") if ok else (False, "invalid ring signature")

def cmd_sign(a):
    r = load_roster(a.roster); x = load_key()
    msg = file_hash(a.file)
    c0, s, tag = lsag_sign(r.keys, x, ring_base(r.course, a.assignment), sig_context(r.hash, r.version, a.assignment), msg)
    out = Path(a.out or (a.file + ".sig.json"))
    out.write_text(json.dumps(sig_dict(r.version, r.hash, a.assignment, msg, c0, s, tag), indent=1))
    print(f"signature -> {out}   (ring of {len(r.keys)}; tag {enc(tag)[:16]}...)")

def cmd_verify(a):
    r = load_roster(a.roster); sig = read_json(a.sig, "signature")
    ok, why = check_sig(sig, r, sig.get("assignment"), file_hash(a.file))
    print(("OK   tag " + sig["tag"][:16] + "...") if ok else "FAIL: " + why)
    sys.exit(0 if ok else 1)

# ------------------------------------------------------- encryption (E2E) --
# Reports are encrypted to the course public key Y = g^k before they leave the
# student's machine, so the drop-box server and the public bulletin board only
# ever hold ciphertext. This is the lecture-4 construction and the one place
# the course rolls its own: hashed ElGamal as a KEM (r, g^r, Y^r -> SHA-256 ->
# separate encryption and MAC keys), an HMAC-SHA256 counter-mode stream as the
# cipher, and an HMAC-SHA256 tag over header || ciphertext (encrypt-then-MAC).
# The MAC header includes the signer's tag, so a ciphertext cannot be lifted
# from the board and re-signed by someone else: it would not decrypt. The
# plaintext is length-prefixed and zero-padded to a FIXED size, so the board
# reveals nothing about report length. Stdlib only.

def kem_keys(shared: int, r: Roster, assignment, c1):
    info = f"{SCHEME}|kem|roster:{r.hash}|assignment:{assignment}|Y:{enc(r.Y)}|c1:{enc(c1)}"
    kdf = lambda label: hashlib.sha256(b"".join(len(b).to_bytes(4, "big") + b for b in
                                                (label, info.encode(), enc(shared).encode()))).digest()
    return kdf(b"enc"), kdf(b"mac")

def keystream_xor(k_enc: bytes, data: bytes) -> bytes:
    out = bytearray(len(data))
    for i in range(0, len(data), 32):
        blk = hmac.new(k_enc, i.to_bytes(8, "big"), hashlib.sha256).digest()
        chunk = data[i:i + 32]
        out[i:i + len(chunk)] = bytes(x ^ y for x, y in zip(chunk, blk))
    return bytes(out)

def mac_header(r: Roster, assignment, c1, tag) -> bytes:
    return (f"{SCHEME}|bundle|course:{r.course}|roster:{r.hash}|assignment:{assignment}"
            f"|Y:{enc(r.Y)}|c1:{enc(c1)}|tag:{enc(tag)}").encode()

def encrypt_report(plaintext: bytes, r: Roster, assignment, tag):
    if len(plaintext) > MAX_PLAINTEXT:
        sys.exit(f"report is {len(plaintext)} bytes; the limit is {MAX_PLAINTEXT} (about four pages). Trim it.")
    body = len(plaintext).to_bytes(8, "big") + plaintext
    body += b"\0" * (FIXED_SIZE - len(body))
    rr = rand_scalar(); c1 = pow(G, rr, P); shared = pow(r.Y, rr, P)
    k_enc, k_mac = kem_keys(shared, r, assignment, c1)
    ct = keystream_xor(k_enc, body)
    mac = hmac.new(k_mac, mac_header(r, assignment, c1, tag) + ct, hashlib.sha256).hexdigest()
    return c1, ct, mac

def bundle_message(assignment, rhash, kem_hex, ct_b64, mac_hex) -> str:
    """What the ring signature signs: a hash of the whole ciphertext bundle."""
    hsh = hashlib.sha256()
    for part in (SCHEME + "|bundle-msg", assignment, rhash, kem_hex, ct_b64, mac_hex):
        b = part.encode(); hsh.update(len(b).to_bytes(4, "big") + b)
    return hsh.hexdigest()

def decrypt_bundle(b: dict, k: int, r: Roster) -> bytes:
    """Verify the MAC and decrypt; raises ValueError on any mismatch."""
    c1 = dec(b["kem"]); ct = base64.b64decode(b["ciphertext"], validate=True); tag = dec(b["sig"]["tag"])
    if len(ct) != FIXED_SIZE:
        raise ValueError("ciphertext is not the fixed size")
    k_enc, k_mac = kem_keys(pow(c1, k, P), r, b["assignment"], c1)
    want = hmac.new(k_mac, mac_header(r, b["assignment"], c1, tag) + ct, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(want, b["mac"]):
        raise ValueError("MAC mismatch (wrong course key, tampered, or a re-signed copy of someone else's bundle)")
    body = keystream_xor(k_enc, ct); n = int.from_bytes(body[:8], "big")
    if n > MAX_PLAINTEXT or any(body[8 + n:]):
        raise ValueError("bad length prefix or padding")
    return body[8:8 + n]

def cmd_coursekey(a):
    """(staff) make the course keypair: secret stays on the instructor laptop."""
    out_secret = Path(a.out_secret or COURSE_SECRET); out_public = Path(a.out_public)
    if out_secret.exists():
        sys.exit(f"{out_secret} exists; not overwriting")
    k = rand_scalar(); Y = pow(G, k, P)
    out_secret.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(out_secret, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump({"scheme": SCHEME, "kind": "course-secret", "k": f"{k:X}", "Y": enc(Y)}, f)
    out_public.write_text(json.dumps({"scheme": SCHEME, "kind": "course-key", "version": a.version,
                                      "Y": enc(Y)}, indent=1))
    print(f"course secret -> {out_secret}   (laptop only; never copy it to the server)")
    print(f"course public key -> {out_public}   (feed it to `roster --coursekey`; it is published inside the roster)")

def load_course_secret(path, r: Roster) -> int:
    sec = read_json(path or COURSE_SECRET, "course secret")
    if sec.get("kind") != "course-secret":
        sys.exit("not a course secret file")
    k = scalar(sec["k"])
    if pow(G, k, P) != r.Y:
        sys.exit("this course secret does not match the course key in the roster")
    return k

# --------------------------------------------------------- deposit (Tor) --
import re
ONION_RE = re.compile(r"^[a-z2-7]{56}\.onion$")

def onion_url_ok(url) -> bool:
    from urllib.parse import urlsplit
    try:
        u = urlsplit(url)
    except ValueError:
        return False
    return u.scheme == "http" and bool(u.hostname) and bool(ONION_RE.match(u.hostname)) and u.path == "/deposit"

def socks5_connect(proxy, host, port, timeout=90):
    """Minimal SOCKS5 CONNECT with remote (Tor-side) name resolution, so
    .onion addresses never touch the local resolver. Offers username/password
    auth with random credentials: Tor uses them purely for stream isolation,
    so this deposit gets a circuit shared with no other local Tor traffic."""
    import socket
    phost, pport = proxy
    hb = host.encode()
    if len(hb) > 255:
        raise ConnectionError("hostname too long")
    s = socket.create_connection((phost, pport), timeout=timeout)
    def rd(n):
        buf = b""
        while len(buf) < n:
            chunk = s.recv(n - len(buf))
            if not chunk: raise ConnectionError("SOCKS proxy closed the connection")
            buf += chunk
        return buf
    s.sendall(b"\x05\x02\x00\x02")                       # methods: none, username/password
    ver, method = rd(2)
    if ver != 5 or method not in (0, 2):
        raise ConnectionError("SOCKS5 handshake failed")
    if method == 2:
        u, pw = secrets.token_hex(8).encode(), secrets.token_hex(8).encode()
        s.sendall(b"\x01" + bytes([len(u)]) + u + bytes([len(pw)]) + pw)
        if rd(2)[1] != 0:
            raise ConnectionError("SOCKS5 isolation auth refused")
    s.sendall(b"\x05\x01\x00\x03" + bytes([len(hb)]) + hb + port.to_bytes(2, "big"))
    ver, rep, _, atyp = rd(4)
    if rep != 0:
        raise ConnectionError(f"SOCKS5 connect failed (code {rep}); is the address right? is Tor connected?")
    if atyp == 1: rd(4 + 2)
    elif atyp == 4: rd(16 + 2)
    elif atyp == 3: rd(rd(1)[0] + 2)
    else: raise ConnectionError("SOCKS5: unknown address type in reply")
    return s

def http_post_json(url, obj, direct=False, socks=None):
    import http.client
    from urllib.parse import urlsplit
    u = urlsplit(url); host, port, path = u.hostname, u.port or 80, u.path or "/"
    if u.scheme != "http" or not host:
        sys.exit("the drop box URL is plain http://<address>.onion/deposit (the .onion name is the authentication)")
    if not direct and not onion_url_ok(url):
        sys.exit("refusing: the drop box address must be a 56-character v3 .onion address (http://....onion/deposit). "
                 "A different address would not be the course's box.")
    body = json.dumps(obj, separators=(",", ":")).encode()
    conn = http.client.HTTPConnection(host, port, timeout=180)
    if direct:
        if host.endswith(".onion"):
            sys.exit("--direct cannot reach a .onion address")
        print("WARNING: --direct sends without Tor; the server sees your IP address. Testing only.", file=sys.stderr)
    else:
        proxies = [socks] if socks else [("127.0.0.1", 9150), ("127.0.0.1", 9050)]
        sock = None
        for pr in proxies:
            try:
                sock = socks5_connect(pr, host, port); break
            except OSError as e:
                last = e
        if sock is None:
            sys.exit("could not reach Tor: start Tor Browser (SOCKS on 127.0.0.1:9150) or a tor daemon "
                     f"(127.0.0.1:9050), or pass --socks HOST:PORT   [{last}]")
        conn.sock = sock
    try:
        conn.request("POST", path, body, {"Content-Type": "application/json", "Content-Length": str(len(body))})
        resp = conn.getresponse(); data = resp.read()
    except OSError as e:
        sys.exit(f"upload failed: {e}")
    try:
        return resp.status, json.loads(data)
    except ValueError:
        return resp.status, {"error": data[:200].decode(errors="replace")}

def do_upload(bundle, a):
    status, r = http_post_json(a.url, bundle, direct=a.direct, socks=parse_socks(a.socks))
    tag = bundle["sig"]["tag"]
    if status == 200 and r.get("status") == "accepted":
        print(f"ACCEPTED   tag {tag[:16]}...   the drop box has your report.")
    elif status == 200 and r.get("status") == "duplicate":
        print(f"ALREADY THERE   tag {tag[:16]}...   the box already holds a report from your key for "
              f"{bundle['assignment']}; it keeps the first one.")
    else:
        sys.exit(f"REJECTED (HTTP {status}): {r.get('error', r)}\n"
                 f"your receipt is saved; fix the problem and re-run:  upload <receipt> --url ...")

def parse_socks(s):
    if not s: return None
    h, _, p = s.rpartition(":"); return (h or "127.0.0.1", int(p))

def cmd_deposit(a):
    r = load_roster(a.roster); x = load_key()
    f = Path(a.file)
    if not f.is_file():
        sys.exit(f"{f} is not a file")
    plaintext = f.read_bytes()
    h = ring_base(r.course, a.assignment); tag = pow(h, x, P)
    c1, ct, mac = encrypt_report(plaintext, r, a.assignment, tag)
    kem_hex, ct_b64, mac_hex = enc(c1), base64.b64encode(ct).decode(), mac
    msg = bundle_message(a.assignment, r.hash, kem_hex, ct_b64, mac_hex)
    c0, s, tag2 = lsag_sign(r.keys, x, h, sig_context(r.hash, r.version, a.assignment), msg)
    assert tag2 == tag
    bundle = {"scheme": SCHEME, "kind": "bundle", "assignment": a.assignment, "roster_version": r.version,
              "roster_hash": r.hash, "kem": kem_hex, "ciphertext": ct_b64, "mac": mac_hex,
              "sig": sig_dict(r.version, r.hash, a.assignment, msg, c0, s, tag)}
    if a.out:
        out = Path(a.out)
    else:
        RECEIPTS.mkdir(parents=True, exist_ok=True)
        out = RECEIPTS / f"{a.assignment}-{enc(tag)[:16]}.json"
    out.write_text(json.dumps(bundle, indent=1))
    print(f"receipt -> {out}   (encrypted to the course key; ring of {len(r.keys)}; tag {enc(tag)[:16]}...)")
    print("(the receipt contains your tag; keep it out of anything you submit under your name)")
    if a.no_upload:
        print(f"not uploading. later:  upload {out}"); return
    a.url = a.url or r.url
    if not a.url:
        sys.exit("no drop-box address: this roster carries none, so pass --url http://<onion>.onion/deposit")
    do_upload(bundle, a)

def cmd_upload(a):
    bundle = read_json(a.bundle, "receipt")
    if bundle.get("kind") != "bundle" or not isinstance(bundle.get("sig"), dict) or "tag" not in bundle["sig"]:
        sys.exit("not a receipt/bundle file")
    if not a.url:
        if not a.roster: sys.exit("pass --url, or --roster so the address can be read from the roster")
        a.url = load_roster(a.roster).url
        if not a.url: sys.exit("this roster carries no drop-box address; pass --url")
    do_upload(bundle, a)

BUNDLE_FIELDS = ("scheme", "kind", "assignment", "roster_version", "roster_hash", "kem", "ciphertext", "mac", "sig")
SIG_FIELDS = ("scheme", "roster_version", "roster_hash", "assignment", "message_sha256", "tag", "c0", "s")
CT_B64_LEN = len(base64.b64encode(b"\0" * FIXED_SIZE))

def verify_bundle(b: dict, r: Roster):
    """Signature + shape check only (no decryption). Returns (ok, reason).
    Anyone can run this on a bulletin-board entry."""
    try:
        if not isinstance(b, dict) or b.get("scheme") != SCHEME or b.get("kind") != "bundle":
            return False, "not a bundle"
        if b.get("roster_hash") != r.hash or b.get("roster_version") != r.version:
            return False, "bundle is over a different roster"
        for k in ("assignment", "kem", "ciphertext", "mac"):
            if not isinstance(b.get(k), str): return False, f"missing {k}"
        if len(b["ciphertext"]) != CT_B64_LEN or len(base64.b64decode(b["ciphertext"], validate=True)) != FIXED_SIZE:
            return False, "ciphertext is not the fixed size"
        if len(b["mac"]) != 64: return False, "bad mac"
        int(b["mac"], 16); dec(b["kem"])
        msg = bundle_message(b["assignment"], r.hash, b["kem"], b["ciphertext"], b["mac"])
        sig = b.get("sig")
        if not isinstance(sig, dict): return False, "missing signature"
        return check_sig(sig, r, b["assignment"], msg)
    except (KeyError, ValueError, TypeError, AttributeError) as e:
        return False, f"malformed bundle ({e.__class__.__name__})"

def canonical_bundle(b: dict) -> dict:
    """Whitelisted copy: nothing but the known fields gets stored/published."""
    return {**{k: b[k] for k in BUNDLE_FIELDS if k != "sig"}, "sig": {k: b["sig"][k] for k in SIG_FIELDS}}

def cmd_verify_bundle(a):
    ok, why = verify_bundle(read_json(a.bundle, "bundle"), load_roster(a.roster))
    print(("OK   " + why) if ok else ("FAIL: " + why)); sys.exit(0 if ok else 1)

def iter_bundles(src: Path):
    files = sorted(src.rglob("*.json")) if src.is_dir() else [src]
    for f in files:
        try:
            b = json.loads(f.read_text())
        except (OSError, ValueError):
            continue
        if isinstance(b, dict) and b.get("kind") == "bundle":
            yield f, b

def verified_plaintexts(src, r: Roster, k: int):
    """Yield (file, bundle, plaintext) for bundles that verify AND decrypt;
    print why the others were skipped."""
    for f, b in iter_bundles(Path(src)):
        ok, why = verify_bundle(b, r)
        if not ok:
            print(f"skip {f.name}: {why}"); continue
        try:
            yield f, b, decrypt_bundle(b, k, r)
        except ValueError as e:
            print(f"skip {f.name}: {e}")

def cmd_decrypt(a):
    """(staff) verify + decrypt one bundle or a directory of them, offline."""
    r = load_roster(a.roster); k = load_course_secret(a.secret, r)
    outdir = Path(a.out_dir); outdir.mkdir(parents=True, exist_ok=True); n_ok = 0
    for f, b, pt in verified_plaintexts(a.bundle, r, k):
        out = outdir / f"{b['assignment']}-{b['sig']['tag'][:32]}.txt"
        out.write_bytes(pt); n_ok += 1
        print(f"{f.name} -> {out}  ({len(pt)} bytes)")
    print(f"{n_ok} report(s) decrypted -> {outdir}")

def cmd_tags(a):
    """(staff) the tags snapshot: one tag per bundle that verifies and
    decrypts, so 'deposited' means a readable report reached the instructor."""
    r = load_roster(a.roster); k = load_course_secret(a.secret, r); seen = {}
    for f, b, _ in verified_plaintexts(a.dir, r, k):
        if b["assignment"] != a.assignment:
            print(f"skip {f.name}: assignment {b['assignment']}"); continue
        t = b["sig"]["tag"]
        if t in seen:
            print(f"note {f.name}: duplicate tag (same signer as {seen[t]}); keeping first"); continue
        seen[t] = f.name
    tags = sorted(seen)
    Path(a.out).write_text(json.dumps({"scheme": SCHEME, "course": r.course, "assignment": a.assignment,
                                       "roster_version": r.version, "roster_hash": r.hash, "tags": tags}, indent=1))
    print(f"{len(tags)} valid, readable, distinct deposits -> {a.out}   "
          f"(roster {len(r.keys)}; {len(r.keys) - len(tags)} keys without one, dropped students included)")
    if len(tags) < MIN_TAGS:
        print(f"WARNING: fewer than {MIN_TAGS} tags; do not accept attendance proofs against this snapshot yet")

# --------------------------------------------------------- attendance proof --
def load_tags(path, r: Roster, assignment):
    t = read_json(path, "tags")
    if t.get("roster_hash") != r.hash or t.get("assignment") != assignment:
        sys.exit("tags file is for a different roster/assignment")
    try:
        tags = [dec(v) for v in t["tags"]]
    except (ValueError, TypeError, KeyError) as e:
        sys.exit(f"bad tags file: {e}")
    if len(tags) != len(set(tags)):
        sys.exit("bad tags file: duplicate tags")
    return tags, hashlib.sha256(json.dumps(t["tags"]).encode()).hexdigest()

def att_context(rhash, assignment, thash, nonce, y) -> str:
    return f"{SCHEME}|attend|roster:{rhash}|assignment:{assignment}|tags:{thash}|nonce:{nonce}|pk:{enc(y)}"

def cmd_attend(a):
    r = load_roster(a.roster); x = load_key(); y = pow(G, x, P); h = ring_base(r.course, a.assignment)
    tags, thash = load_tags(a.tags, r, a.assignment)
    if len(tags) < MIN_TAGS and not a.force:
        sys.exit(f"only {len(tags)} tags in this snapshot; a proof over fewer than {MIN_TAGS} would narrow down "
                 f"which report is yours. Wait for a fuller snapshot (or --force if you accept that).")
    mine = pow(h, x, P)
    if mine not in tags:
        sys.exit("your tag is not in the published tags list: no deposited report found for your key "
                 "(deposit first, or wait for the next snapshot)")
    j = tags.index(mine); m = len(tags)
    c = [0] * m; s = [0] * m; A = [0] * m; B = [0] * m
    rr = rand_scalar(); A[j] = pow(G, rr, P); B[j] = pow(h, rr, P)
    for i in range(m):
        if i == j: continue
        c[i] = rand_scalar(); s[i] = rand_scalar()
        A[i] = pow(G, s[i], P) * pow(y, c[i], P) % P
        B[i] = pow(h, s[i], P) * pow(tags[i], c[i], P) % P
    ctx = att_context(r.hash, a.assignment, thash, a.nonce, y)
    cc = H(ctx, *[enc(v) for v in A], *[enc(v) for v in B])
    c[j] = (cc - sum(c[i] for i in range(m) if i != j)) % Q
    s[j] = (rr - x * c[j]) % Q
    Path(a.out).write_text(json.dumps({"scheme": SCHEME, "assignment": a.assignment, "roster_hash": r.hash,
                                       "tags_sha256": thash, "nonce": a.nonce, "pubkey": pk_line(y),
                                       "c": [f"{v:X}" for v in c], "s": [f"{v:X}" for v in s]}, indent=1))
    print(f"attendance proof -> {a.out}   (over {m} tags; reveals your public key, not your report)")

def cmd_verify_attend(a):
    r = load_roster(a.roster); pr = read_json(a.proof, "proof")
    def fail(why): print("FAIL: " + why); sys.exit(1)
    try:
        assignment = pr["assignment"]
        tags, thash = load_tags(a.tags, r, assignment)
        if len(tags) < a.min_tags:
            fail(f"snapshot has {len(tags)} tags, fewer than the required {a.min_tags}")
        if pr.get("roster_hash") != r.hash or pr.get("tags_sha256") != thash:
            fail("proof is over a different roster or tags snapshot")
        y = parse_pk_line(pr["pubkey"])
        if y not in r.keys:
            fail("public key not in roster")
        if a.expect_pubkey is not None:
            exp = Path(a.expect_pubkey).read_text().strip() if Path(a.expect_pubkey).exists() else a.expect_pubkey.strip()
            if parse_pk_line(exp) != y:
                fail("proof is for a different public key than this student registered")
        if a.expect_nonce is not None and pr.get("nonce") != a.expect_nonce:
            fail("nonce does not match the one issued to this student")
        c = [scalar(v) for v in pr["c"]]; s = [scalar(v) for v in pr["s"]]
        if len(c) != len(tags) or len(s) != len(tags):
            fail("proof length does not match tags list")
    except (KeyError, ValueError, TypeError) as e:
        fail(f"malformed proof ({e})")
    h = ring_base(r.course, assignment)
    A = [pow(G, s[i], P) * pow(y, c[i], P) % P for i in range(len(tags))]
    B = [pow(h, s[i], P) * pow(tags[i], c[i], P) % P for i in range(len(tags))]
    cc = H(att_context(r.hash, assignment, thash, pr["nonce"], y), *[enc(v) for v in A], *[enc(v) for v in B])
    if sum(c) % Q != cc % Q:
        fail("invalid attendance proof")
    print("OK   " + pr["pubkey"][:40] + "... submitted for " + assignment)

# ----------------------------------------------------------------- selftest --
def cmd_selftest(a):
    hx = f"{P:X}"
    assert len(hx) == 512 and hx.startswith("FFFFFFFFFFFFFFFFC90FDAA2") and hx.endswith("FFFFFFFFFFFFFFFF")
    assert pow(G, Q, P) == 1
    xs = [rand_scalar() for _ in range(5)]; ys = sorted(pow(G, x, P) for x in xs)
    k = rand_scalar(); Y = pow(G, k, P)
    rd = {"scheme": SCHEME, "course": "selftest", "version": "v0", "keys": [enc(y) for y in ys], "course_key": enc(Y)}
    r = parse_roster(rd); h = ring_base(r.course, "A0"); ctx = sig_context(r.hash, r.version, "A0")
    c0, s, tag = lsag_sign(ys, xs[0], h, ctx, "msg")
    assert lsag_verify(ys, c0, s, tag, h, ctx, "msg") and not lsag_verify(ys, c0, s, tag, h, ctx, "msg2")
    assert not lsag_verify(ys, c0, [s[0] + Q] + s[1:], tag, h, ctx, "msg")            # no malleability
    c0b, sb, tagb = lsag_sign(ys, xs[0], h, ctx, "another"); assert tagb == tag        # linkable
    assert lsag_sign(ys, xs[0], ring_base(r.course, "A1"), ctx, "msg")[2] != tag       # per-assignment tags
    pt = b"hello " * 1000
    c1, ct, mac = encrypt_report(pt, r, "A0", tag)
    b = {"kem": enc(c1), "ciphertext": base64.b64encode(ct).decode(), "mac": mac, "assignment": "A0",
         "sig": {"tag": enc(tag)}}
    assert decrypt_bundle(b, k, r) == pt and len(ct) == FIXED_SIZE
    for bad in ({**b, "mac": "00" * 32}, {**b, "assignment": "A1"}, {**b, "sig": {"tag": enc(pow(h, xs[1], P))}},
                {**b, "ciphertext": base64.b64encode(bytes([ct[0] ^ 1]) + ct[1:]).decode()}):
        try: decrypt_bundle(bad, k, r); raise AssertionError("tamper undetected")
        except ValueError: pass
    try: scalar("F" * 513); raise AssertionError("oversized scalar accepted")
    except ValueError: pass
    print("selftest ok: group params, sign/verify, non-malleability, linkability, per-assignment tags, "
          "encrypt/decrypt + tamper/re-sign detection, scalar bounds")

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
    p.add_argument("--force", action="store_true", help=f"prove even over fewer than {MIN_TAGS} tags")
    p = sp.add_parser("verify-attend"); p.add_argument("proof"); p.add_argument("--roster", required=True); p.add_argument("--tags", required=True)
    p.add_argument("--min-tags", type=int, default=MIN_TAGS); p.add_argument("--expect-pubkey", help="pubkey.txt (or line) this student registered")
    p.add_argument("--expect-nonce", help="the nonce issued to this student")
    p = sp.add_parser("roster"); p.add_argument("dir"); p.add_argument("--course", required=True)
    p.add_argument("--version", required=True); p.add_argument("--coursekey", required=True); p.add_argument("--out", default="roster.json")
    p.add_argument("--dropbox-url", help="http://<onion>.onion/deposit, so students need no --url")
    p = sp.add_parser("tags"); p.add_argument("dir"); p.add_argument("--roster", required=True)
    p.add_argument("--assignment", required=True); p.add_argument("--secret"); p.add_argument("--out", default="tags.json")
    p = sp.add_parser("deposit"); p.add_argument("file"); p.add_argument("--roster", required=True)
    p.add_argument("--assignment", required=True)
    p.add_argument("--url", help="http://<onion>.onion/deposit"); p.add_argument("--out", help="receipt path")
    p.add_argument("--no-upload", action="store_true", help="just write the receipt")
    p.add_argument("--socks", help="Tor SOCKS5 proxy HOST:PORT (default: try 9150 then 9050)")
    p.add_argument("--direct", action="store_true", help="TESTING ONLY: no Tor (server sees your IP)")
    p = sp.add_parser("upload"); p.add_argument("bundle"); p.add_argument("--url"); p.add_argument("--roster")
    p.add_argument("--socks"); p.add_argument("--direct", action="store_true")
    p = sp.add_parser("verify-bundle"); p.add_argument("bundle"); p.add_argument("--roster", required=True)
    p = sp.add_parser("coursekey"); p.add_argument("--version", required=True)
    p.add_argument("--out-secret"); p.add_argument("--out-public", default="course-key.json")
    p = sp.add_parser("decrypt"); p.add_argument("bundle", help="a bundle file or a directory of them")
    p.add_argument("--roster", required=True); p.add_argument("--secret"); p.add_argument("--out-dir", default="reports")
    a = ap.parse_args(argv)
    if not a.cmd:
        ap.print_help(); return
    {"keygen": cmd_keygen, "pubkey": cmd_pubkey, "selftest": cmd_selftest, "sign": cmd_sign,
     "verify": cmd_verify, "attend": cmd_attend, "verify-attend": cmd_verify_attend,
     "roster": cmd_roster, "tags": cmd_tags, "deposit": cmd_deposit, "upload": cmd_upload,
     "verify-bundle": cmd_verify_bundle, "coursekey": cmd_coursekey, "decrypt": cmd_decrypt}[a.cmd](a)

if __name__ == "__main__":
    main()
