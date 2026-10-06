# JMessage 2026 Specification

*Version 1.1, October 5, 2026. Practical Cryptographic Systems, Fall 2026.*

JMessage is an end-to-end encrypted messaging system built for teaching. It is
**deliberately not a secure design**: some of its choices are obsolete, and some
are worse than that. Do not use it to protect real data.

The keywords MUST, MUST NOT, SHOULD and MAY are used as in RFC 2119. Numbered
processing steps, message layouts, and unqualified instructions in this
specification are also requirements. The autograder may test these requirements;
it will accept any explicitly permitted MAY behavior and will not require a
SHOULD behavior. Appendix B (robustness) is recommended practice and is not
graded. The [assignment handout](handout.md) describes the work to
submit, the learning goals, and the subset of checks required for review-lab
eligibility. This document defines protocol behavior.

---

## 1. Overview

A JMessage deployment has two parts:

- **The server.** It stores accounts, identity public keys and mailboxes, and
  relays opaque messages between users. It performs no client-side cryptography,
  and the design treats it as **untrusted**: clients must not rely on it for the
  confidentiality or integrity of message contents.
- **Clients.** Each client generates its own long-term identity key, which never
  leaves the client. Two clients that want to talk run a **handshake** through
  the server. The handshake negotiates a **cipher suite** and derives **session
  keys**. Messages are then encrypted under those session keys.

A typical interaction looks like this:

1. Alice registers, logs in, generates an Ed25519 identity key, and uploads the
   public half. Bob does the same.
2. Alice wants to message Bob and has no session with him, so she sends a
   `HELLO`.
3. Bob answers with a `REPLY` that chooses a suite and is signed by Bob.
4. Alice verifies the `REPLY`, derives the session keys, and sends a signed
   `FINISH`, followed by her encrypted `DATA` records.
5. Bob verifies the `FINISH`, derives the same keys, and decrypts the `DATA`.
   He acknowledges each record with a `RECEIPT`.

## 2. Primitives

| Purpose | Primitive |
|---|---|
| Identity signatures | Ed25519 (RFC 8032), raw 32-byte public keys and 64-byte signatures |
| Classical key agreement | X25519 (RFC 7748), raw 32-byte public keys |
| Post-quantum key agreement | ML-KEM-768 (FIPS 203): 1184-byte encapsulation key, 1088-byte ciphertext, 32-byte shared secret |
| Hash | SHA-256 |
| KDF | HKDF-SHA256 (RFC 5869) |
| Record protection, suite JM2 | AES-256-GCM |
| Record protection, suite JM1 | AES-128-CBC with PKCS#7 padding, and HMAC-SHA256 |

Clients MUST reject an X25519 shared secret that is all zeros. A library error
during X25519 key import or exchange also aborts that handshake; it does not
trigger suite fallback. Use library implementations of the cryptographic
primitives, and a cryptographically secure random source for keys, session
identifiers, and IVs. Seeded test fixtures are not a source of production
randomness.

## 3. Encodings

All binary structures in this spec are byte strings, with integers in big-endian
order. The notation is:

- `u8`, `u16`, `u32`, `u64`: unsigned integers of 1, 2, 4 and 8 bytes.
- `bytes[n]`: exactly `n` bytes.
- `vec8<x>`: a `u8` length followed by that many bytes.
- `vec16<x>`: a `u16` length followed by that many bytes.
- `str8(s)`: `vec8` of the UTF-8 encoding of `s`.
- `||`: concatenation.

Quoted strings in cryptographic expressions are their exact ASCII bytes,
without quotation marks or a terminating null byte. Spaces inside the quotes
are significant. In particular, the HKDF info label ends with a space.

Usernames are 1 to 32 characters from `[a-z0-9_]`.

A **message body** is one of the binary structures in §6 and §7. Its first byte
is the message type. On the wire, the body is base64-encoded (standard alphabet,
with padding) and carried in the `payload` field of the JSON message envelope
(§4.5). The transcript hashes in §6 are computed over the **decoded bytes**, not
over the base64 text. Base64 decoding should be strict (Appendix B).

Parsing MUST consume the entire body. Truncated fields, inconsistent length
prefixes, and trailing bytes are structural errors. For DATA, all remaining
bytes constitute `protected`. A vector's prefix counts bytes, whereas HELLO's
`n` counts two-byte suite identifiers. A HELLO with `n = 0` or duplicate suite
identifiers is invalid and is silently discarded. Unknown suite identifiers
are allowed in an otherwise valid HELLO and are ignored during selection.

Parsing a length-prefixed field and validating its contents are separate
steps: a fully present `ek_I` with the wrong semantic length reaches §6.4,
step 3; a field truncated relative to its own length prefix does not. If JM2
is absent from a HELLO, `ek_I` MUST be empty; otherwise discard the HELLO. If
JM2 is offered, `ek_I` of any length other than 1184 bytes (including empty)
is a §6.4 step 3 failure and produces a `hybrid_invalid` REJECT, not a silent
discard.

## 4. Server API

The server speaks HTTPS with JSON bodies. Authenticated calls carry
`Authorization: Bearer <apikey>`. Error responses use standard status codes:
`400` for malformed requests, `401` for bad credentials, `404` when something is
not found, `409` for conflicts, `413` when a payload is too large, and `429` for
rate limiting or a full mailbox.

When you run your own server locally you may use plain HTTP.

### 4.1 Register

`POST /register` with `{"username": "...", "password": "..."}`. Returns `200`,
or `409` if the username is already taken.

### 4.2 Log in

`POST /login` with `{"username": "...", "password": "..."}`. Returns
`{"apikey": "<string>"}`. Logging in again invalidates the previous API key.

### 4.3 Identity keys

- `POST /keys` (authenticated) with `{"idPK": "<base64 of 32 bytes>"}`. This
  replaces any key previously uploaded for the account.
- `GET /keys/<username>` returns `{"idPK": "..."}`, or `404` if the user has
  not uploaded a key.
- `GET /users` returns
  `[{"username": ..., "created": <unix time>, "lastSeen": <unix time>}, ...]`.

These GET endpoints do not require authentication. Timestamps are integer
seconds since the Unix epoch. A successful key upload returns `200` with `{}`;
a successful registration also returns `{}`. Login, send, and receive return
`200` with the JSON shown here. Clients MUST NOT depend on error-response text
or the ordering of the user list.

### 4.4 Send

`POST /messages` (authenticated) with `{"to": "<username>", "payload": "<base64>"}`.

- The server sets `from` to the authenticated user.
- It assigns an increasing integer `id` and returns `{"id": <int>}`.
- The payload limit is 8192 characters of base64.

### 4.5 Receive

`GET /messages` (authenticated) returns every waiting message in the order the
server received them, then deletes them from the mailbox:

```
[{"id": <int>, "from": "<username>", "to": "<username>", "payload": "<base64>"}, ...]
```

Clients SHOULD poll this endpoint every 1 to 5 seconds.

### 4.6 Delivery assumptions and limits

Use one polling consumer per account. Clients MUST process each received batch
in order and serialize outgoing requests so that FINISH is accepted by the
server before DATA is sent for that session. Message IDs are transport
identifiers, not record sequence numbers.

Mailbox retrieval is destructive, not an acknowledged delivery protocol. A
lost HTTP response can lose a batch, and the record layer does not repair
missing records or reorder them. Graded tests use successful, ordered
delivery. Recovery from network loss or restarts is outside the graded scope;
Appendix B gives a recommended policy. Whatever a client does after a transport
failure, it MUST NOT reset sequence counters while keeping the same keys.

## 5. Identity keys and fingerprints

Each client has one long-term Ed25519 keypair `(idSK, idPK)`. It uploads `idPK`
and keeps `idSK` local. A client MAY generate a new keypair at every start-up,
but a stable key makes fingerprints meaningful.

The **fingerprint** of a user is

```
fp = first 10 bytes of SHA256("JMessage-2026 fingerprint" || idPK)
```

It is displayed as 10 hex pairs separated by spaces, for example
`93 AF 70 ED 10 00 82 91 02 74`.

Clients fetch a peer's `idPK` from the server when they need it. Comparing
fingerprints out of band is the only defense against a server that substitutes
keys. It is out of scope for the graded parts, but your client MUST provide a
command that displays its own fingerprint and that of a named peer. Displaying
a fingerprint alone does not authenticate it.

Before starting or accepting a handshake, obtain the peer's key and store its
exact bytes in that handshake's state. Use that same key for every signature
check in the handshake; do not re-fetch a key to make a failed signature pass.
If the key is missing or cannot be imported, report an error and do not proceed.
Keep the client's own identity key fixed while any handshake or session is
active. (Appendix B describes optional detection of a peer's key changing
between handshakes.)

Ordinary graded client runs use a stable, correct directory. Controlled
security exercises begin with authenticated peer public keys, supplied by
course fixtures; clients MUST use those keys without replacing them from the
directory. These are explicit exercise assumptions, not properties of the
untrusted server. Key-directory substitution is discussed in the written work.

## 6. Handshake

### 6.1 Cipher suites

| Code | Name | Key agreement | Records |
|---|---|---|---|
| `0x0002` | `JM2_X25519MLKEM768_AES256GCM` | X25519 + ML-KEM-768 | AES-256-GCM |
| `0x0001` | `JM1_X25519_AES128CBC_HMACSHA256` | X25519 | AES-128-CBC + HMAC-SHA256 |

JM1 is the legacy suite, kept for compatibility with older clients. Preference
order is JM2 before JM1. Conforming clients MUST implement both suites.
An ordinary initial HELLO MUST offer `[0x0002, 0x0001]`, in that order. Clients
MUST also expose a local compatibility-test option to initiate with only JM1;
this is also the offer
used by the retry in §6.8. Receivers support both offers regardless of this
local option. Suite selection follows the responder's fixed preference order.

### 6.2 Message types

| Type | Name | Sent by |
|---|---|---|
| `0x01` | `HELLO` | initiator |
| `0x02` | `REPLY` | responder |
| `0x03` | `FINISH` | initiator |
| `0x04` | `REJECT` | responder |
| `0x10` | `DATA` | either side |
| `0x11` | `RECEIPT` | either side |
| `0x12` | `RESEND` | either side |

A client MUST silently discard a message body whose type it does not recognize,
or that fails to parse.

### 6.3 HELLO

The initiator, **I**, picks a fresh random 16-byte session identifier `sid` and a
fresh X25519 keypair `(x_I, X_I)`. If it offers JM2, it also generates a fresh
ML-KEM-768 keypair `(dk_I, ek_I)`.

```
HELLO = u8 0x01
     || bytes[16] sid
     || u8 n || u16 suite[n]         -- offered suites, in preference order
     || bytes[32] X_I
     || vec16<ek_I>                  -- 1184 bytes if JM2 is offered, else empty
```

HELLO is not signed. The initiator authenticates itself in FINISH (§6.6).

### 6.4 Processing a HELLO (responder R)

When R receives a HELLO addressed to its local username from user **I** (the
envelope's `from` field), it runs these steps in order. Discard envelopes with
invalid usernames or a different recipient before processing any message type.

1. If it cannot parse the HELLO, or `sid` is already in use, discard it silently.
   A `sid` is *in use* if this client has any state for it: a pending handshake
   in either role, an established session, or a retired identifier (§6.9).
2. Choose the first suite in preference order (JM2, then JM1) that appears in
   `suite[]`. If there is none, send `REJECT` with reason `0x02`
   (`no_common_suite`) and stop.
3. If the chosen suite is JM2, check that `ek_I` is exactly 1184 bytes and passes
   the encapsulation-key check of FIPS 203 §7.2. Some libraries run that check
   when the key is imported and others only at `Encaps`, so treat a failure at
   either point the same way. (Note: the Python `cryptography` library reports
   a key that fails the modulus check with a message about the key's length,
   even when the length is correct.) If any check fails, send `REJECT` with reason
   `0x01` (`hybrid_invalid`) and stop.
4. Obtain and pin I's identity key (§5). If it is unavailable, retire the
   `sid`, report an error, and stop without sending anything. (Steps 2 and 3
   come first so that a REJECT can be sent to a peer whose key is unavailable.)
   Then generate a fresh X25519 keypair `(x_R, X_R)`. For JM2, also compute
   `(ss_pq, ct) = ML-KEM.Encaps(ek_I)`.
5. Compute `dh` and apply §2's X25519 checks. Build REPLY (§6.5) and derive the
   session keys (§6.7). If these operations succeed, store the handshake state
   as *pending-finish* and send REPLY. On a cryptographic failure, discard the
   pending state without sending REPLY. An encapsulation-key validation failure
   uses step 3; other library or backend failures are local errors, not reasons
   to fall back. Whenever R sends a REJECT, it retires the `sid`.

### 6.5 REPLY

```
REPLY_core = u8 0x02
          || bytes[16] sid
          || u16 suite                -- the chosen suite
          || bytes[32] X_R
          || vec16<ct>                -- 1088 bytes for JM2, else empty

TH_R  = SHA256("JMessage-2026 TH-R" || str8(I) || str8(R) || HELLO || REPLY_core)
sig_R = Ed25519.Sign(idSK_R, "JMessage-2026 responder" || TH_R)

REPLY = REPLY_core || bytes[64] sig_R
```

Here `HELLO` means the exact HELLO bytes that R received.

A REPLY whose envelope `from` is not the peer the HELLO was sent to, or whose
`sid` is not in *pending-reply*, is silently discarded without changing any
state (§6.9); it is not a failed check. When I receives a structurally valid
REPLY for a *pending-reply* `sid` from the expected peer R, it:

1. Checks that `suite` is a supported suite it offered, and that `ct` is
   exactly 1088 bytes for JM2 and empty for JM1.
2. Recomputes `TH_R` using the HELLO bytes **it sent** and verifies `sig_R`
   under the peer identity key stored for this handshake (§5).
3. Computes `dh = X25519(x_I, X_R)` and applies §2's X25519 checks.
4. For JM2, computes `ss_pq = ML-KEM.Decaps(dk_I, ct)` using the private key
   retained from this HELLO. For JM1, this step is omitted. A decapsulation
   library error aborts the handshake; it does not trigger fallback.
5. Derives the session keys using §6.7, then sends FINISH as specified in §6.6.

If any check fails, I aborts the handshake and discards the pending state. This
binds the negotiation to both identities: an attacker who changes the offered
suites in transit causes the signature to fail.

### 6.6 FINISH

```
TH_I  = SHA256("JMessage-2026 TH-I" || str8(I) || str8(R) || HELLO || REPLY)
sig_I = Ed25519.Sign(idSK_I, "JMessage-2026 initiator" || TH_I)

FINISH = u8 0x03 || bytes[16] sid || bytes[64] sig_I
```

After deriving the session keys, I sends FINISH. On successful acceptance of
that send by the server, the session is *established* for I, which MAY send
DATA. This transport acceptance is not cryptographic confirmation that R has
derived the same keys. On a failed or uncertain send, apply §4.6.

When R receives a FINISH for a *pending-finish* session from its expected peer,
it verifies `sig_I` under the stored `idPK_I`, using the HELLO and REPLY bytes
it received and sent. If the signature is valid, the session is
established for R. Otherwise R discards the session. R MUST discard any DATA for
a session that is still *pending-finish*.

### 6.7 Key schedule

```
dh = X25519(x_I, X_R) = X25519(x_R, X_I)
ikm = ss_pq || dh          (JM2)
ikm = dh                   (JM1)

TH  = SHA256("JMessage-2026 keys" || str8(I) || str8(R) || HELLO || REPLY)
OKM = HKDF-SHA256(salt = TH, ikm = ikm,
                  info = "JMessage-2026 " || u16 suite, L)
```

The output `OKM` is split in order:

| Suite | L | Split |
|---|---|---|
| JM2 | 64 | `k_IR` (32) · `k_RI` (32) |
| JM1 | 96 | `enc_IR` (16) · `mac_IR` (32) · `enc_RI` (16) · `mac_RI` (32) |

`IR` keys protect records from I to R, and `RI` keys protect records from R to I.

### 6.8 REJECT

```
REJECT = u8 0x04 || bytes[16] sid || u8 reason
      || bytes[64] Ed25519.Sign(idSK_R, "JMessage-2026 reject" || sid || u8 reason || str8(I))
```

REJECT messages are signed so that nobody except the responder can produce a
valid one.

When I receives a REJECT for a pending `sid`, it verifies the signature under
the stored `idPK_R`. If the signature is invalid, I ignores the REJECT and the
handshake stays pending. (This differs deliberately from a REPLY with an
invalid signature, which aborts the handshake: an unsigned or forged REJECT
must not be able to end or redirect a handshake.) If it is valid, I proceeds
as follows.

- **Reason `0x01` (`hybrid_invalid`).** This means the responder could not use
  the initiator's ML-KEM key, which is usually an interoperability problem in one
  of the two post-quantum implementations. I MUST discard the pending handshake
  and immediately send a new HELLO to the same peer, with a fresh `sid`, fresh
  ephemeral keys, and only JM1 offered. It retries **at most once** per original
  HELLO, and the retry reuses the peer identity key pinned for the original
  attempt rather than fetching it again.
- **Any other reason.** I abandons the handshake and reports an error to the
  user.

### 6.9 Sessions

- A session is identified by its `sid`. Its state holds: the peer, the role
  (I or R), the suite, the four or two record keys, `send_seq`, `recv_seq` and
  the handshake bytes. Pending state also retains the required ephemeral
  private keys, peer identity key, start time, and whether the single fallback
  retry has been used. Initialize both counters to zero on establishment.
- A pair of users MAY have several sessions at once. For example, both sides
  might send a HELLO at the same moment.
- To send a message, a client uses the most recently established session with
  that peer. If there is none, it queues the message and starts a handshake,
  unless a handshake with that peer is already pending in either role; queued
  text is sent on whichever session with that peer is established first.
- Clients MAY keep sessions only in memory.

The state transitions are:

| Current state | Accepted event | Result |
|---|---|---|
| No state for `sid` | Start a local handshake | Store HELLO and private keys; enter *pending-reply* |
| No state for `sid` | Accept a peer HELLO | Send REPLY; enter *pending-finish* |
| *pending-reply* | Valid REPLY and successful FINISH send | Enter *established* |
| *pending-reply* | Valid REJECT | Follow §6.8; retire the old `sid` |
| *pending-finish* | Valid FINISH | Enter *established* |
| Either pending state | Fatal validation error or timeout | Abandon handshake and report failure |
| *established* | DATA or control record | Follow §7; never reset counters |

Only process REPLY and REJECT in *pending-reply*, and FINISH in
*pending-finish*. Silently discard other out-of-state messages, including
duplicate REPLY/FINISH after establishment. For every existing session or
handshake, the envelope's `from` MUST match the stored peer and `to` MUST match
the local username; discard mismatches without changing state. Unknown-session
DATA and control records are silently discarded. A duplicate HELLO for an
active or retired `sid` is silently discarded.

Pending handshakes SHOULD expire (Appendix B); a handshake that expires is
abandoned with an error report. Any handshake failure not otherwise specified
(a failed FINISH verification, a cryptographic failure in §6.4 step 5 or §6.5,
an expired handshake) is reported to the user as an error, never raised as an
exception to the caller. Discard ephemeral secrets when
they are no longer needed and discard record keys on abandonment. Keep retired
session identifiers for the lifetime of the process; never reuse them. A retry
uses a new identifier but retains the original attempt's retry budget. A second `hybrid_invalid`, or one for an
attempt that offered only JM1 initially, terminates the attempt with an error.

Queued text remains associated with its peer. If that peer's handshake fails,
report the failure and return the text to the user as unsent rather than
starting an unbounded automatic retry loop. When multiple sessions become
established, choose the latest local establishment event for new outgoing
text; continue accepting incoming records on other established sessions.

## 7. Records

### 7.1 DATA

```
DATA = u8 0x10 || bytes[16] sid || u64 seq || protected
```

`seq` starts at 0 in each direction and increases by 1 for each **new** record
constructed. Retransmitting a cached record does not allocate a new sequence
number. Never assign different plaintext to an already used sequence number
under the same directional keys. Counters MUST NOT wrap (Appendix B).

A receiver processes DATA only for an established session. It discards the
record silently if `seq != recv_seq`. The plaintext is the UTF-8 message text.
Let `k` be the key for the sender's direction. Text is encoded as UTF-8 without
normalization, a byte-order mark added by the encoder, or an added newline.
Empty text is allowed. Senders MUST reject text whose encoding exceeds 4096
bytes before allocating a sequence number. This bound fits the server's base64
payload limit under either suite, including all record overhead.

**JM2:**

```
protected = AES-256-GCM.Encrypt(key = k, nonce = u32 0 || u64 seq,
                                aad = sid || u64 seq, plaintext)
```

`protected` is `ciphertext || tag`, with a 16-byte tag at the end and no nonce
prepended. The nonce is the four zero bytes followed by the eight-byte sequence
number. Each direction uses its own key and sequence counter.

**JM1** (MAC-then-encrypt):

```
T  = HMAC-SHA256(mac, sid || u64 seq || plaintext)
P  = PKCS7-Pad(plaintext || T, 16)
iv = 16 random bytes
protected = iv || AES-128-CBC-Encrypt(enc, iv, P)
```

### 7.2 Receiving DATA

The receiver runs these steps, in this order.

1. Parse the record. For JM1, `protected` must be at least 32 bytes and its
   length a multiple of 16. If not, discard silently.
   For JM2, `protected` must contain at least the 16-byte tag; otherwise discard
   silently. Apply the session, peer, and sequence checks before decryption.
2. **JM2:** decrypt with AES-GCM. If authentication fails, go to step 5.
3. **JM1:**
   1. CBC-decrypt to obtain `P`.
   2. Check the PKCS#7 padding of `P`. The last byte `p` must be between 1 and
      16, and the last `p` bytes must all equal `p`. If the padding is invalid,
      the record is **malformed**: discard it silently.
   3. Remove the padding. If fewer than 32 bytes remain, go to step 5.
   4. Split what remains into `plaintext || T`, where `T` is the last 32 bytes.
      Verify `T` in constant time. If verification fails, go to step 5.
4. Authentication success: advance `recv_seq` and send a `RECEIPT` naming the **received** sequence number. Decode the
   authenticated plaintext as strict UTF-8. If decoding fails or it exceeds
   4096 bytes, report a local application-format error and do not display it as
   text. The sequence number is still consumed and the receipt is still sent;
   do not send a RESEND for an application-format error. Otherwise deliver the
   text exactly once. Processing ends here; do not continue to step 5.
5. Authentication failure: the record was probably damaged in transit, so ask
   the sender to retransmit by sending a `RESEND`. Do not increment `recv_seq`.

### 7.3 RECEIPT and RESEND

Both are unencrypted control messages:

```
RECEIPT = u8 0x11 || bytes[16] sid || u64 seq
RESEND  = u8 0x12 || bytes[16] sid || u64 seq
```

A client MUST NOT send a RECEIPT or RESEND in response to a RECEIPT or RESEND.
On receiving either control message, require an established session, the
expected peer, and a `seq` previously sent in that session's outgoing direction.
Otherwise discard it silently. These messages are unauthenticated: a RECEIPT
is a delivery indication, not cryptographic proof that the peer read the text.

On receiving a RESEND, a client MAY resend the exact cached DATA body, including
its original IV or tag, without re-encrypting or changing the sequence counter.
It MAY instead display a warning, which is sufficient for graded client
behavior. If the body is no longer cached, display a warning. In particular,
never reconstruct a JM2 record from editable text under an old sequence number.
Automatic resending, if implemented, is limited to one resend per record;
further requests only produce a warning. Duplicate RECEIPTs do not change
cryptographic state or advance counters, and a client reports a given receipt
to the user at most once. An already accepted DATA record is
discarded by the sequence check and does not produce a second receipt.

## 8. Client requirements (summary for the autograder)

Your client MUST:

1. Register, log in, upload a key and show fingerprints (§4, §5).
2. Act as both initiator and responder, for both suites (§6).
3. Send and receive text messages, and send RECEIPT and RESEND as specified (§7).

The course server's `echo` user, which replies to every message with the same
text, is a practice peer for checking interoperability. It is not part of
grading; graded tests run locally against controlled peers.

The [assignment handout](handout.md) defines the client interface, test hooks,
and scaffolding boundary. The supplied starter-kit guide documents the driver.

## Appendix A. Test vectors

These vectors were produced by the staff reference implementation with fixed
inputs and checked against an independent implementation of this specification.
All values are hexadecimal. The initiator is `alice` and the responder is `bob`.
ML-KEM-768 private keys are given as the 64-byte FIPS 203 seed `d || z`
(the `from_seed_bytes` format). The ML-KEM ciphertext is a single library
Encaps output; check it with Decaps. Ed25519 signatures are deterministic.

### A.1 Suite 0x0001 (JM1_X25519_AES128CBC_HMACSHA256)

```
alice Ed25519 private key:
  a407ad54fe0e4fd90aecefec0c901b914238097a1fee90577ca80e91cf16796e
alice Ed25519 public key:
  b7a8519a397817f5a47f250cf9dbbcda3f288ffd7a2fa334a8ccabfabcfa8b8b
alice fingerprint: F1 26 31 C6 16 5D E6 90 8D 9A
bob Ed25519 private key:
  07c20c4ef934fc9ee6314d543c98eeb25565bf8d719dbe7b9ca44a5826134923
bob Ed25519 public key:
  30440c94ee6788a28757880a5882fd8b737d29d2962514653d8968c204630477
bob fingerprint: B4 35 0C BD 9D 48 61 D3 A1 30
sid:
  3e4990cc71be28040a8d224873f603b4
x25519_I_private:
  ce69f8017aedb596c2a022071d328bd18f23937817babc7abf5d9cb552ac1f55
x25519_I_public:
  fe9ae3d84bcf05aca21170d84eed83fae3b95a8d4b27f23fa39a4083ca1d5b73
x25519_R_private:
  34ec346bcf486cfbf3fb562e6ed0742424accd1b327e6ec784075e95c7d84b98
x25519_R_public:
  92e64cc3511c134bc4bb415456a8e73dc95a9df163755ee773af9a799c0ed01f
HELLO:
  013e4990cc71be28040a8d224873f603b4010001fe9ae3d84bcf05aca21170d8
  4eed83fae3b95a8d4b27f23fa39a4083ca1d5b730000
REPLY_core:
  023e4990cc71be28040a8d224873f603b4000192e64cc3511c134bc4bb415456
  a8e73dc95a9df163755ee773af9a799c0ed01f0000
TH_R:
  a83fdd88946409a7a9c493aaa13e6ce39727edc9c02c143072d2ccecb06ecea0
sig_R:
  ef18e6aa7c14198cfd2333d7c702f57c9e138479ee1ca0c90b1b7d679fb62c68
  0772ebd85ecba892826afd36f4d774d9d9ee67bae093736bbb6d3299f3ef1306
REPLY:
  023e4990cc71be28040a8d224873f603b4000192e64cc3511c134bc4bb415456
  a8e73dc95a9df163755ee773af9a799c0ed01f0000ef18e6aa7c14198cfd2333
  d7c702f57c9e138479ee1ca0c90b1b7d679fb62c680772ebd85ecba892826afd
  36f4d774d9d9ee67bae093736bbb6d3299f3ef1306
TH_I:
  80639f56c183b1d4941b3a09bc06c2c2741690603c1a53e21a4f635876f080b9
sig_I:
  2ae8bd26271cea1c62df5fcd458b0b8646234a928afc192f0947dbec0282f82e
  e154e9ca40d7e27399ce20b5a18a87c40f666d412d7eedbc3ca9db84bb36d50b
FINISH:
  033e4990cc71be28040a8d224873f603b42ae8bd26271cea1c62df5fcd458b0b
  8646234a928afc192f0947dbec0282f82ee154e9ca40d7e27399ce20b5a18a87
  c40f666d412d7eedbc3ca9db84bb36d50b
dh:
  f395ed1b60ffa6cba13ab9266f97c22a2f0340d0dc13309aa98df35047a63e71
ikm:
  f395ed1b60ffa6cba13ab9266f97c22a2f0340d0dc13309aa98df35047a63e71
TH:
  79fd02b750cc332afa6c7057b4143be40aa21854eaada8cf05065d80e1ab8c77
hkdf_info:
  4a4d6573736167652d32303236200001
OKM:
  897cbb6e5a5a5894f00dac7f438e2e10e57832f36f8518e7bc737ddf4c162f2a
  4542a6ce6ccaef22add57876a2a5eea1c483f6cf133d8e6ff597f74059867872
  d94a1f64382df4f28590c438a7cf3e2381225f9906ad632d25c48c58ea7516cd
enc_IR:
  897cbb6e5a5a5894f00dac7f438e2e10
mac_IR:
  e57832f36f8518e7bc737ddf4c162f2a4542a6ce6ccaef22add57876a2a5eea1
enc_RI:
  c483f6cf133d8e6ff597f74059867872
mac_RI:
  d94a1f64382df4f28590c438a7cf3e2381225f9906ad632d25c48c58ea7516cd
```

Records:

`I->R` seq 0: empty text, text "" (0 bytes)

```
plaintext:
  (empty)
iv:
  87bb0072bd1ca4767d1837cec40d3ff9
T:
  7726217dc2212d7c6d0316ff4e0432bbc59d50b4f04fe1e26cb10d79620d6a25
P:
  7726217dc2212d7c6d0316ff4e0432bbc59d50b4f04fe1e26cb10d79620d6a25
  10101010101010101010101010101010
protected:
  87bb0072bd1ca4767d1837cec40d3ff9672f6d6e9dc848df20738989210b9004
  8440dd236ccfc0d4e640811596a9d1e638b0ba376f4ab88a0e8c78b06006e253
DATA:
  103e4990cc71be28040a8d224873f603b4000000000000000087bb0072bd1ca4
  767d1837cec40d3ff9672f6d6e9dc848df20738989210b90048440dd236ccfc0
  d4e640811596a9d1e638b0ba376f4ab88a0e8c78b06006e253
RECEIPT:
  113e4990cc71be28040a8d224873f603b40000000000000000
```

`I->R` seq 1: multibyte UTF-8 (2-, 3- and 4-byte sequences), text "héllo € 🦉" (15 bytes)

```
plaintext:
  68c3a96c6c6f20e282ac20f09fa689
iv:
  acc4c71d9e5a67736aa3ed495abc28af
T:
  923f8283cbc3a7148810f82f3d9a2e4a3df250449251090687b5cc517b34e693
P:
  68c3a96c6c6f20e282ac20f09fa689923f8283cbc3a7148810f82f3d9a2e4a3d
  f250449251090687b5cc517b34e69301
protected:
  acc4c71d9e5a67736aa3ed495abc28aff9cdd187d1e589cbeb4294e46a45654a
  7fb22d103c395d4c2681dcac4e494da0554ea06931f8d7388805d5270ceb148d
DATA:
  103e4990cc71be28040a8d224873f603b40000000000000001acc4c71d9e5a67
  736aa3ed495abc28aff9cdd187d1e589cbeb4294e46a45654a7fb22d103c395d
  4c2681dcac4e494da0554ea06931f8d7388805d5270ceb148d
RECEIPT:
  113e4990cc71be28040a8d224873f603b40000000000000001
```

`I->R` seq 2: 15 bytes: JM1 P gets 1 padding byte, text "fifteen bytes!!" (15 bytes)

```
plaintext:
  6669667465656e2062797465732121
iv:
  bceb5049dc000ff0bdc947cfc03d1cf4
T:
  78ed658e4ff91e113e4052804fd5252250dda6a1d8912dc65b9e52c6dc415c85
P:
  6669667465656e206279746573212178ed658e4ff91e113e4052804fd5252250
  dda6a1d8912dc65b9e52c6dc415c8501
protected:
  bceb5049dc000ff0bdc947cfc03d1cf4d70580a30d780bd37171905a115d29d9
  c92e0009a146937794e8335d9a37541eada10d2b04f029e808d3d202de0123b5
DATA:
  103e4990cc71be28040a8d224873f603b40000000000000002bceb5049dc000f
  f0bdc947cfc03d1cf4d70580a30d780bd37171905a115d29d9c92e0009a14693
  7794e8335d9a37541eada10d2b04f029e808d3d202de0123b5
RECEIPT:
  113e4990cc71be28040a8d224873f603b40000000000000002
```

`I->R` seq 3: 16 bytes: JM1 P gets a full 16-byte padding block, text "sixteen bytes..." (16 bytes)

```
plaintext:
  7369787465656e2062797465732e2e2e
iv:
  cd0f6186acd534a9e24e4535728e07ad
T:
  06919bb8e9c5059710046bb8295e3f345f8862b1a2f34fc1abd867f4d16d0ba4
P:
  7369787465656e2062797465732e2e2e06919bb8e9c5059710046bb8295e3f34
  5f8862b1a2f34fc1abd867f4d16d0ba410101010101010101010101010101010
protected:
  cd0f6186acd534a9e24e4535728e07adcbf79135578ef65c385579af79a14d54
  62374e36e83b9e897fd977cd53414682b1b1d00765164a2fa0fe949ff06638f9
  8ccadf9f262ae6451d4a337272a44da8
DATA:
  103e4990cc71be28040a8d224873f603b40000000000000003cd0f6186acd534
  a9e24e4535728e07adcbf79135578ef65c385579af79a14d5462374e36e83b9e
  897fd977cd53414682b1b1d00765164a2fa0fe949ff06638f98ccadf9f262ae6
  451d4a337272a44da8
RECEIPT:
  113e4990cc71be28040a8d224873f603b40000000000000003
```

`R->I` seq 0: empty text, text "" (0 bytes)

```
plaintext:
  (empty)
iv:
  641c8da334792610aaa23f2e5902220d
T:
  5b91cc3601b4862a6bb3011f94a134b8ce581f519b4a970c9e144f8d5a82a401
P:
  5b91cc3601b4862a6bb3011f94a134b8ce581f519b4a970c9e144f8d5a82a401
  10101010101010101010101010101010
protected:
  641c8da334792610aaa23f2e5902220da259b903f16f11dd86c9207853fd7348
  c502c26236cef37ec45e70f165174e8b792050b988739c7b835a58f22a914373
DATA:
  103e4990cc71be28040a8d224873f603b40000000000000000641c8da3347926
  10aaa23f2e5902220da259b903f16f11dd86c9207853fd7348c502c26236cef3
  7ec45e70f165174e8b792050b988739c7b835a58f22a914373
RECEIPT:
  113e4990cc71be28040a8d224873f603b40000000000000000
```

`R->I` seq 1: multibyte UTF-8 (2-, 3- and 4-byte sequences), text "héllo € 🦉" (15 bytes)

```
plaintext:
  68c3a96c6c6f20e282ac20f09fa689
iv:
  9a04f43e64944b6a8c55d7fded346393
T:
  ea6c30d287128d1a9f4f9a525ba7c00de1d3f47e094f28adcc91f07db531f939
P:
  68c3a96c6c6f20e282ac20f09fa689ea6c30d287128d1a9f4f9a525ba7c00de1
  d3f47e094f28adcc91f07db531f93901
protected:
  9a04f43e64944b6a8c55d7fded34639352364cfc7a6eb103d53c47f6bed9f978
  76ddf945b94e6cad64b6a0b4b4237985bf64c5c9ee9bad9f2ecbfe1f46c0b3c7
DATA:
  103e4990cc71be28040a8d224873f603b400000000000000019a04f43e64944b
  6a8c55d7fded34639352364cfc7a6eb103d53c47f6bed9f97876ddf945b94e6c
  ad64b6a0b4b4237985bf64c5c9ee9bad9f2ecbfe1f46c0b3c7
RECEIPT:
  113e4990cc71be28040a8d224873f603b40000000000000001
```

`R->I` seq 2: 15 bytes: JM1 P gets 1 padding byte, text "fifteen bytes!!" (15 bytes)

```
plaintext:
  6669667465656e2062797465732121
iv:
  62117d34e037a21067e006b78dc51c8c
T:
  1e15663445afad99acc7306c6e78b8a08c7bd7317e9015c9ee307ffb5065b55d
P:
  6669667465656e20627974657321211e15663445afad99acc7306c6e78b8a08c
  7bd7317e9015c9ee307ffb5065b55d01
protected:
  62117d34e037a21067e006b78dc51c8cc33ddee3245277a0a84523cd2557b240
  f7234f5fa0e2a0dd459086e45c7fc58fffe813a73b7016928c1ea3866d3c2d7c
DATA:
  103e4990cc71be28040a8d224873f603b4000000000000000262117d34e037a2
  1067e006b78dc51c8cc33ddee3245277a0a84523cd2557b240f7234f5fa0e2a0
  dd459086e45c7fc58fffe813a73b7016928c1ea3866d3c2d7c
RECEIPT:
  113e4990cc71be28040a8d224873f603b40000000000000002
```

`R->I` seq 3: 16 bytes: JM1 P gets a full 16-byte padding block, text "sixteen bytes..." (16 bytes)

```
plaintext:
  7369787465656e2062797465732e2e2e
iv:
  9ed1a3b7c6087b8a6441bea0c1fbf7cc
T:
  0a26a97f03f691faf6d7c1c6fa551b60a85fe47675df6568f072a123df57ec39
P:
  7369787465656e2062797465732e2e2e0a26a97f03f691faf6d7c1c6fa551b60
  a85fe47675df6568f072a123df57ec3910101010101010101010101010101010
protected:
  9ed1a3b7c6087b8a6441bea0c1fbf7ccd95e2b1e885aa155d848aea6dbc620b6
  baa97df0ac17fb1e0a28a014541a370312410c180c754cb8773f72948cdac87e
  f35fa4dbd6b1528082b40e9e484d0932
DATA:
  103e4990cc71be28040a8d224873f603b400000000000000039ed1a3b7c6087b
  8a6441bea0c1fbf7ccd95e2b1e885aa155d848aea6dbc620b6baa97df0ac17fb
  1e0a28a014541a370312410c180c754cb8773f72948cdac87ef35fa4dbd6b152
  8082b40e9e484d0932
RECEIPT:
  113e4990cc71be28040a8d224873f603b40000000000000003
```

REJECT (reason 0x01) for the same sid:

```
REJECT:
  043e4990cc71be28040a8d224873f603b401ca543ba07327367efad806a7140b
  42361ff8521ac05d91f0f7caceb7b68ba7d4447b0c253d337047fc11a976d8eb
  1eaad8559837b594405c138f2c94e780a30a
```

### A.2 Suite 0x0002 (JM2_X25519MLKEM768_AES256GCM)

```
alice Ed25519 private key:
  a407ad54fe0e4fd90aecefec0c901b914238097a1fee90577ca80e91cf16796e
alice Ed25519 public key:
  b7a8519a397817f5a47f250cf9dbbcda3f288ffd7a2fa334a8ccabfabcfa8b8b
alice fingerprint: F1 26 31 C6 16 5D E6 90 8D 9A
bob Ed25519 private key:
  07c20c4ef934fc9ee6314d543c98eeb25565bf8d719dbe7b9ca44a5826134923
bob Ed25519 public key:
  30440c94ee6788a28757880a5882fd8b737d29d2962514653d8968c204630477
bob fingerprint: B4 35 0C BD 9D 48 61 D3 A1 30
sid:
  9b31db61637f2f7fd97c3b66826e23b8
x25519_I_private:
  760cdfe1de55763b9f3f3979ff2fc1b3dfd8bc187dfc3eeefe454dd85dcf06c6
x25519_I_public:
  1c2b9bd422a454f26eb003aecfd0a18817ef69e60d0d108ea2088a6fff9e6d76
x25519_R_private:
  f187790b3591f33b6e6bebb4fef27faf9d7115da1ce15e1445d0b92751ca3d44
x25519_R_public:
  3c2b7fc9549d3b329d89b30406b1e19c9cad4fac4e6eb34503325b0d9581b50b
mlkem768_I_seed:
  4055bde582ab395c67364cab29dcc0dfc27d1d2f32c9f9f1f749b4f0498b3398
  dc5ec263ea70f3afe25a2d90d74ed5e77f59e2c16d53ec4b59c1638c030ccec6
mlkem768_I_ek:
  1660177eeaa782e47aa52b6d53e03a5ab3622d0c97c0d6935023a89227879be1
  2f1fbb2ee3b8add44a0d82d807a0c2ac08c8c23b6443b23cc8f6f24266c7bbd6
  a1c75514345f7b805521bcffa37e87c03d097ace59cb653dcc2cee638b05415d
  88f4c42d784fdcd34290e8811a68a4d63009e86975a230be1ec17f91e75184f9
  a66de92a8514307382420e43c80e6210b866c4b2075f00325f6dbcaaf7600962
  a672a55b5c57409ee8121af949ce2fe49adaa110b58ccbe8dcc3db44603a662b
  d910c94dd02487f3120fbc168155cbee182bd45a3f08d2cb1106c59859800937
  abe529584b84585a61721cf6071beb7d1cab95ff5655ec0a69b9e2987287bf54
  87544ad96a8c83378a731e19c9cc3c03b376719709a904dc23ce2b7aad7782cc
  f8694fb3db70814b900042c5cc82984f63325d7c882f9b968a698fb5d07dfd35
  3acd57431b4a25b3283dbd9918179c9a620ac7d44c44e4220b4a791c265163b0
  bc7e8d0767e414c8d4b639cd95a927ca2dda3574365344bc12567c697e29734a
  bde8aed1590db5781f8c8b9b19768b7732c664410b02191f21480d5baba8c386
  0162a8a3cf7ba1aef4c07493b8ef860acb430d32c0c6d3d177dc5a8426a612c3
  5077b7a31cbf1580cb7b2a7962274160cbe2b6888771bac8b4559f2b87b8fa82
  4930affb419941c87742d7260893bc69507128d8bc9d0ca8a542117dd6452e35
  86374c3c36b0187819bdd5c392479480865b6a389901d6d6aab9519ded19bbab
  8a37ebdc013d630a567b728bf4590584633c8540634ca352f9b0219a473ed437
  6792ce34000bfc2a143573b7fc41cfa1d80a38b8b941d1a448f4413725870489
  2bb4bc63495b75dbf227eeb12c03a0c7d8c7aa8be460fdd3818463bbc5e77aaf
  64c52e244311b11db7fa34f3a8782a082d60c33ba2e62b00e408f7847609fa25
  4480b7c6c13278fa29e3a4a88c9c619203406e4167a459a98838760cf796bca2
  b1231530e695cf43f707f274a66267a241b297906646913b171524bedc171653
  e5647600b2e7519969356c38e440fcab0d506aa292b95e5e05ce11d52ad93abc
  a3445640b846af062ce0e4137a548c547839cc3ab6cda5ce76b0782cd469fa8c
  a0d13512a096b0d1a77a13bb12de4a148277789bb247d2b3b813bc38de138fcd
  8c3e119555cfb81aeefc237b32610eea982dfc7a7cc6a939aca89e61533c71be
  6fe61194567b92c68293f00d38307e167a5cc110383d766e45cc1711f45a9692
  79d9d31168a9886a99309842a85f637bc4c9912b248944f4004dd4addc6a4429
  b033036351e07827ee4a2ecdb275cc1ac87de360895800c0728e7fea63e18422
  bc672677d4781eec4125ca6dce73783c56c4a12649a6aa833699a3eba438e429
  5768a97bb75691cc290146454f7796a709608e62dc0476d40cb9bc22a265b5e8
  470dfa7cb1458a1f2a97543c1c3c819c1f39251344f382df3a5121b62726f1ba
  6155adf48c1a2eebb118615f39f606a09415b8b848257c52d774196390422a07
  ab2e738496d3cc81f7527d1854d62c14a8971d59319ed68c55b6c028e39ac2dd
  88cb67f49ab534a4aa3749b0b27da5fb04dc1a2bf5a83651d759055686f7dc0d
  1e54ae53ea5cfc1f163bf8d64da74db1ab1f37e7bd2e92ada120d187ef3393e2
mlkem768_ct:
  a0c372a9e6dbd018aff75c709ab5f2711eed4f1c48b5d9e2e44b620c7f106e29
  89584bc10ca1fddfec1124bb5787fcf6ead506580bd42b72d8af451a75f12dfe
  dfc0cd5421ba844a564de47168867e0ff54bebfbfb30d5730d3688217a2c4fb8
  e96e4cd32473f7f8aba76316d9471067c52d9bde2f655061c6b4ad4a2ae16c96
  6d4013aec10b975a9223c6b303cc3f24f7c1549d684a148b5874650be788ffda
  2c7400dcbb8ae96efd0dbd7038b23565a566e8cb69f5ba82f95d06ab7838ce01
  f77686221add0273651bef45c960c8112b04c0908469f901b194e577d6d878c5
  015fd1fa2beb21d16248ab340f6039af0e4b4157de88714eb64283f35fa372e9
  f864019616eaafc22c4adb820827b0625545be2e90d1b20e522519d14365a476
  e7dea233fa8ea9ae1c3838c6479beecb8f20d766c3713d87dabc19bc124cf5a2
  7abffd3ab22b02ce99604301ff43288bc81761ede84e4bd6134f992f9d50ab97
  33ac9734e2162417ad07028a35c74afd79bfc1b688e19267ea6aeda58c0d0769
  ff800395a1c4d2d2715ebe17eda30029c2a11bfdb2a92be46ebc11bb69860c56
  823e28a079001e7588934aed85051b32a1a64708e55a5e43b850c4eeb4957451
  2427497da51a86cd5b06f22fe1060542c3a4f3a6e0c45b74bc24391adff6f4f6
  61b33c2293a3531ed2f570c9eb70afec18d7578c19caf8364652cd3ed6e9786d
  e53c9e6bd592ee2253a822f8fed23396da2bc9f7e4ddb61140e9105e23650f6e
  d263482a68f23172395223234c096e09c5045dbf7c5ba237307f008e32567407
  a63c12f4fdfc14d6e15f927a154e8043fdbfd67590d217b0aedb0baedf7ffdc9
  04fe96b83b230f3563ac5ba0fa2ffdb26ba7b8de6d4a8c4c4767b92c66cb0c0d
  d1266cb6a61dbc680bd18276aea30deeee5c8558565ef8ba8f5582101f589275
  1c08c6836a4c849d901a395fb68e84c84db753a9c3c490eabd50f2c491d9b12d
  4ab439c42684cc0a72817d0c02dcb1cf04b9cf3bdfa62b3ba0769b80e75a6522
  f3d8c8cfe7280ef13a3a84620b6853f4646d55b8aa5fdd204cd265fd38d6be62
  5529a62c8075cbf33bbe9c07b5c9c679935b0b4bbf4f4234bd93d5379130a2a6
  4fcb056320a9a8e9e7930e9c2c633f333abe30259fd4e067bd10d830fd71f065
  4182bec07ebd237b3c8f036478350a25ad671451d3c1763555fe3f6f0f4f5d13
  f9fc15581d0634323159ee6d534d07e7fbade2267b180e4bf504ffde0527a23a
  451eeda009327e932872867a4bb2cb7ab5502dfb8220e98f4855c9849c160c73
  ad9b65ec8bf08a68ee8c308ec780091b8ba2e34f5f85e9eb2bdd1a07f83f4904
  7edf7b5f564c02408f2f83b1cecdbf76745945471cb25ac0ed1311b9f91cc5c8
  ea9ccc4def6faed9693f79c4c22d01e3980d7bf642325450642a28c9572426df
  470284cc14519a1f27c465b50f25e73db5b27398eb27478507e8f11d0d5eac7c
  f8e4022c838dd0b90808796dc4a5fb183445a0b5036372bf0c2bc3596f648c6a
ss_pq:
  0fcbe46706c53f5ca3a3b1ee7ee7041897cd2c2d4fb0da6231e1a70a0f6b8126
HELLO:
  019b31db61637f2f7fd97c3b66826e23b802000200011c2b9bd422a454f26eb0
  03aecfd0a18817ef69e60d0d108ea2088a6fff9e6d7604a01660177eeaa782e4
  7aa52b6d53e03a5ab3622d0c97c0d6935023a89227879be12f1fbb2ee3b8add4
  4a0d82d807a0c2ac08c8c23b6443b23cc8f6f24266c7bbd6a1c75514345f7b80
  5521bcffa37e87c03d097ace59cb653dcc2cee638b05415d88f4c42d784fdcd3
  4290e8811a68a4d63009e86975a230be1ec17f91e75184f9a66de92a85143073
  82420e43c80e6210b866c4b2075f00325f6dbcaaf7600962a672a55b5c57409e
  e8121af949ce2fe49adaa110b58ccbe8dcc3db44603a662bd910c94dd02487f3
  120fbc168155cbee182bd45a3f08d2cb1106c59859800937abe529584b84585a
  61721cf6071beb7d1cab95ff5655ec0a69b9e2987287bf5487544ad96a8c8337
  8a731e19c9cc3c03b376719709a904dc23ce2b7aad7782ccf8694fb3db70814b
  900042c5cc82984f63325d7c882f9b968a698fb5d07dfd353acd57431b4a25b3
  283dbd9918179c9a620ac7d44c44e4220b4a791c265163b0bc7e8d0767e414c8
  d4b639cd95a927ca2dda3574365344bc12567c697e29734abde8aed1590db578
  1f8c8b9b19768b7732c664410b02191f21480d5baba8c3860162a8a3cf7ba1ae
  f4c07493b8ef860acb430d32c0c6d3d177dc5a8426a612c35077b7a31cbf1580
  cb7b2a7962274160cbe2b6888771bac8b4559f2b87b8fa824930affb419941c8
  7742d7260893bc69507128d8bc9d0ca8a542117dd6452e3586374c3c36b01878
  19bdd5c392479480865b6a389901d6d6aab9519ded19bbab8a37ebdc013d630a
  567b728bf4590584633c8540634ca352f9b0219a473ed4376792ce34000bfc2a
  143573b7fc41cfa1d80a38b8b941d1a448f44137258704892bb4bc63495b75db
  f227eeb12c03a0c7d8c7aa8be460fdd3818463bbc5e77aaf64c52e244311b11d
  b7fa34f3a8782a082d60c33ba2e62b00e408f7847609fa254480b7c6c13278fa
  29e3a4a88c9c619203406e4167a459a98838760cf796bca2b1231530e695cf43
  f707f274a66267a241b297906646913b171524bedc171653e5647600b2e75199
  69356c38e440fcab0d506aa292b95e5e05ce11d52ad93abca3445640b846af06
  2ce0e4137a548c547839cc3ab6cda5ce76b0782cd469fa8ca0d13512a096b0d1
  a77a13bb12de4a148277789bb247d2b3b813bc38de138fcd8c3e119555cfb81a
  eefc237b32610eea982dfc7a7cc6a939aca89e61533c71be6fe61194567b92c6
  8293f00d38307e167a5cc110383d766e45cc1711f45a969279d9d31168a9886a
  99309842a85f637bc4c9912b248944f4004dd4addc6a4429b033036351e07827
  ee4a2ecdb275cc1ac87de360895800c0728e7fea63e18422bc672677d4781eec
  4125ca6dce73783c56c4a12649a6aa833699a3eba438e4295768a97bb75691cc
  290146454f7796a709608e62dc0476d40cb9bc22a265b5e8470dfa7cb1458a1f
  2a97543c1c3c819c1f39251344f382df3a5121b62726f1ba6155adf48c1a2eeb
  b118615f39f606a09415b8b848257c52d774196390422a07ab2e738496d3cc81
  f7527d1854d62c14a8971d59319ed68c55b6c028e39ac2dd88cb67f49ab534a4
  aa3749b0b27da5fb04dc1a2bf5a83651d759055686f7dc0d1e54ae53ea5cfc1f
  163bf8d64da74db1ab1f37e7bd2e92ada120d187ef3393e2
REPLY_core:
  029b31db61637f2f7fd97c3b66826e23b800023c2b7fc9549d3b329d89b30406
  b1e19c9cad4fac4e6eb34503325b0d9581b50b0440a0c372a9e6dbd018aff75c
  709ab5f2711eed4f1c48b5d9e2e44b620c7f106e2989584bc10ca1fddfec1124
  bb5787fcf6ead506580bd42b72d8af451a75f12dfedfc0cd5421ba844a564de4
  7168867e0ff54bebfbfb30d5730d3688217a2c4fb8e96e4cd32473f7f8aba763
  16d9471067c52d9bde2f655061c6b4ad4a2ae16c966d4013aec10b975a9223c6
  b303cc3f24f7c1549d684a148b5874650be788ffda2c7400dcbb8ae96efd0dbd
  7038b23565a566e8cb69f5ba82f95d06ab7838ce01f77686221add0273651bef
  45c960c8112b04c0908469f901b194e577d6d878c5015fd1fa2beb21d16248ab
  340f6039af0e4b4157de88714eb64283f35fa372e9f864019616eaafc22c4adb
  820827b0625545be2e90d1b20e522519d14365a476e7dea233fa8ea9ae1c3838
  c6479beecb8f20d766c3713d87dabc19bc124cf5a27abffd3ab22b02ce996043
  01ff43288bc81761ede84e4bd6134f992f9d50ab9733ac9734e2162417ad0702
  8a35c74afd79bfc1b688e19267ea6aeda58c0d0769ff800395a1c4d2d2715ebe
  17eda30029c2a11bfdb2a92be46ebc11bb69860c56823e28a079001e7588934a
  ed85051b32a1a64708e55a5e43b850c4eeb49574512427497da51a86cd5b06f2
  2fe1060542c3a4f3a6e0c45b74bc24391adff6f4f661b33c2293a3531ed2f570
  c9eb70afec18d7578c19caf8364652cd3ed6e9786de53c9e6bd592ee2253a822
  f8fed23396da2bc9f7e4ddb61140e9105e23650f6ed263482a68f23172395223
  234c096e09c5045dbf7c5ba237307f008e32567407a63c12f4fdfc14d6e15f92
  7a154e8043fdbfd67590d217b0aedb0baedf7ffdc904fe96b83b230f3563ac5b
  a0fa2ffdb26ba7b8de6d4a8c4c4767b92c66cb0c0dd1266cb6a61dbc680bd182
  76aea30deeee5c8558565ef8ba8f5582101f5892751c08c6836a4c849d901a39
  5fb68e84c84db753a9c3c490eabd50f2c491d9b12d4ab439c42684cc0a72817d
  0c02dcb1cf04b9cf3bdfa62b3ba0769b80e75a6522f3d8c8cfe7280ef13a3a84
  620b6853f4646d55b8aa5fdd204cd265fd38d6be625529a62c8075cbf33bbe9c
  07b5c9c679935b0b4bbf4f4234bd93d5379130a2a64fcb056320a9a8e9e7930e
  9c2c633f333abe30259fd4e067bd10d830fd71f0654182bec07ebd237b3c8f03
  6478350a25ad671451d3c1763555fe3f6f0f4f5d13f9fc15581d0634323159ee
  6d534d07e7fbade2267b180e4bf504ffde0527a23a451eeda009327e93287286
  7a4bb2cb7ab5502dfb8220e98f4855c9849c160c73ad9b65ec8bf08a68ee8c30
  8ec780091b8ba2e34f5f85e9eb2bdd1a07f83f49047edf7b5f564c02408f2f83
  b1cecdbf76745945471cb25ac0ed1311b9f91cc5c8ea9ccc4def6faed9693f79
  c4c22d01e3980d7bf642325450642a28c9572426df470284cc14519a1f27c465
  b50f25e73db5b27398eb27478507e8f11d0d5eac7cf8e4022c838dd0b9080879
  6dc4a5fb183445a0b5036372bf0c2bc3596f648c6a
TH_R:
  002a3f4b2615a82367ef54b5ea1664344cd5a8cfc0229803e74ec7dd344a632e
sig_R:
  9bb113ad61b4305360e99e2d4fd6d16b94dcc19edefa747d7db4c07b12694647
  08d2fc7b0af38943d45e3793408e13181e8cea4ed754a39066adfdde13739e04
REPLY:
  029b31db61637f2f7fd97c3b66826e23b800023c2b7fc9549d3b329d89b30406
  b1e19c9cad4fac4e6eb34503325b0d9581b50b0440a0c372a9e6dbd018aff75c
  709ab5f2711eed4f1c48b5d9e2e44b620c7f106e2989584bc10ca1fddfec1124
  bb5787fcf6ead506580bd42b72d8af451a75f12dfedfc0cd5421ba844a564de4
  7168867e0ff54bebfbfb30d5730d3688217a2c4fb8e96e4cd32473f7f8aba763
  16d9471067c52d9bde2f655061c6b4ad4a2ae16c966d4013aec10b975a9223c6
  b303cc3f24f7c1549d684a148b5874650be788ffda2c7400dcbb8ae96efd0dbd
  7038b23565a566e8cb69f5ba82f95d06ab7838ce01f77686221add0273651bef
  45c960c8112b04c0908469f901b194e577d6d878c5015fd1fa2beb21d16248ab
  340f6039af0e4b4157de88714eb64283f35fa372e9f864019616eaafc22c4adb
  820827b0625545be2e90d1b20e522519d14365a476e7dea233fa8ea9ae1c3838
  c6479beecb8f20d766c3713d87dabc19bc124cf5a27abffd3ab22b02ce996043
  01ff43288bc81761ede84e4bd6134f992f9d50ab9733ac9734e2162417ad0702
  8a35c74afd79bfc1b688e19267ea6aeda58c0d0769ff800395a1c4d2d2715ebe
  17eda30029c2a11bfdb2a92be46ebc11bb69860c56823e28a079001e7588934a
  ed85051b32a1a64708e55a5e43b850c4eeb49574512427497da51a86cd5b06f2
  2fe1060542c3a4f3a6e0c45b74bc24391adff6f4f661b33c2293a3531ed2f570
  c9eb70afec18d7578c19caf8364652cd3ed6e9786de53c9e6bd592ee2253a822
  f8fed23396da2bc9f7e4ddb61140e9105e23650f6ed263482a68f23172395223
  234c096e09c5045dbf7c5ba237307f008e32567407a63c12f4fdfc14d6e15f92
  7a154e8043fdbfd67590d217b0aedb0baedf7ffdc904fe96b83b230f3563ac5b
  a0fa2ffdb26ba7b8de6d4a8c4c4767b92c66cb0c0dd1266cb6a61dbc680bd182
  76aea30deeee5c8558565ef8ba8f5582101f5892751c08c6836a4c849d901a39
  5fb68e84c84db753a9c3c490eabd50f2c491d9b12d4ab439c42684cc0a72817d
  0c02dcb1cf04b9cf3bdfa62b3ba0769b80e75a6522f3d8c8cfe7280ef13a3a84
  620b6853f4646d55b8aa5fdd204cd265fd38d6be625529a62c8075cbf33bbe9c
  07b5c9c679935b0b4bbf4f4234bd93d5379130a2a64fcb056320a9a8e9e7930e
  9c2c633f333abe30259fd4e067bd10d830fd71f0654182bec07ebd237b3c8f03
  6478350a25ad671451d3c1763555fe3f6f0f4f5d13f9fc15581d0634323159ee
  6d534d07e7fbade2267b180e4bf504ffde0527a23a451eeda009327e93287286
  7a4bb2cb7ab5502dfb8220e98f4855c9849c160c73ad9b65ec8bf08a68ee8c30
  8ec780091b8ba2e34f5f85e9eb2bdd1a07f83f49047edf7b5f564c02408f2f83
  b1cecdbf76745945471cb25ac0ed1311b9f91cc5c8ea9ccc4def6faed9693f79
  c4c22d01e3980d7bf642325450642a28c9572426df470284cc14519a1f27c465
  b50f25e73db5b27398eb27478507e8f11d0d5eac7cf8e4022c838dd0b9080879
  6dc4a5fb183445a0b5036372bf0c2bc3596f648c6a9bb113ad61b4305360e99e
  2d4fd6d16b94dcc19edefa747d7db4c07b1269464708d2fc7b0af38943d45e37
  93408e13181e8cea4ed754a39066adfdde13739e04
TH_I:
  3afdcbcb8d37d0ae0d43224f01cbb3958c7a8c6bf89edacf2ab4591ec97657d0
sig_I:
  4b2f310efcadd7c0d2af8337de2b97af040142782202944da4be75fa05d5433c
  38ddc38c328efaaec4ffa22527ada25aa7528708b2ceda460bd30de8220de50c
FINISH:
  039b31db61637f2f7fd97c3b66826e23b84b2f310efcadd7c0d2af8337de2b97
  af040142782202944da4be75fa05d5433c38ddc38c328efaaec4ffa22527ada2
  5aa7528708b2ceda460bd30de8220de50c
dh:
  de8f4e38c62abca8e8e77a9d0f360e01b294e077cf892df5dfef49ed91238d5a
ikm:
  0fcbe46706c53f5ca3a3b1ee7ee7041897cd2c2d4fb0da6231e1a70a0f6b8126
  de8f4e38c62abca8e8e77a9d0f360e01b294e077cf892df5dfef49ed91238d5a
TH:
  827ca2c42f261c06de21e0cb84272621cc9a19c5c974a554494a6e7929796dd7
hkdf_info:
  4a4d6573736167652d32303236200002
OKM:
  3d6020927c9356c730bf3963ddad7433c1831f02c120fbc342705ff873d97389
  0b8d2e53bab249967530a918c08df2a7f78d61eaf93d6e3fec5d0d7b1fb0fa3c
k_IR:
  3d6020927c9356c730bf3963ddad7433c1831f02c120fbc342705ff873d97389
k_RI:
  0b8d2e53bab249967530a918c08df2a7f78d61eaf93d6e3fec5d0d7b1fb0fa3c
```

Records:

`I->R` seq 0: empty text, text "" (0 bytes)

```
plaintext:
  (empty)
nonce:
  000000000000000000000000
aad:
  9b31db61637f2f7fd97c3b66826e23b80000000000000000
protected:
  9917346d1f5d3e8cfcb9736707593c94
DATA:
  109b31db61637f2f7fd97c3b66826e23b800000000000000009917346d1f5d3e
  8cfcb9736707593c94
RECEIPT:
  119b31db61637f2f7fd97c3b66826e23b80000000000000000
```

`I->R` seq 1: multibyte UTF-8 (2-, 3- and 4-byte sequences), text "héllo € 🦉" (15 bytes)

```
plaintext:
  68c3a96c6c6f20e282ac20f09fa689
nonce:
  000000000000000000000001
aad:
  9b31db61637f2f7fd97c3b66826e23b80000000000000001
protected:
  fb8c72e7b42ea562f88edbab481c730fa3c01f5c2a0e29f32014a2864d1812
DATA:
  109b31db61637f2f7fd97c3b66826e23b80000000000000001fb8c72e7b42ea5
  62f88edbab481c730fa3c01f5c2a0e29f32014a2864d1812
RECEIPT:
  119b31db61637f2f7fd97c3b66826e23b80000000000000001
```

`I->R` seq 2: 15 bytes: JM1 P gets 1 padding byte, text "fifteen bytes!!" (15 bytes)

```
plaintext:
  6669667465656e2062797465732121
nonce:
  000000000000000000000002
aad:
  9b31db61637f2f7fd97c3b66826e23b80000000000000002
protected:
  d80e0b7be28ef389526e894d003eeb2521691278cb482b7eee51ad2458d2da
DATA:
  109b31db61637f2f7fd97c3b66826e23b80000000000000002d80e0b7be28ef3
  89526e894d003eeb2521691278cb482b7eee51ad2458d2da
RECEIPT:
  119b31db61637f2f7fd97c3b66826e23b80000000000000002
```

`I->R` seq 3: 16 bytes: JM1 P gets a full 16-byte padding block, text "sixteen bytes..." (16 bytes)

```
plaintext:
  7369787465656e2062797465732e2e2e
nonce:
  000000000000000000000003
aad:
  9b31db61637f2f7fd97c3b66826e23b80000000000000003
protected:
  bc27df7c3aff5d881bb6a457cd9083553f010f49b4eb90581238273e1df21bfb
DATA:
  109b31db61637f2f7fd97c3b66826e23b80000000000000003bc27df7c3aff5d
  881bb6a457cd9083553f010f49b4eb90581238273e1df21bfb
RECEIPT:
  119b31db61637f2f7fd97c3b66826e23b80000000000000003
```

`R->I` seq 0: empty text, text "" (0 bytes)

```
plaintext:
  (empty)
nonce:
  000000000000000000000000
aad:
  9b31db61637f2f7fd97c3b66826e23b80000000000000000
protected:
  486b40366d3b78e808b28b3dbb31d85c
DATA:
  109b31db61637f2f7fd97c3b66826e23b80000000000000000486b40366d3b78
  e808b28b3dbb31d85c
RECEIPT:
  119b31db61637f2f7fd97c3b66826e23b80000000000000000
```

`R->I` seq 1: multibyte UTF-8 (2-, 3- and 4-byte sequences), text "héllo € 🦉" (15 bytes)

```
plaintext:
  68c3a96c6c6f20e282ac20f09fa689
nonce:
  000000000000000000000001
aad:
  9b31db61637f2f7fd97c3b66826e23b80000000000000001
protected:
  2a75280d57cb817e32430367b04a03c391a5fb2045aa54f165a2acc3e63875
DATA:
  109b31db61637f2f7fd97c3b66826e23b800000000000000012a75280d57cb81
  7e32430367b04a03c391a5fb2045aa54f165a2acc3e63875
RECEIPT:
  119b31db61637f2f7fd97c3b66826e23b80000000000000001
```

`R->I` seq 2: 15 bytes: JM1 P gets 1 padding byte, text "fifteen bytes!!" (15 bytes)

```
plaintext:
  6669667465656e2062797465732121
nonce:
  000000000000000000000002
aad:
  9b31db61637f2f7fd97c3b66826e23b80000000000000002
protected:
  e27be884cb14de936e95c2170a5325812c79634d8ccdb5876b62aafd84ad3b
DATA:
  109b31db61637f2f7fd97c3b66826e23b80000000000000002e27be884cb14de
  936e95c2170a5325812c79634d8ccdb5876b62aafd84ad3b
RECEIPT:
  119b31db61637f2f7fd97c3b66826e23b80000000000000002
```

`R->I` seq 3: 16 bytes: JM1 P gets a full 16-byte padding block, text "sixteen bytes..." (16 bytes)

```
plaintext:
  7369787465656e2062797465732e2e2e
nonce:
  000000000000000000000003
aad:
  9b31db61637f2f7fd97c3b66826e23b80000000000000003
protected:
  fb322aea26e145c1507fab1fac43d944c0aad1e7fbddea3c0ae7c638fe299f2b
DATA:
  109b31db61637f2f7fd97c3b66826e23b80000000000000003fb322aea26e145
  c1507fab1fac43d944c0aad1e7fbddea3c0ae7c638fe299f2b
RECEIPT:
  119b31db61637f2f7fd97c3b66826e23b80000000000000003
```

REJECT (reason 0x01) for the same sid:

```
REJECT:
  049b31db61637f2f7fd97c3b66826e23b80135870f63d4823c76d76596462a89
  195aef82a12a680213d2b97e662df828e382d941fce006faf2f66099108f0345
  d3c6f0acdbbd38a2ee0790495f6baf079f0b
```

## Appendix B. Robustness recommendations (not graded)

These practices make a client behave sensibly outside the graded scenarios.
Clients SHOULD follow them, and the autograder does not test them.

- **Strict base64.** Reject whitespace, characters outside the alphabet, and
  missing or incorrect padding. Re-encoding the decoded bytes should reproduce
  the original string. The starter kit's decoder does this.
- **Transport failures.** On a failed or uncertain send or receive, report the
  error. Then either stop, or abandon the affected sessions (all sessions after
  an uncertain receive) and start fresh handshakes before sending new text. Do
  not silently resend text whose delivery is uncertain; the user can choose to
  send it again in a fresh session.
- **Handshake expiry.** Expire pending handshakes once 60 seconds or more
  have elapsed since creation,
  measured with a monotonic clock, checking before processing an incoming
  message for that handshake and during polling. Invalid or duplicate messages
  do not extend the deadline. A fallback retry gets a new deadline.
- **Peer key changes.** If a later directory lookup returns a different key for
  a peer you have already talked to, report it and require an explicit local
  trust reset, which abandons that peer's handshakes and sessions, before using
  the new key. This detects changes after first contact; it does not
  authenticate the first key.
- **Counter exhaustion.** After sequence number `2^64 - 1`, a direction is
  exhausted: new text requires a fresh session, and a receiver marks the
  direction exhausted instead of wrapping to zero.

## Changelog

- **1.1 (October 5, 2026, before release).** Added Appendix A test vectors.
  Clarified: a REPLY from the wrong peer or for a non-pending `sid` is
  discarded, not a failed check (§6.5); an invalid REJECT signature leaves the
  handshake pending, deliberately unlike an invalid REPLY signature (§6.8);
  the fallback retry reuses the pinned peer key (§6.8); `send_text` starts a
  handshake only when none is pending with that peer (§6.9); the meaning of
  "`sid` in use", the placement of the identity-key lookup in HELLO
  processing, and that every REJECT retires its `sid` (§6.4); a JM2 offer with
  an `ek_I` of the wrong length, including empty, is `hybrid_invalid` (§3);
  unspecified handshake failures are reported as errors, and expiry is at
  ≥ 60 s (§6.9, Appendix B); duplicate RECEIPTs are reported once (§7.3).
- **1.0 (October 5, 2026).** Release version.
