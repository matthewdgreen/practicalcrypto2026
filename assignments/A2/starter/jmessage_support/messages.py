"""Wire format of the seven JMessage message bodies (specification §§6-7).

What this file is for
---------------------
Supplied so that you do not spend your time on byte packing. Each `encode_*`
produces exactly the layout in the specification; each `parse_*` enforces the
structural rules of §3 (bounds, length prefixes, no trailing bytes, HELLO's
suite-list rules) and raises `DecodeError` on any violation, which your client
turns into a silent discard (§6.2).

Where it sits
-------------

      your protocol.py  --- decides what to send, what to accept, what to hash
            |    ^
     encode_*    parse_*
            v    |
      messages.py  (this file: bytes <-> small frozen dataclasses)
            |
        codec.py   (u8/u16/u64, vec16, Reader)

What you should learn from reading it
-------------------------------------
* The exact byte layout of each message, side by side with the spec notation.
  For example, an ordinary HELLO offering both suites is

      01                      u8 type = HELLO
      <16 bytes>              sid
      02                      u8 n = 2 suites
      00 02  00 01            u16 suite[0] = JM2, u16 suite[1] = JM1
      <32 bytes>              X_I (X25519 public key)
      04 a0                   u16 length of ek_I = 1184
      <1184 bytes>            ek_I (ML-KEM-768 encapsulation key)

  for 1 + 16 + 1 + 4 + 32 + 2 + 1184 = 1240 bytes in total.
* Where structural checks end and semantic checks begin. `parse_hello`
  rejects a HELLO whose `ek_I` field is truncated, but it accepts a fully
  present `ek_I` of the wrong length when JM2 is offered, because §3 and §6.4
  step 3 say that case gets a REJECT, not a silent discard.
* Why `Reply.core` exists: §6.5 signs `REPLY_core`, which is every byte of the
  REPLY except the signature. Because these parsers are strict, re-encoding
  the parsed fields would give the same bytes; slicing the received body means
  nobody has to rely on that argument. Hash the bytes you actually received.

What it deliberately does NOT do
--------------------------------
It does not compute transcript hashes, decide what any signature covers, derive
keys, protect or unprotect records, or decide whether a message is acceptable
in the current state. Those are the decisions the assignment is about, and they
live in your `protocol.py`. Read the spec section cited next to each function;
you should be able to write out a HELLO byte by byte without looking here.

Two related details: `encode_reject` takes a finished signature, because what
the REJECT signature covers (§6.8) is your job; and `parse_data` does not check
the length of `protected`, because the minimum length depends on the session's
suite (§7.2 step 1), which only your client knows.

Specification sections: §2 (sizes), §3 (structural rules), §6.1 (suites),
§6.2 (types), §6.3 HELLO, §6.5 REPLY, §6.6 FINISH, §6.8 REJECT, §7.1 DATA,
§7.3 RECEIPT/RESEND.
"""

from dataclasses import dataclass

from .codec import DecodeError, Reader, u8, u16, u64

# ----- Protocol constants -------------------------------------------------------
# Every number that appears on the wire, named once. Import these rather than
# writing 0x02 or 1184 in your own code; a typo in a constant is a hard bug to
# find because both copies of your client will agree with each other.

# Message types (§6.2). The first byte of every body.
T_HELLO, T_REPLY, T_FINISH, T_REJECT = 0x01, 0x02, 0x03, 0x04
T_DATA, T_RECEIPT, T_RESEND = 0x10, 0x11, 0x12

# Cipher suites (§6.1), in the responder's fixed preference order
JM1 = 0x0001                     # JM1_X25519_AES128CBC_HMACSHA256 (legacy)
JM2 = 0x0002                     # JM2_X25519MLKEM768_AES256GCM
# §6.1/§6.4 step 2: the responder picks the first entry of this tuple that the
# HELLO offers. The order of the initiator's list does not change the choice.
PREFERENCE = (JM2, JM1)

# REJECT reasons (§6.8)
REASON_HYBRID_INVALID = 0x01     # responder could not use the initiator's ML-KEM key
REASON_NO_COMMON_SUITE = 0x02    # no offered suite is one the responder supports

# Fixed field sizes (§2)
SID_LEN = 16                     # session identifier, chosen at random by I (§6.3)
X25519_LEN = 32                  # raw X25519 public key (RFC 7748)
ED25519_PK_LEN = 32              # raw Ed25519 public key (RFC 8032)
SIG_LEN = 64                     # raw Ed25519 signature
MLKEM_EK_LEN = 1184              # ML-KEM-768 encapsulation key (FIPS 203)
MLKEM_CT_LEN = 1088              # ML-KEM-768 ciphertext (FIPS 203)


# ----- Parsed message structures ------------------------------------------------
# One frozen dataclass per message. "Frozen" means the fields cannot be
# reassigned after parsing, so a parsed message cannot be edited by accident
# between the check that accepted it and the code that uses it.

@dataclass(frozen=True)
class Hello:
    """A parsed HELLO (§6.3).

    Attributes:
        sid: 16-byte session identifier chosen by the initiator.
        suites: tuple of `int` suite codes, in the order the initiator listed
            them. Guaranteed nonempty and duplicate-free by `parse_hello`; may
            contain unknown codes, which §3 says to ignore during selection.
        x_pub: the initiator's 32-byte ephemeral X25519 public key, X_I.
        ek: the initiator's ML-KEM-768 encapsulation key, ek_I, as raw bytes.
            Empty if JM2 is not offered (`parse_hello` enforces that). If JM2
            is offered, its length has NOT been checked: that is §6.4 step 3.
    """
    sid: bytes
    suites: tuple
    x_pub: bytes
    ek: bytes


@dataclass(frozen=True)
class Reply:
    """A parsed REPLY (§6.5).

    Attributes:
        sid: the session identifier from the HELLO being answered.
        suite: the `int` suite code the responder chose. Not checked here;
            §6.5 step 1 (offered and supported) is your job.
        x_pub: the responder's 32-byte ephemeral X25519 public key, X_R.
        ct: the ML-KEM ciphertext. Present-but-unchecked: §6.5 step 1 requires
            1088 bytes for JM2 and empty for JM1.
        sig: the responder's 64-byte signature, sig_R.
        core: REPLY_core, every byte of the received body before `sig`. This is
            the exact byte string that TH_R covers (§6.5).
    """
    sid: bytes
    suite: int
    x_pub: bytes
    ct: bytes
    sig: bytes
    core: bytes          # REPLY_core: every byte before sig_R (what TH_R hashes)


@dataclass(frozen=True)
class Finish:
    """A parsed FINISH (§6.6): the session identifier and the initiator's sig_I."""
    sid: bytes
    sig: bytes


@dataclass(frozen=True)
class Reject:
    """A parsed REJECT (§6.8).

    Attributes:
        sid: the session identifier of the rejected HELLO.
        reason: the `int` reason code (REASON_* above; others are possible).
        sig: the responder's 64-byte signature. What it covers is in §6.8.
    """
    sid: bytes
    reason: int
    sig: bytes


@dataclass(frozen=True)
class Data:
    """A parsed DATA record (§7.1).

    Attributes:
        sid: the session the record claims to belong to.
        seq: the `int` sequence number from the u64 field.
        protected: every remaining byte of the body. Its internal structure
            (IV, ciphertext, tag) depends on the suite and is §7.1-§7.2.
    """
    sid: bytes
    seq: int
    protected: bytes


@dataclass(frozen=True)
class Control:          # RECEIPT or RESEND
    """A parsed RECEIPT or RESEND (§7.3); `kind` is T_RECEIPT or T_RESEND."""
    kind: int
    sid: bytes
    seq: int


# ----- HELLO (§6.3) -------------------------------------------------------------

def encode_hello(sid, suites, x_pub, ek):
    """Build a HELLO body.

    Args:
        sid: 16 random bytes (§6.3). Not length-checked here; pass SID_LEN bytes.
        suites: iterable of `int` suite codes, in your preference order. An
            ordinary HELLO offers (JM2, JM1); the JM1-only option offers (JM1,).
        x_pub: your 32-byte ephemeral X25519 public key.
        ek: your 1184-byte ML-KEM encapsulation key if JM2 is offered, else b"".

    Returns:
        The body `bytes`. Keep a copy: you will need these exact bytes again
        for the transcript hashes (§6.5 "the HELLO bytes it sent").

    Raises:
        ValueError: if a suite code or the number of suites does not fit its
            field (from `u8`/`u16`).
    """
    # §6.3 HELLO = u8 0x01 || sid || u8 n || u16 suite[n] || X_I || vec16<ek_I>
    out = u8(T_HELLO) + sid + u8(len(suites))
    for suite in suites:
        out += u16(suite)
    # u16(len(ek)) + ek is vec16<ek_I>, written out so the layout reads like §6.3.
    return out + x_pub + u16(len(ek)) + ek


def parse_hello(body):
    """Parse a HELLO body and apply §3's structural rules.

    Args:
        body: the decoded message `bytes`.

    Returns:
        A `Hello`.

    Raises:
        DecodeError: if the type byte is not HELLO; any field is truncated;
            there are trailing bytes; the suite list is empty or has
            duplicates; or `ek_I` is nonempty although JM2 is not offered.
            Per §3 each of these means "discard silently".

    Not checked here (on purpose): whether any offered suite is supported
    (§6.4 step 2) and whether `ek_I` has the right length for JM2 (§6.4 step 3).
    Those failures are answered with a REJECT, not a silent discard, so they
    belong to your HELLO-processing logic.
    """
    r = Reader(body)
    if r.u8() != T_HELLO:
        raise DecodeError("not a HELLO")
    sid = r.take(SID_LEN)
    n = r.u8()                                   # §3: n counts two-byte suite ids
    suites = tuple(r.u16() for _ in range(n))
    x_pub = r.take(X25519_LEN)
    ek = r.vec16()                               # §3: semantic length is checked in §6.4 step 3
    r.finish()                                   # §3: trailing bytes are structural errors
    if n == 0 or len(set(suites)) != n:          # §3: n = 0 or duplicates -> discard
        raise DecodeError("empty or duplicate suite list")
    if JM2 not in suites and ek:                 # §3: no JM2 -> ek_I MUST be empty
        raise DecodeError("ek_I present without JM2")
    return Hello(sid, suites, x_pub, ek)


# ----- REPLY (§6.5) -------------------------------------------------------------

def encode_reply_core(sid, suite, x_pub, ct):
    """Build REPLY_core: the REPLY without its signature.

    Args:
        sid: the 16-byte session identifier from the HELLO.
        suite: the chosen `int` suite code.
        x_pub: your 32-byte ephemeral X25519 public key, X_R.
        ct: the 1088-byte ML-KEM ciphertext for JM2, or b"" for JM1.

    Returns:
        REPLY_core `bytes`. You hash these into TH_R, sign, and append the
        64-byte signature to get the full REPLY (§6.5). There is no
        `encode_reply`: the signature step is protocol logic, so it is yours.
    """
    # §6.5 REPLY_core = u8 0x02 || sid || u16 suite || X_R || vec16<ct>
    return u8(T_REPLY) + sid + u16(suite) + x_pub + u16(len(ct)) + ct


def parse_reply(body):
    """Parse a REPLY body.

    Args:
        body: the decoded message `bytes`.

    Returns:
        A `Reply` whose `core` is the exact prefix of `body` before the
        signature.

    Raises:
        DecodeError: wrong type byte, truncated field, or trailing bytes.

    The suite value and the ciphertext length are not checked here; §6.5
    step 1 does that, and a failure there aborts the handshake rather than
    being silently discarded.
    """
    r = Reader(body)
    if r.u8() != T_REPLY:
        raise DecodeError("not a REPLY")
    sid = r.take(SID_LEN)
    suite = r.u16()
    x_pub = r.take(X25519_LEN)
    ct = r.vec16()
    # Everything consumed so far is REPLY_core. Slice it from the original body
    # rather than re-encoding the fields: the signature is over received bytes.
    core_len = len(body) - r.remaining
    sig = r.take(SIG_LEN)
    r.finish()
    return Reply(sid, suite, x_pub, ct, sig, body[:core_len])


# ----- FINISH (§6.6) ------------------------------------------------------------

def encode_finish(sid, sig):
    """Build a FINISH body: `u8 0x03 || sid || sig_I` (§6.6).

    Args:
        sid: the 16-byte session identifier.
        sig: your 64-byte signature sig_I, which you compute (§6.6).

    Returns:
        The body `bytes` (81 bytes).
    """
    return u8(T_FINISH) + sid + sig              # §6.6


def parse_finish(body):
    """Parse a FINISH body into a `Finish`.

    Raises:
        DecodeError: wrong type byte, truncated field, or trailing bytes.
    """
    r = Reader(body)
    if r.u8() != T_FINISH:
        raise DecodeError("not a FINISH")
    sid, sig = r.take(SID_LEN), r.take(SIG_LEN)
    r.finish()
    return Finish(sid, sig)


# ----- REJECT (§6.8) ------------------------------------------------------------

def encode_reject(sid, reason, sig):
    """Build a REJECT body: `u8 0x04 || sid || u8 reason || sig` (§6.8).

    Args:
        sid: the 16-byte session identifier of the HELLO being rejected.
        reason: an `int` reason code, normally a REASON_* constant.
        sig: the 64-byte signature. Note that the signed message in §6.8 is
            not the same as these body bytes; building it is your job.

    Returns:
        The body `bytes` (82 bytes).
    """
    return u8(T_REJECT) + sid + u8(reason) + sig  # §6.8 (the signed bytes are your job)


def parse_reject(body):
    """Parse a REJECT body into a `Reject`.

    Raises:
        DecodeError: wrong type byte, truncated field, or trailing bytes.
    """
    r = Reader(body)
    if r.u8() != T_REJECT:
        raise DecodeError("not a REJECT")
    sid, reason, sig = r.take(SID_LEN), r.u8(), r.take(SIG_LEN)
    r.finish()
    return Reject(sid, reason, sig)


# ----- DATA (§7.1) --------------------------------------------------------------

def encode_data(sid, seq, protected):
    """Build a DATA body: `u8 0x10 || sid || u64 seq || protected` (§7.1).

    Args:
        sid: the 16-byte session identifier.
        seq: the `int` sequence number for this record, 0 .. 2**64 - 1.
        protected: the suite-specific encrypted payload you computed (§7.1).

    Returns:
        The body `bytes`.

    Raises:
        ValueError: if `seq` does not fit in a u64.
    """
    return u8(T_DATA) + sid + u64(seq) + protected   # §7.1


def parse_data(body):
    """Parse a DATA body into a `Data`.

    Raises:
        DecodeError: wrong type byte or a header shorter than 25 bytes.

    There is no `finish()` call because `protected` is "all remaining bytes"
    (§3). Its minimum length is checked in §7.2 step 1, by your code.
    """
    r = Reader(body)
    if r.u8() != T_DATA:
        raise DecodeError("not DATA")
    sid, seq = r.take(SID_LEN), r.u64()
    return Data(sid, seq, r.rest())              # §3: all remaining bytes are `protected`


# ----- RECEIPT and RESEND (§7.3) ------------------------------------------------

def encode_control(kind, sid, seq):
    """Build a RECEIPT or RESEND body: `u8 kind || sid || u64 seq` (§7.3).

    Args:
        kind: T_RECEIPT or T_RESEND.
        sid: the 16-byte session identifier.
        seq: the `int` sequence number being acknowledged or requested.

    Returns:
        The body `bytes` (25 bytes).

    Raises:
        ValueError: if `kind` is not one of the two control types, or `seq`
            does not fit in a u64.
    """
    if kind not in (T_RECEIPT, T_RESEND):
        raise ValueError("kind must be T_RECEIPT or T_RESEND")
    return u8(kind) + sid + u64(seq)             # §7.3 RECEIPT / RESEND


def parse_control(body):
    """Parse a RECEIPT or RESEND body into a `Control`.

    Raises:
        DecodeError: the type byte is neither control type, a field is
            truncated, or there are trailing bytes.
    """
    r = Reader(body)
    kind = r.u8()
    if kind not in (T_RECEIPT, T_RESEND):
        raise DecodeError("not a control message")
    sid, seq = r.take(SID_LEN), r.u64()
    r.finish()
    return Control(kind, sid, seq)


# ----- Dispatch helper ----------------------------------------------------------

def message_type(body):
    """The first byte, or None for an empty body. Dispatch on this in receive().

    Args:
        body: the decoded message `bytes`.

    Returns:
        The message type as an `int` (compare with the T_* constants), or
        `None` if `body` is empty. An unrecognised type, like an empty body,
        is silently discarded (§6.2).
    """
    return body[0] if body else None
