"""Byte-level encoding helpers: integers, vectors, base64, UTF-8 and usernames.

What this file is for
---------------------
Every JMessage message body (specification §§6-7) is built out of a handful of
primitive encodings defined in specification §3: big-endian unsigned integers
(`u8`, `u16`, `u32`, `u64`), length-prefixed byte strings (`vec8`, `vec16`) and
UTF-8 strings with a one-byte length (`str8`). This module provides exactly
those, plus the two text encodings that sit around a body: strict base64 for
the JSON envelope (§3, §4.5, Appendix B) and strict UTF-8 for message text
(§7.1, §7.2 step 4).

Where it sits
-------------
It is the bottom layer. Everything else imports it; it imports nothing from
the rest of the kit.

      client.py / your protocol.py
                 |
          messages.py  (message layouts, §§6-7)
                 |
            codec.py   (this file: integers, vectors, base64, UTF-8)

What you should learn from reading it
-------------------------------------
* How the §3 notation maps to Python: `u16(5)` is `b"\\x00\\x05"`;
  `vec16(b"abc")` is `b"\\x00\\x03abc"`; `str8("bob")` is `b"\\x03bob"`.
* Why a parser needs a *bounded* cursor (`Reader`), and why "the message is
  finished" is a check in its own right (`Reader.finish`).
* Why base64 decoding must be canonical, and why text length is limited.

What it deliberately does NOT do
--------------------------------
It knows nothing about message types, transcripts, keys or signatures. It
cannot tell you which bytes to hash or sign; it only turns numbers and strings
into bytes and back. The layouts of the seven message bodies live in
`messages.py`; the decisions about those bytes live in your `protocol.py`.

Specification sections: §3 (encodings, usernames), §4.4-§4.5 (payload limit),
§7.1-§7.2 (text limit and strict UTF-8), Appendix B (strict base64).
"""

import base64
import binascii
import re

# ----- Limits -----------------------------------------------------------------
# Two numeric limits from the specification, shared by the driver, the relay and
# the event validator so that they cannot drift apart.

# §4.4: the server accepts at most 8192 characters of base64 in `payload`.
MAX_PAYLOAD_CHARS = 8192
# §7.1: senders reject text whose UTF-8 encoding exceeds 4096 bytes. The spec
# chose this so that a maximal record still fits under MAX_PAYLOAD_CHARS after
# record overhead and base64 expansion, in either suite.
MAX_TEXT_BYTES = 4096


# ----- Errors -----------------------------------------------------------------

class DecodeError(ValueError):
    """Malformed byte or transport encoding.

    Raised by every parser in this kit when input bytes do not have the
    expected structure: a truncated field, a length prefix that runs past the
    end, trailing bytes, non-canonical base64, or invalid UTF-8.

    It subclasses `ValueError` so that callers who catch `ValueError` also
    catch it. In your protocol code, a `DecodeError` from parsing a peer's
    message means "discard silently" (specification §6.2): it is evidence of a
    malformed message, not of a bug in your client, so it must not escape
    `receive` as an exception.
    """


# ----- Usernames (§3) -----------------------------------------------------------

def username(value):
    """Validate a JMessage username and return it unchanged.

    Args:
        value: the candidate username; any type is accepted so that untrusted
            JSON can be passed in directly.

    Returns:
        The same string, if it is 1 to 32 characters from `[a-z0-9_]`.

    Raises:
        ValueError: if `value` is not a string or does not match §3.

    Why it matters: usernames are interpolated into URL paths
    (`GET /keys/<username>`) and hashed into transcripts as `str8(I)`. A strict
    allowlist means no path separators, no Unicode look-alikes and no
    case-folding ambiguity ("Alice" vs "alice"), so both sides of a handshake
    hash exactly the same bytes for the same user.
    """
    # `re.fullmatch` anchors at both ends; `re.match` would accept "alice/../x".
    if not isinstance(value, str) or re.fullmatch(r"[a-z0-9_]{1,32}", value) is None:
        raise ValueError("username must contain 1–32 lowercase letters, digits, or underscores")
    return value


# ----- Encoding integers and vectors (§3) ---------------------------------------
# These functions build bytes. Each one checks its input and raises rather than
# silently truncating, because a value that does not fit its field would
# otherwise produce a message the peer parses differently from what you meant.

def uint(value, width):
    """Encode a non-negative integer as exactly `width` big-endian bytes.

    Args:
        value: an `int` (not a `bool`) in the range 0 .. 2**(8*width) - 1.
        width: the field size in bytes; one of 1, 2, 4 or 8 (§3's u8..u64).

    Returns:
        `bytes` of length `width`.

    Raises:
        ValueError: if the width is unsupported or the value does not fit.

    `type(value) is not int` rejects `True`/`False`, which Python otherwise
    treats as the integers 1 and 0. A boolean reaching an encoder is almost
    always a bug, and it is better to find it here than in a hex dump.
    """
    if width not in (1, 2, 4, 8) or type(value) is not int or not 0 <= value < 1 << (8 * width):
        raise ValueError("unsigned integer does not fit the requested width")
    # "big" is network byte order, as §3 requires ("integers in big-endian order").
    return value.to_bytes(width, "big")


def u8(value):
    """Encode `value` as a 1-byte unsigned integer (§3 `u8`). See `uint`."""
    return uint(value, 1)


def u16(value):
    """Encode `value` as a 2-byte big-endian unsigned integer (§3 `u16`). See `uint`."""
    return uint(value, 2)


def u32(value):
    """Encode `value` as a 4-byte big-endian unsigned integer (§3 `u32`). See `uint`."""
    return uint(value, 4)


def u64(value):
    """Encode `value` as an 8-byte big-endian unsigned integer (§3 `u64`). See `uint`.

    Sequence numbers in DATA, RECEIPT and RESEND are u64 (§7.1, §7.3).
    """
    return uint(value, 8)


def vec8(data):
    """Encode a byte string with a 1-byte length prefix (§3 `vec8<x>`).

    Args:
        data: `bytes` of length 0..255.

    Returns:
        `u8(len(data)) || data`.

    Raises:
        TypeError: if `data` is not `bytes` (a `str` would need an encoding
            decision, which belongs to the caller; see `str8`).
        ValueError: if `data` is longer than 255 bytes (raised by `u8`).
    """
    if not isinstance(data, bytes):
        raise TypeError("vector contents must be bytes")
    return u8(len(data)) + data


def vec16(data):
    """Encode a byte string with a 2-byte length prefix (§3 `vec16<x>`).

    Args:
        data: `bytes` of length 0..65535.

    Returns:
        `u16(len(data)) || data`. HELLO's `ek_I` and REPLY's `ct` use this
        layout (§6.3, §6.5); an empty field is encoded as `b"\\x00\\x00"`.

    Raises:
        TypeError: if `data` is not `bytes`.
        ValueError: if `data` is longer than 65535 bytes.
    """
    if not isinstance(data, bytes):
        raise TypeError("vector contents must be bytes")
    return u16(len(data)) + data


def str8(text):
    """Encode a string as `vec8` of its UTF-8 bytes (§3 `str8(s)`).

    Args:
        text: a `str` whose UTF-8 encoding is at most 255 bytes.

    Returns:
        `u8(len(utf8)) || utf8`. The transcript hashes in §6.5-§6.7 include
        `str8(I) || str8(R)`; the length prefix is what stops the pair
        ("ab", "c") from hashing the same as ("a", "bc").

    Raises:
        UnicodeError: if `text` contains lone surrogates.
        ValueError: if the encoding is longer than 255 bytes.
    """
    return vec8(text.encode("utf-8", errors="strict"))


# ----- Base64 for the JSON envelope (§3, §4.5, Appendix B) ----------------------

def encode_base64(data):
    """Encode bytes as standard base64 with padding, returned as `str`.

    Args:
        data: `bytes` (for example, a complete message body).

    Returns:
        The base64 text that goes in the envelope's `payload` field (§4.4).
        This encoder always produces the one canonical form for its input.
    """
    return base64.b64encode(data).decode("ascii")


def decode_base64(text, *, max_chars=MAX_PAYLOAD_CHARS):
    """Strictly decode standard base64 text and return the bytes.

    Args:
        text: the base64 `str` from a JSON field. Any other type is rejected.
        max_chars: upper bound on `len(text)`, checked before any decoding work.
            Defaults to the §4.4 payload limit; key lookups pass 44, the exact
            base64 length of a 32-byte key.

    Returns:
        The decoded `bytes`.

    Raises:
        DecodeError: if `text` is not a `str`, is too long, contains anything
            outside the base64 alphabet (including whitespace or newlines), has
            missing or incorrect padding, or is not the canonical encoding of
            the bytes it decodes to.

    Why canonical (Appendix B): standard base64 has more than one text form
    for some inputs. "YR==" and "YQ==" both decode to b"a", because the low
    bits of the last character are ignored by lenient decoders. If two
    different strings are accepted for the same bytes, then two components
    that compare or log the text form can disagree about whether two messages
    are "the same". The rule here is simple and testable: decode, re-encode,
    and require the result to equal the input exactly.

    Why not just call `base64.b64decode(text)`: without `validate=True` it
    silently skips characters outside the alphabet (including newlines), and
    even with it, it accepts non-canonical trailing bits. Both checks are
    needed.
    """
    # Check type and size first so that an oversized or non-string value costs
    # nothing to reject.
    if not isinstance(text, str) or len(text) > max_chars:
        raise DecodeError("invalid base64 type or length")
    try:
        # .encode("ascii") rejects non-ASCII characters such as "é";
        # validate=True rejects characters outside the base64 alphabet.
        raw = base64.b64decode(text.encode("ascii"), validate=True)
    except (ValueError, UnicodeError, binascii.Error) as exc:
        raise DecodeError("invalid base64") from exc
    # Round-trip check: the only accepted text for `raw` is its canonical form.
    if encode_base64(raw) != text:
        raise DecodeError("noncanonical base64")
    return raw


# ----- Message text: strict UTF-8 with a size limit (§7.1, §7.2) ----------------

def encode_text(text):
    """Encode message text as UTF-8 and enforce the §7.1 size limit.

    Args:
        text: the user's message as a `str`. Empty text is allowed (§7.1).

    Returns:
        The UTF-8 bytes, exactly as Python encodes them: no normalization, no
        byte-order mark, no added newline (§7.1).

    Raises:
        UnicodeError: if `text` contains lone surrogates (not valid UTF-8).
        ValueError: if the encoding is longer than MAX_TEXT_BYTES.

    §7.1 says to reject oversized text "before allocating a sequence number".
    Calling this before touching any session state is the easy way to obey
    that: if it raises, nothing has changed.
    """
    raw = text.encode("utf-8", errors="strict")
    if len(raw) > MAX_TEXT_BYTES:
        raise ValueError("text exceeds 4096 UTF-8 bytes")
    return raw


def decode_text(raw):
    """Decode authenticated plaintext bytes as strict UTF-8 text (§7.2 step 4).

    Args:
        raw: `bytes` recovered from a record that has already passed
            authentication.

    Returns:
        The decoded `str`.

    Raises:
        DecodeError: if `raw` is longer than MAX_TEXT_BYTES or is not valid
            UTF-8 (overlong forms, lone surrogates and truncated sequences are
            all rejected by Python's strict decoder).

    §7.2 step 4 treats a failure here as a local "application-format error":
    the record was authentic, so its sequence number is still consumed and its
    RECEIPT still sent, but the bytes are not displayed as text. That is why
    this raises `DecodeError` rather than returning a replacement string.
    """
    if len(raw) > MAX_TEXT_BYTES:
        raise DecodeError("text exceeds 4096 UTF-8 bytes")
    try:
        return raw.decode("utf-8", errors="strict")
    except UnicodeError as exc:
        raise DecodeError("invalid UTF-8") from exc


# ----- Parsing: a bounds-checked cursor (§3) ------------------------------------

class Reader:
    """A bounded, forward-only cursor over a byte string.

    Use it to parse a structure field by field, then call `finish()`:

        r = Reader(body)
        kind = r.u8()
        sid = r.take(16)
        ek = r.vec16()
        r.finish()          # anything left over is a structural error (§3)

    Why bounds-checked: Python slicing never fails. `body[10:42]` on a 20-byte
    input quietly returns 10 bytes, and a parser built on raw slices then
    carries a short "32-byte key" into the cryptography. Every read here
    checks that the requested bytes are actually present and raises
    `DecodeError` if not, so a truncated or lying length prefix is caught at
    the field where it occurs (§3: "Truncated fields, inconsistent length
    prefixes, and trailing bytes are structural errors").

    Why `finish()` is separate: §3 says "Parsing MUST consume the entire body."
    Rejecting trailing bytes means each message has exactly one encoding. If
    parsers ignored extra bytes, two different byte strings would parse to the
    same message, while a transcript hash over the raw bytes would treat them
    as different.
    """

    def __init__(self, data):
        """Start a cursor at offset 0 of `data`.

        Args:
            data: the `bytes` to parse.

        Raises:
            TypeError: if `data` is not `bytes` (a `str` or `bytearray` is a
                caller bug: `bytearray` is mutable, so it could change while
                being parsed).
        """
        if not isinstance(data, bytes):
            raise TypeError("input must be bytes")
        self._data = data
        self._offset = 0

    @property
    def remaining(self):
        """The number of unread bytes, as an `int`."""
        return len(self._data) - self._offset

    def take(self, count):
        """Read exactly `count` bytes and advance the cursor.

        Args:
            count: a non-negative `int`.

        Returns:
            `bytes` of length exactly `count`.

        Raises:
            DecodeError: if `count` is not a non-negative `int`, or fewer than
                `count` bytes remain. The cursor does not move on failure.

        This is the single place where bounds are enforced; every other read
        method is built on it.
        """
        if type(count) is not int or count < 0 or count > self.remaining:
            raise DecodeError("truncated field or invalid length")
        start = self._offset
        self._offset += count
        return self._data[start:self._offset]

    def uint(self, width):
        """Read a big-endian unsigned integer of `width` bytes (1, 2, 4 or 8).

        Returns:
            The value as an `int`.

        Raises:
            ValueError: if `width` is unsupported (a programming error).
            DecodeError: if fewer than `width` bytes remain.
        """
        if width not in (1, 2, 4, 8):
            raise ValueError("unsupported integer width")
        return int.from_bytes(self.take(width), "big")

    def u8(self):
        """Read a 1-byte unsigned integer (§3 `u8`)."""
        return self.uint(1)

    def u16(self):
        """Read a 2-byte big-endian unsigned integer (§3 `u16`)."""
        return self.uint(2)

    def u32(self):
        """Read a 4-byte big-endian unsigned integer (§3 `u32`)."""
        return self.uint(4)

    def u64(self):
        """Read an 8-byte big-endian unsigned integer (§3 `u64`)."""
        return self.uint(8)

    def vec8(self):
        """Read a `vec8<x>`: a 1-byte length, then that many bytes.

        Raises:
            DecodeError: if the length prefix claims more bytes than remain.
        """
        return self.take(self.u8())

    def vec16(self):
        """Read a `vec16<x>`: a 2-byte length, then that many bytes.

        Raises:
            DecodeError: if the length prefix claims more bytes than remain.

        Note (§3): this checks only that the field is *present*. Whether its
        length makes sense for its meaning (for example, a 1184-byte `ek_I`)
        is a separate validation step that belongs to the protocol logic.
        """
        return self.take(self.u16())

    def str8(self):
        """Read a `str8(s)`: a `vec8` decoded as strict UTF-8.

        Returns:
            The decoded `str`.

        Raises:
            DecodeError: if the field is truncated or not valid UTF-8.
        """
        try:
            return self.vec8().decode("utf-8", errors="strict")
        except UnicodeError as exc:
            raise DecodeError("invalid UTF-8 string") from exc

    def rest(self):
        """Read and return all remaining bytes (possibly none).

        Use this only where the message format says "all remaining bytes",
        as DATA does for `protected` (§3, §7.1). After `rest()`, `finish()`
        trivially succeeds.
        """
        return self.take(self.remaining)

    def finish(self):
        """Assert that the whole input has been consumed.

        Raises:
            DecodeError: if any bytes remain (§3: trailing bytes are a
                structural error, and the message must be discarded).
        """
        if self.remaining:
            raise DecodeError("trailing bytes")
