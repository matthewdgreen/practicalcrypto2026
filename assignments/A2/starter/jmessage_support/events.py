"""Validation and display of the events your `Client` emits (handout §3).

What this file is for
---------------------
Your `Client` never talks to the network or the terminal directly. It reports
everything it wants done, or wants the user to know, by calling
`emit(event)` with a small dictionary. The handout §3 table defines the six
event types. This module checks that an event has exactly the shape the table
promises (`validate_event`) and chooses which fields are safe to print
(`display_event`).

Where it sits
-------------

      your Client --emit(event)--> Runtime.emit / Network.emit
                                        |
                                 validate_event  (this file)
                                        |
                     "send" -> transport    other -> display_event -> output

Both the live driver (`runtime.py`) and the in-memory test network
(`testing.py`) call `validate_event` first, so a malformed event fails the
same way in tests as it does live.

What you should learn from reading it
-------------------------------------
* The exact contract of each event type: which keys, which Python types, and
  which ranges (a 16-byte `sid`, a u64 `seq`, a suite of 1 or 2).
* Why the display path uses an allowlist: your events may carry extra keys
  while you debug, and nothing outside the allowlist ever reaches the screen.

What it deliberately does NOT do
--------------------------------
It does not decide *when* to emit anything, and it does not check that an
event is truthful (for example, that a "message" event's text was really
authenticated). Those are protocol decisions in your `protocol.py`.

Specification/handout sections: handout §3 (event table); spec §4.4 (payload
limit, applied to "send" bodies); spec §7.1 (text limit, applied to "message").
"""

from .codec import MAX_PAYLOAD_CHARS, encode_base64, encode_text, username


# ----- Validation ---------------------------------------------------------------

def validate_event(event):
    """Check that `event` matches one row of the handout §3 event table.

    Args:
        event: the `dict` your `Client` passed to `emit`.

    Returns:
        None. Validation either passes silently or raises.

    Raises:
        ValueError: if `event` is not a dict, has an unknown "type", or any
            required field is missing, of the wrong type, or out of range.
            Raised *before* anything is sent or displayed, so a malformed
            event has no side effects.

    The checks, by type:
        send          "to" is a valid username; "body" is nonempty `bytes`
                      whose base64 fits the §4.4 payload limit.
        established   "peer" username; 16-byte "sid"; "suite" is 1 or 2.
        message       "peer"; "sid"; u64 "seq"; "text" is a `str` within
                      4096 UTF-8 bytes (§7.1).
        receipt       "peer"; "sid"; u64 "seq".
        warning/error "peer" is a username or None; "message" is a `str`.

    Why check sizes here as well as in the transport: catching an oversized
    body at the moment you emit it gives a traceback pointing into your own
    code, rather than an HTTP 413 from the server later.
    """
    if not isinstance(event, dict):
        raise ValueError("emit expects an event dictionary")
    kind = event.get("type")
    if kind == "send":
        username(event.get("to"))
        body = event.get("body")
        # `not body` rejects b"": every message body has at least a type byte (§3).
        if (not isinstance(body, bytes) or not body
                or len(encode_base64(body)) > MAX_PAYLOAD_CHARS):
            raise ValueError("send event requires a nonempty binary body within the payload limit")
    elif kind in ("established", "message", "receipt"):
        username(event.get("peer"))
        if not isinstance(event.get("sid"), bytes) or len(event["sid"]) != 16:
            raise ValueError("event sid must be 16 bytes")
        if kind == "established":
            # `type(...) is not int` also rejects True/False (see codec.uint).
            if type(event.get("suite")) is not int or event["suite"] not in (1, 2):
                raise ValueError("event suite must be 1 or 2")
        else:
            if type(event.get("seq")) is not int or not 0 <= event["seq"] < 2**64:
                raise ValueError("event seq must be a u64")
        if kind == "message":
            if not isinstance(event.get("text"), str):
                raise ValueError("message event requires text")
            # Reuses the sender-side limit: a "message" event may only carry
            # text that could legitimately have been sent (§7.1, §7.2 step 4).
            encode_text(event["text"])
    elif kind in ("warning", "error"):
        # handout §3: "Error events for an unknown affected peer may use
        # "peer": None".
        if event.get("peer") is not None:
            username(event["peer"])
        if not isinstance(event.get("message"), str):
            raise ValueError("warning/error event requires a message string")
    else:
        raise ValueError(f"unknown event type: {kind!r}")


# ----- Display ------------------------------------------------------------------

def display_event(event):
    """Allowlist fields for display; never print extra student internal state.

    Args:
        event: an already validated, non-"send" event `dict`.

    Returns:
        A new `dict` containing only the allowlisted keys for that event type,
        with any `bytes` value (such as `sid`) converted to lowercase hex so it
        can be printed as JSON.

    Raises:
        KeyError: if called with a "send" event, which is never displayed
            (raw protocol bodies are not shown to the user; README §4).

    Why an allowlist and not a blocklist: if you put a key or a debug field in
    an event while developing ("private_key": ...), a blocklist would need to
    know that name in advance. An allowlist shows only what the handout §3
    table defines, whatever else is present.
    """
    fields = {
        "established": ("type", "peer", "sid", "suite"),
        "message": ("type", "peer", "sid", "seq", "text"),
        "receipt": ("type", "peer", "sid", "seq"),
        "warning": ("type", "peer", "message"),
        "error": ("type", "peer", "message"),
    }
    return {key: event.get(key).hex() if isinstance(event.get(key), bytes) else event.get(key)
            for key in fields[event["type"]]}
