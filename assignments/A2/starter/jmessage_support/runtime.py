"""Single-threaded bridge from Client callbacks to ordered HTTP operations.

What this file is for
---------------------
Your `Client` is a pure state machine: it takes inputs (`receive`,
`send_text`, ...) and produces outputs by calling `emit(event)`. Something has
to connect it to the real world. `Runtime` does that: it is the `emit` your
client calls, it turns "send" events into HTTP requests, it prints everything
else, and it feeds received mailbox entries back into `Client.receive` in
order.

Where it sits
-------------

      user / UI                                    server
         |                                           ^
         v                                           |
      client.py  --dispatch-->  Runtime.call(core.method, ...)
                                   |        ^
                                   v        | emit(event)
                               your Client (protocol.py)
                                   |
             Runtime.emit:  "send"  --> API.send (transport.py)
                            others  --> output(display_event(...))
      Runtime.poll:  API.receive --> parse_envelope --> Client.receive (in order)

What you should learn from reading it
-------------------------------------
* Why every protocol call happens on one thread, in a fixed order. Your
  `Client` holds counters and pending handshakes in ordinary Python objects;
  two threads calling into it at once could, for example, both read
  `send_seq = 5` and both send a record with sequence number 5. Running all
  calls on the caller's thread, one after another, removes that whole class
  of bug without any locks.
* How a transport failure is handled: it is latched, the driver stops, and
  your optional `transport_failed` hook runs only after your code has
  returned (§4.6, Appendix B).
* Why a missing peer key is reported and survived, not treated as fatal.

What it deliberately does NOT do
--------------------------------
It never retries a send, never reorders or deduplicates messages, never
resets your counters, and never looks inside a message body. Whatever your
client must do after a failure is your client's decision; this module only
guarantees that it stops sending.

Specification/handout sections: handout §3 (emit contract; transport_failed);
spec §4.5 (ordered, destructive receive), §4.6 (serialized sends; uncertain
delivery; never reset counters), Appendix B (transport failures).
"""

from .events import display_event, validate_event
from .transport import PeerKeyUnavailable, TransportError, parse_envelope


class Runtime:
    """Connects one `Client` to one `API` and one output function.

    Attributes:
        api: the `transport.API` used for HTTP.
        account: this client's username; envelopes addressed elsewhere are
            dropped before they reach the client.
        output: a callable that receives display dictionaries (JSON-printed by
            `client.py`; a UI would render them instead).
        client: your `Client`, set by the driver after construction (the
            `Client` needs `runtime.emit` to be constructed, so the two are
            wired up in two steps).
        stopped: True once a transport failure has occurred. No further calls
            are made after that.

    Usage pattern for a custom UI (README §4): build a `Runtime` with your own
    `output`, attach your `Client`, then call `runtime.call(...)` and
    `runtime.poll()` from a single protocol thread.
    """

    def __init__(self, api, account, output):
        """Create a runtime; see the class docstring for the arguments."""
        self.api = api
        self.account = account
        self.output = output
        self.client = None
        self.stopped = False
        # (affected peer or None, TransportError) from the first failure. Latched:
        # once set it is never cleared, so the driver cannot "forget" a failure.
        self._failure = None

    # ----- The emit callback your Client calls -----

    def emit(self, event):
        """Handle one event from the `Client` (handout §3).

        Args:
            event: an event `dict` from the handout §3 table.

        Returns:
            None. For a "send" event, returning normally means the server
            accepted the message (handout §3: "A successful emit of a send
            event means the transport accepted the send").

        Raises:
            ValueError: if the event is malformed (from `validate_event`).
            TransportError: if this is a "send" and the driver has already
                failed, or the send itself fails. The failure is recorded
                before re-raising, so the driver still stops even if your code
                catches the exception.

        Sends happen synchronously, inside your call to `emit`. That is how
        §4.6's ordering rule is met: when `emit` returns for a FINISH, the
        server has stored it, so any DATA you emit afterwards is stored after
        it. It also means `emit` never calls back into your client.
        """
        validate_event(event)
        if event["type"] != "send":
            self.output(display_event(event))
            return
        if self.stopped or self._failure is not None:
            # After one failure, refuse all further sends. Later records could
            # otherwise reach the peer while an earlier one is missing.
            raise TransportError("driver has stopped sending after a transport failure")
        try:
            message_id = self.api.send(event["to"], event["body"])
        except TransportError as exc:
            # Record first, then re-raise: if your code swallows this exception,
            # `call` still sees `_failure` and stops the driver.
            self._failure = (event["to"], exc)
            raise
        self.output({"type": "sent", "to": event["to"], "id": message_id})

    # ----- Calling into the Client -----

    def call(self, method, *args, peer=None):
        """Run `method(*args)` on this thread and apply the failure policy.

        Args:
            method: a bound method, usually of the `Client` (for example
                `core.send_text`) or of the `API` (`api.receive`).
            *args: positional arguments for `method`.
            peer: the username this call concerns, if any. It is used to label
                error output and is passed to `transport_failed` if this call
                hits the first transport failure.

        Returns:
            Whatever `method` returned, or None if it raised
            `PeerKeyUnavailable`.

        Raises:
            TransportError: if the driver was already stopped, or a transport
                failure happened during this call (whether or not `method`
                caught it). The driver's main loop exits on it.
            Any other exception from `method` propagates unchanged, with its
            traceback, so you can debug your code. Note README §2: an
            unexpected exception during `poll` loses the rest of that batch.

        Order of events on a transport failure:
            1. the failing `emit` records `_failure` and raises;
            2. your method returns or raises (either way, it has finished);
            3. `stopped` is set;
            4. `client.transport_failed(affected)` is called, outside your
               original method, so the hook never runs half-way through a
               state change;
            5. the original `TransportError` is re-raised.
        """
        if self.stopped:
            raise TransportError("driver has stopped; restart before continuing")
        try:
            result = method(*args)
        except PeerKeyUnavailable as exc:
            # A missing or malformed directory key is a per-peer problem, not a
            # transport failure: another user must not be able to stop this
            # driver by messaging without a published key. Report and continue.
            self.output({"type": "error", "peer": peer, "message": str(exc)})
            result = None
        except TransportError as exc:
            # A failure raised directly by `method` (for example `api.receive`).
            # Keep the first failure if `emit` already recorded one.
            if self._failure is None:
                self._failure = (peer, exc)
            result = None
        if self._failure is not None:
            affected, error = self._failure
            self.stopped = True
            # Invoke the optional hook only after the protocol call has unwound.
            if self.client is not None:
                try:
                    self.client.transport_failed(affected)
                except Exception:
                    self.output({"type": "warning", "peer": affected,
                                 "message": "transport_failed hook raised; driver is stopping"})
            raise error
        return result

    # ----- Receiving -----

    def poll(self):
        """Fetch one mailbox batch and feed it to the `Client`, in order.

        Steps:
            1. GET /messages through `call`, with `peer=None`. If this fails,
               the batch may have been deleted on the server without reaching
               us, so every session is potentially affected and the hook gets
               `transport_failed(None)` (handout §3).
            2. For each entry, in server order (§4.5, §4.6 "process each
               received batch in order"): validate the envelope; skip it if
               malformed or addressed to another account; otherwise call
               `client.receive(sender, recipient, body)`.
            3. Call `client.check_timeouts()` once, so pending handshakes can
               expire even when no message for them arrives (Appendix B).

        Raises:
            TransportError: as for `call`.
            Any unexpected exception from your `receive`. The remaining
            entries of the batch are then lost, because the server already
            deleted them (README §2).
        """
        batch = self.call(self.api.receive)
        for item in batch:
            try:
                envelope = parse_envelope(item)
            except (ValueError, KeyError, TypeError):
                continue  # Untrusted malformed envelope, not a protocol callback.
            # Defence in depth: the server should only return our own mail, but
            # it is untrusted. Your Client must still check `recipient` itself
            # (§6.4, §6.9) rather than rely on this filter: other callers of
            # `receive`, such as tests, do not go through it.
            if envelope.recipient != self.account:
                continue
            self.call(self.client.receive, envelope.sender, envelope.recipient,
                      envelope.body, peer=envelope.sender)
        self.call(self.client.check_timeouts)
