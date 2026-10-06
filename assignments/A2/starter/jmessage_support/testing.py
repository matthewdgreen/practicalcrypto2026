"""Ordered in-memory transport for normal client interoperability checks.

What this file is for
---------------------
A fake network and a fake clock, so that you can run two (or more) `Client`
objects inside one Python process and watch them talk, without HTTP, threads
or real time. The public checks in `tests/student_checks.py` are built on it,
and you can use it for your own experiments (README §3).

Where it sits
-------------

      Network.attach("alice", Client)       Network.attach("bob", Client)
              |  emit(send) -> queue.append        ^
              v                                    |  pump(): popleft,
           alice Client                        bob Client.receive(...)
                        \\                    /
                         Network.queue (FIFO)  +  Network.wire (full log)
                         Network.clock (fake)  +  Network.events[name]

    It plays the role that `Runtime` + `API` + the server play in the live
    driver, with the same `emit` contract and the same `PeerKeyUnavailable`.

What you should learn from reading it
-------------------------------------
* That your `Client` can be tested as a pure state machine: put messages in,
  look at the events that come out.
* Why delivery is queued, not immediate. In `emit`, a send is only appended
  to a queue; delivery happens later in `pump()`. If `emit` delivered
  immediately, bob's `receive` would run *inside* alice's `emit` call, while
  alice was half-way through updating her own state, and a reply from bob
  could re-enter alice before her first call had returned. The live driver
  never does that (handout §3: "The callback does not re-enter the client"),
  so the test network does not either.
* How an injected clock makes time-dependent behaviour (handshake expiry,
  Appendix B) testable without sleeping.

What it deliberately does NOT do
--------------------------------
It contains no protocol implementation and no cryptographic test vectors. It
delivers every message, once, in order; it does not drop, duplicate, reorder
or modify anything, so it says nothing about how your client behaves on a
hostile network. Passing checks built on it with two copies of your own code
shows self-consistency, not conformance (README §3).

Specification/handout sections: handout §3 (Client constructor, emit, now);
spec §4.6 (ordered delivery), §5 (authenticated fixture keys), Appendix B
(expiry via `advance`).
"""

from collections import deque
from copy import deepcopy

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .codec import username
from .events import validate_event
from .transport import PeerKeyUnavailable


# ----- A controllable clock ---------------------------------------------------

class Clock:
    """A fake monotonic clock: call it to read the time, `advance` to move it.

    Pass an instance as the `now` argument of your `Client` (the Network does
    this for you). It starts at 0.0 seconds and only moves when told to.
    """

    def __init__(self):
        """Start the clock at 0.0 seconds."""
        self.value = 0.0

    def __call__(self):
        """Return the current fake time in seconds (a `float`)."""
        return self.value

    def advance(self, seconds):
        """Move the clock forward by `seconds`.

        Raises:
            ValueError: if `seconds` is negative. A monotonic clock never goes
                backwards (Appendix B asks for a monotonic clock for expiry).
        """
        if seconds < 0:
            raise ValueError("clock cannot move backwards")
        self.value += seconds


# ----- The in-memory network ----------------------------------------------------

class Network:
    """Callbacks enqueue only; pump() delivers later, without reentrancy.

    The fixture authenticates its fixed account keys. It supplies no client
    protocol implementation and no cryptographic test vectors.

    Typical use:

        net = Network()                       # accounts "alice" and "bob"
        alice = net.attach("alice", Client)
        bob = net.attach("bob", Client)
        alice.start_handshake("bob")          # alice emits a HELLO (queued)
        net.pump()                            # deliver until the queue is empty
        net.matching("bob", "established")    # inspect the events bob emitted

    Attributes:
        clock: the shared `Clock` passed to every attached client as `now`.
        keys: username -> Ed25519 private key object, generated fresh for each
            Network. These are the "authenticated fixture keys" of spec §5:
            `lookup_key` returns exactly these public keys.
        clients: username -> attached client object.
        events: username -> list of every event that client emitted (deep
            copies, so later changes to your objects do not rewrite history).
        queue: FIFO of (sender, recipient, body) waiting for delivery.
        wire: every (sender, recipient, body) ever sent, in order; useful for
            looking at the bytes your client produced.
        max_pending: cap on the queue length, to catch runaway senders.
    """

    def __init__(self, names=("alice", "bob"), *, max_pending=1024):
        """Create accounts for `names`, each with a fresh Ed25519 key.

        Args:
            names: usernames to create (validated).
            max_pending: maximum queue length before `emit` raises.
        """
        self.clock = Clock()
        self.keys = {username(name): Ed25519PrivateKey.generate() for name in names}
        self.clients = {}
        self.events = {name: [] for name in names}
        self.queue = deque()
        self.wire = []
        self.max_pending = max_pending
        self._delivering = False

    def lookup_key(self, peer):
        """The `lookup_peer_key` callback given to every client.

        Args:
            peer: a username.

        Returns:
            That account's raw 32-byte Ed25519 public key.

        Raises:
            PeerKeyUnavailable: if `peer` is not one of this Network's accounts.
        """
        # Same exception as the live driver, so student code handles both alike.
        if peer not in self.keys:
            raise PeerKeyUnavailable(f"no identity key published for {peer}")
        return self.keys[peer].public_key().public_bytes_raw()

    def attach(self, name, factory, *, jm1_only=False):
        """Construct a client for account `name` and wire it to this network.

        Args:
            name: one of the Network's usernames.
            factory: a class or callable with the handout §3 constructor
                signature, normally your `protocol.Client`.
            jm1_only: passed through to the constructor (§6.1 compatibility
                option).

        Returns:
            The constructed client.

        Raises:
            ValueError: if a client is already attached under `name`.
        """
        if name in self.clients:
            raise ValueError("client already attached")
        def emit(event):
            """This client's `emit`: validate, record, and queue any send.

            Raises ValueError for a malformed event or unknown recipient, and
            RuntimeError if the queue is full. Never calls another client.
            """
            validate_event(event)
            saved = deepcopy(event)
            self.events[name].append(saved)
            if event["type"] == "send":
                peer = event["to"]
                if peer not in self.keys:
                    raise ValueError("unknown fixture peer")
                if len(self.queue) >= self.max_pending:
                    raise RuntimeError("pending-message limit exceeded")
                # The envelope's sender is the attaching account, never a value
                # from the event: as on the real server, "from" cannot be forged
                # by the client (§4.4).
                envelope = (name, peer, event["body"])
                self.queue.append(envelope)
                self.wire.append(envelope)
        client = factory(name, self.keys[name].private_bytes_raw(), self.lookup_key,
                         emit, self.clock, jm1_only=jm1_only)
        self.clients[name] = client
        return client

    def pump(self, *, limit=1000):
        """Deliver queued messages in FIFO order until the queue is empty.

        Messages that clients emit while receiving are appended to the same
        queue and delivered in turn, so one `pump()` runs a whole exchange
        (HELLO, REPLY, FINISH, DATA, RECEIPT ...) to completion.

        Args:
            limit: maximum deliveries in this call.

        Returns:
            The number of messages delivered (`int`).

        Raises:
            RuntimeError: if called from inside a delivery (re-entrancy), or if
                more than `limit` messages are delivered. The second usually
                means two clients are answering each other forever, for
                example by acknowledging acknowledgements, which §7.3 forbids.
            Any exception raised by a client's `receive` propagates.
        """
        if self._delivering:
            raise RuntimeError("transport cannot deliver reentrantly")
        self._delivering = True
        delivered = 0
        try:
            while self.queue:
                if delivered >= limit:
                    raise RuntimeError("delivery limit exceeded; check for a control-message loop")
                sender, peer, body = self.queue.popleft()
                self.clients[peer].receive(sender, peer, body)
                delivered += 1
        finally:
            self._delivering = False
        return delivered

    def advance(self, seconds):
        """Advance the shared clock, then call every client's `check_timeouts()`.

        This mirrors the live driver, which calls `check_timeouts` after each
        poll (Appendix B handshake expiry), but takes no real time.
        """
        self.clock.advance(seconds)
        for client in self.clients.values():
            client.check_timeouts()

    def matching(self, name, kind):
        """Return the events of type `kind` that client `name` has emitted, in order."""
        return [event for event in self.events[name] if event["type"] == kind]
