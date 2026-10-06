"""Student implementation of specification §§5-7. Supplied methods are stubs.

What this file is for
---------------------
This is your protocol core: the `Client` class whose interface is fixed by
handout §3. Everything cryptographic in JMessage happens here: fingerprints,
the HELLO/REPLY/FINISH handshake with suite negotiation and REJECT, the key
schedule, record protection for both suites, receipts and resend requests.

Where it sits
-------------

      client.py / your UI          tests (testing.Network)
              \\                       /
               Runtime.call(...)  or direct calls
                         |
                         v
      +---------------- Client (this file) ----------------+
      |  inputs:  start_handshake, send_text, receive,     |
      |           fingerprint, check_timeouts, ...         |
      |  outputs: self.emit({"type": "send" | "established"|
      |           | "message" | "receipt" | "warning"      |
      |           | "error", ...})                         |
      +----------------------------------------------------+
           |  uses                          |  uses
      jmessage_support/messages.py      cryptography (library primitives)
      jmessage_support/codec.py         padding.py (your Part 0 functions)

    You never touch HTTP, JSON, base64, threads or the terminal: the driver
    does that. You receive decoded bytes and emit events.

How to use this skeleton
------------------------
The sections below are in the order we suggest you build them. Each one says
which spec sections it implements, what goes in and comes out, what must be
true afterwards, and which row of the "What counts as explained" table in
AGENTS.md it belongs to (that table lists what you should be able to say
about each review-critical region before, or instead of, asking an agent to
write it). Every method still raises NotImplementedError or does nothing;
replacing those bodies, and adding whatever helper functions, classes and
state you need, is the assignment.

    1. State                    __init__                        §6.9
    2. Fingerprint              fingerprint                     §5
    3. Handshake as initiator   start_handshake (+ REPLY,       §§6.3, 6.5, 6.6, 6.8
                                FINISH, REJECT in receive)
    4. Handshake as responder   receive (HELLO, FINISH)         §§6.2, 6.4, 6.5, 6.6
    5. Key schedule             (your helpers)                  §6.7
    6. Records                  send_text (+ DATA in receive)   §§6.9, 7.1, 7.2
    7. Control messages         (RECEIPT, RESEND in receive)    §7.3
    8. Timeouts and robustness  check_timeouts, reset_peer_trust, Appendix B
                                transport_failed

A suggested route: get sections 1-6 working for JM1 only (`--jm1-only`, and
`run_checks.py review_eligible`), then add JM2, then section 7, then 8.

Rules that apply everywhere
---------------------------
* Malformed or unexpected peer input is discarded or reported as the spec
  says; it must never escape `receive` as an exception (handout §3). The
  supplied parsers raise `DecodeError` for structural errors; catch it.
* Emit events in processing order, and finish cryptographic processing before
  emitting an event that exposes plaintext (handout §3).
* `emit` of a "send" event returns only after the transport accepted it, and
  raises if delivery failed or is uncertain (handout §3, spec §4.6). It never
  calls back into your Client.
* Use library implementations of every primitive and a CSPRNG for keys, sids
  and IVs (spec §2). Do not implement ML-KEM, X25519, Ed25519, AES, HMAC or
  HKDF yourself (handout §3).
* Use the constants and encoders in `jmessage_support.messages` rather than
  writing magic numbers.
"""


class Client:
    """The handout §3 protocol-core interface. One instance per local account.

    The driver constructs exactly one `Client` and calls it from one thread,
    one call at a time, so you need no locks (see jmessage_support/runtime.py).
    """

    # ----- 1. State (§6.9) ---------------------------------------------------
    # Core zone (AGENTS.md, "Core"): you design the per-sid state yourself.
    #
    # Spec §6.9 says what a session holds: the peer, the role (I or R), the
    # suite, the record keys, send_seq, recv_seq and the handshake bytes; and
    # what pending state additionally retains: the ephemeral private keys it
    # still needs, the peer identity key pinned for this handshake (§5), the
    # start time, and whether the single fallback retry has been used (§6.8).
    # It also requires you to remember retired session identifiers for the
    # life of the process (§6.9), to know the most recently established
    # session per peer, and to queue text for a peer that has no session yet.
    # The state table in §6.9 lists the states and the events each accepts.

    def __init__(self, username, identity_private_key, lookup_peer_key, emit, now,
                 *, jm1_only=False):
        """Store the handout §3 constructor arguments and create empty state.

        Args:
            username: this client's own username (`str`). Envelopes whose
                recipient is not this name are discarded (§6.4, §6.9).
            identity_private_key: the raw 32-byte Ed25519 private key idSK
                (§5). Keep the identity key fixed for the life of the client.
            lookup_peer_key: a callable `lookup_peer_key(name) -> bytes`
                returning a raw 32-byte Ed25519 public key. It raises
                `jmessage_support.transport.PeerKeyUnavailable` (a
                `LookupError`) if the user has no usable key; report an error
                and do not proceed with that handshake (§5). It may also raise
                `TransportError`, which you should let propagate.
            emit: the synchronous event callback (handout §3 table).
            now: a callable returning monotonic seconds (`float`). Use it, not
                `time.time()`, for handshake start times (Appendix B); the
                tests substitute a fake clock.
            jm1_only: the local compatibility-test option of §6.1. When True,
                handshakes this client *initiates* offer only JM1. It does not
                change what this client accepts as a responder (§6.1).

        Afterwards:
            No messages have been sent and no events emitted. All your
            per-session and per-peer state exists and is empty.
        """
        self.username = username
        self.identity_private_key = identity_private_key
        self.lookup_peer_key = lookup_peer_key
        self.emit = emit
        self.now = now
        self.jm1_only = jm1_only
        # TODO: Design your handshake and session state. See specification §6.9.

    # ----- 2. Fingerprint (§5) -----------------------------------------------
    # Core zone (AGENTS.md, "Core"). A good first function: it exercises
    # hashing, byte concatenation and formatting, and you can check it against
    # the course server's `echo` fingerprint in handout §3 and the values in
    # spec Appendix A.

    def fingerprint(self, peer=None):
        """Return the §5 display string for self, or a named peer.

        Implements spec §5: the fingerprint of a user is derived from that
        user's raw 32-byte public key idPK and shown as ten uppercase hex
        pairs separated by single spaces.

        Args:
            peer: a username (`str`), or None for this client's own key.

        Returns:
            The formatted fingerprint `str`, for example
            "93 AF 70 ED 10 00 82 91 02 74".

        Raises:
            PeerKeyUnavailable: may propagate from `lookup_peer_key` for a peer
                with no usable key; the driver reports it. (This is the one
                method that returns a value instead of only emitting events.)

        Afterwards:
            No state has changed and nothing has been emitted. Displaying a
            fingerprint does not authenticate it (§5).
        """
        raise NotImplementedError("Implement fingerprint in protocol.py")

    # ----- 3. Handshake as initiator (§§6.3, 6.5, 6.6, 6.8) ------------------
    # Review-critical (AGENTS.md "What counts as explained": rows "Transcript &
    # signatures" and "State machine").
    #
    # The initiator's side of the handshake spans several inputs:
    #   start_handshake       build and send HELLO; enter pending-reply (§6.3)
    #   REPLY via receive     the five numbered checks and actions of §6.5,
    #                         ending in FINISH (§6.6) and establishment
    #   REJECT via receive    verify, then act on the reason (§6.8)
    # Before writing any of it, be able to say: which bytes TH_R and TH_I
    # cover and in what order; which copy of HELLO the initiator hashes (§6.5
    # step 2 says); which key verifies sig_R and where it came from (§5); and
    # what each failure does (abort for a REPLY, ignore for a bad REJECT
    # signature, §6.8).

    def start_handshake(self, peer):
        """Begin a fresh handshake (§6), even if another session exists.

        Implements spec §6.3 (HELLO), with the offer rules of §6.1 and the key
        pinning rule of §5.

        Args:
            peer: the username to handshake with.

        Returns:
            None. Communicates only through `emit`.

        Emits:
            A "send" event carrying a HELLO to `peer`; or, if the peer's
            identity key is unavailable, an "error" event and nothing else
            (§5: "report an error and do not proceed").

        Afterwards (spec §6.9 state table, row 1):
            A new, never-before-used `sid` is in the pending-reply state with
            everything §6.9 says pending state retains, including the exact
            HELLO bytes you sent. The offer is [JM2, JM1] normally and [JM1]
            when `jm1_only` is set (§6.1); ek_I is present exactly when JM2 is
            offered (§6.3). Any existing sessions with `peer` are unaffected.
        """
        raise NotImplementedError("Implement start_handshake in protocol.py")

    # ----- 4. Handshake as responder (§§6.2, 6.4, 6.5, 6.6) ------------------
    # Review-critical (AGENTS.md "What counts as explained": rows "Transcript &
    # signatures" and "State machine").
    #
    # The responder's side, also reached through `receive`:
    #   HELLO via receive     the five ordered steps of §6.4: parse and sid
    #                         check; suite selection by the responder's fixed
    #                         preference; the JM2 encapsulation-key checks;
    #                         pin the initiator's key; derive, store
    #                         pending-finish, send REPLY (§6.5)
    #   FINISH via receive    verify sig_I under the pinned key over the HELLO
    #                         and REPLY bytes you received and sent; establish
    #                         or discard (§6.6)
    # §6.4 also says when to send REJECT (§6.8) and that every REJECT retires
    # its sid. §3 says which malformed HELLOs are discarded silently and which
    # reach §6.4 step 3.

    def receive(self, sender, recipient, body):
        """Process a decoded binary body; emit outputs through self.emit.

        The single entry point for every message from the network. It
        implements the dispatch and discard rules of §6.2 and the envelope
        checks of §6.4 and §6.9, then hands each message type to the logic
        described in sections 3-7 of this file.

        Args:
            sender: the envelope's "from" username, as set by the server.
            recipient: the envelope's "to" username.
            body: the message body as `bytes` (already base64-decoded). Its
                first byte is the message type (§3, §6.2).

        Returns:
            None. Communicates only through `emit`.

        Raises:
            Nothing for any peer input, however malformed (handout §3). A
            `TransportError` from a failed `emit` may propagate.

        Rules from the spec that apply before any type-specific logic:
            * Discard envelopes whose usernames are invalid or whose recipient
              is not this client, before processing any message type (§6.4).
            * Silently discard an unrecognised type or a body that fails to
              parse (§6.2).
            * For any existing session or handshake, the sender must match
              the stored peer; discard mismatches without changing state
              (§6.9).
            * Process REPLY and REJECT only in pending-reply, FINISH only in
              pending-finish, DATA and control messages only for established
              sessions; silently discard everything else (§6.9).

        Afterwards:
            Exactly the state change the §6.9 table allows for this message in
            the current state, or none at all.
        """
        raise NotImplementedError("Implement receive in protocol.py")

    # ----- 5. Key schedule (§6.7) ---------------------------------------------
    # Review-critical (AGENTS.md "What counts as explained": row "Key
    # schedule"). No stub method: this is called from your handshake code in
    # both roles, and how you structure it is up to you.
    #
    # Inputs:  the suite; dh = X25519 shared secret (after §2's checks); for
    #          JM2, ss_pq from ML-KEM; both usernames; the exact HELLO and
    #          REPLY bytes of this handshake.
    # Outputs: the directional record keys of the §6.7 table, IR (initiator to
    #          responder) and RI (responder to initiator).
    # Spec:    §6.7 defines ikm, the transcript hash used as the HKDF salt, the
    #          info string (note §3: the label ends with a space), the output
    #          length L and the split.
    # Afterwards: both sides hold identical IR and RI keys. Each side sends
    #          with its own direction's key and receives with the other's,
    #          so which key is "mine" depends on the role.

    # ----- 6. Records (§§6.9, 7.1, 7.2) ----------------------------------------
    # Core and review-critical (AGENTS.md "Core": the JM1 record functions and
    # the JM2 AEAD calls; "What counts as explained": row "Record receive").
    #
    # Sending (send_text below, §7.1): build `protected` for the session's
    # suite and wrap it in DATA. Receiving (DATA via receive, §7.2): the five
    # ordered steps, whose outcomes are a silent discard, a RESEND, or a
    # RECEIPT plus delivery (or a local error for invalid UTF-8). Use your
    # Part 0 `pkcs7_pad`/`pkcs7_unpad` for JM1.

    def send_text(self, peer, text):
        """Send or queue text using the appropriate session (§§6.9 and 7).

        Implements the session-selection and queueing rules of §6.9 and DATA
        construction in §7.1.

        Args:
            peer: the recipient username.
            text: the message `str`. Empty text is allowed (§7.1).

        Returns:
            None. Communicates only through `emit`.

        Emits:
            A "send" event with a DATA body if a session with `peer` is
            established; otherwise possibly a HELLO, if no handshake with that
            peer is pending in either role (§6.9). An "error" event if the
            text is invalid or too long.

        Afterwards:
            * Text over 4096 UTF-8 bytes (or not encodable as UTF-8) was
              rejected before any sequence number was allocated (§7.1).
            * If a DATA record was sent: it used the most recently established
              session with `peer` (§6.9), that session's send_seq was used
              once and then advanced by one, and its sequence number was never
              before paired with different plaintext under these keys (§7.1).
              JM1 used a fresh random IV; JM2 used the nonce §7.1 defines.
            * Otherwise the text is queued for `peer`, to be sent on whichever
              session with that peer is established first (§6.9).
        """
        raise NotImplementedError("Implement send_text in protocol.py")

    # ----- 7. Control messages (§7.3) -------------------------------------------
    # Part of AGENTS.md "What counts as explained", row "Record receive".
    # No stub method: RECEIPT and RESEND arrive through `receive`, and you send
    # them from your DATA-receive path.
    #
    # §7.3 says: never answer a control message with a control message; accept
    # one only for an established session, from the expected peer, naming a
    # seq this session has already sent; report a given receipt at most once;
    # on RESEND, either warn, or resend the exact cached DATA body (at most
    # once per record), never a re-encryption. Both messages are
    # unauthenticated: a RECEIPT is a delivery indication, not proof.

    # ----- 8. Timeouts and robustness (Appendix B) ------------------------------
    # Optional and not graded (handout §3, spec Appendix B). These methods must
    # exist; they may remain no-ops. The supplied driver stops on any transport
    # failure, so it does not depend on them.

    def check_timeouts(self):
        """Optional Appendix B robustness; this method may remain a no-op.

        Called by the driver after every poll, and by `Network.advance` in
        tests. Appendix B recommends expiring a pending handshake once 60 s or
        more of `self.now()` have elapsed since it was created, abandoning it
        with an error report (§6.9).

        Returns:
            None.
        """

    def reset_peer_trust(self, peer):
        """Optional Appendix B robustness; this method may remain a no-op.

        An explicit local user action (the `reset-trust` command), never an
        automatic response to a peer message (handout §3). Appendix B: after
        a peer's directory key changes, require this reset, which abandons
        that peer's handshakes and sessions, before using the new key.

        Args:
            peer: the username whose trust state to reset.

        Returns:
            None.
        """

    def transport_failed(self, peer=None):
        """Optional Appendix B robustness; the supplied live driver stops on failure.

        Called once by the driver after a transport failure: with the affected
        `peer` after a failed send, or with `None` after an uncertain receive,
        which may have lost mail for any session (handout §3). Appendix B
        suggests abandoning the affected sessions. Whatever you do, never
        reset sequence counters while keeping the same keys (§4.6).

        Args:
            peer: the affected username, or None for "all sessions".

        Returns:
            None.
        """
