"""Public smoke checks; not a replacement for independent conformance tests.

What this file is for
---------------------
The checks behind `run_checks.py warmup`, `review_eligible` and
`client_smoke` (README §3, handout §6). They import your `padding.py` and
`protocol.py` and are expected to fail until you implement them.

Where it sits
-------------

      run_checks.py --> unittest --> these TestCases
                                        |  Network.attach("alice", your Client)
                                        |  Network.attach("bob",   your Client or --peer-module)
                                        v
                               jmessage_support/testing.py (in-memory, ordered delivery)

What you should learn from reading it
-------------------------------------
* Exactly what "review eligible" requires: the files exist, the interface
  exists, the padding boundary cases work, and an ordinary JM1 handshake and
  exchange succeeds with you in each role.
* What an ordinary exchange looks like from the outside: one "established"
  event per side with matching `sid` and the expected suite, then for each
  text a "message" event at the receiver with the right `seq` and a "receipt"
  event back at the sender.

What it deliberately does NOT do
--------------------------------
These checks run on a perfect network and, by default, against a second copy
of your own client. They do not test malformed input, wrong signatures,
retransmission, expiry or anything adversarial, and they cannot detect a
mistake you make identically on both sides (for example, a wrong label in a
transcript hash). Passing is a progress check, not evidence of conformance or
security. Check byte-level outputs against the spec's Appendix A test vectors.
"""

import importlib
from pathlib import Path
import unittest

from jmessage_support.testing import Network

# Set by run_checks.py from --peer-module. None means "use a second copy of
# the student's own Client as the peer".
PEER_MODULE = None
# The starter directory (the parent of tests/).
ROOT = Path(__file__).resolve().parents[1]


# ----- Part 0: padding ------------------------------------------------------------

class WarmupChecks(unittest.TestCase):
    """Handout Part 0: `pkcs7_pad` / `pkcs7_unpad` boundary and rejection cases."""

    def test_padding_boundaries(self):
        """Empty, one-short and aligned inputs pad and unpad as PKCS#7 requires."""
        from padding import pkcs7_pad, pkcs7_unpad
        # (input, expected padded output) at block size 16. Note the aligned case:
        # 16 bytes in, 32 bytes out.
        examples = [(b"", b"\x10" * 16), (b"A" * 15, b"A" * 15 + b"\x01"),
                    (b"A" * 16, b"A" * 16 + b"\x10" * 16)]
        for plain, padded in examples:
            with self.subTest(length=len(plain)):
                self.assertEqual(pkcs7_pad(plain), padded)
                self.assertEqual(pkcs7_unpad(padded), plain)
        # The extremes of the supported block-size range (1 and 255).
        self.assertEqual(pkcs7_pad(b"", 1), b"\x01")
        self.assertEqual(pkcs7_pad(b"", 255), b"\xff" * 255)

    def test_invalid_padding(self):
        """Unpadding rejects bad input, and both functions reject bad block sizes."""
        from padding import pkcs7_pad, pkcs7_unpad
        # Empty; not block-aligned; pad byte 0; pad byte 17 > 16; last two
        # bytes disagree (claims 2 bytes of padding but they are 01 02).
        for raw in (b"", b"A", b"A" * 15 + b"\x00", b"A" * 15 + b"\x11",
                    b"A" * 14 + b"\x01\x02"):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                pkcs7_unpad(raw)
        for width in (0, 256):
            with self.subTest(width=width):
                with self.assertRaises(ValueError):
                    pkcs7_pad(b"A", width)
                with self.assertRaises(ValueError):
                    pkcs7_unpad(b"A", width)


# ----- Submission shape -----------------------------------------------------------

class SubmissionChecks(unittest.TestCase):
    """Handout §7: the required files exist, and handout §3: the interface exists."""

    def test_required_files(self):
        """Each required file exists and is not empty (contents are not judged)."""
        for name in ("protocol.py", "padding.py", "padding_first_attempt.py",
                     "design.md", "written.md", "ai-usage.md"):
            with self.subTest(file=name):
                path = ROOT / name
                self.assertTrue(path.is_file(), f"missing {name}")
                self.assertTrue(path.read_text(encoding="utf-8").strip(), f"empty {name}")

    def test_client_interface(self):
        """`protocol.Client` has all seven handout §3 methods."""
        from protocol import Client
        for name in ("start_handshake", "send_text", "receive", "check_timeouts",
                     "fingerprint", "reset_peer_trust", "transport_failed"):
            self.assertTrue(callable(getattr(Client, name, None)), f"missing Client.{name}")


# ----- Ordinary exchanges ---------------------------------------------------------

def exchange(test, *, jm1_only, initiator):
    """Run one complete handshake and eight text messages between alice and bob.

    Args:
        test: the running `unittest.TestCase`, used for assertions.
        jm1_only: passed to both clients. True means the initiator offers only
            JM1, so the session must use suite 1; False means the ordinary
            offer [JM2, JM1], so the session must use suite 2 (§6.1, §6.4).
        initiator: "alice" (your client starts) or "bob" (the peer starts).

    Alice is always your `protocol.Client`. Bob is your client too, unless
    `PEER_MODULE` names an independent implementation.

    What is checked, in order:
        1. After `start_handshake` and delivery, each side emitted exactly one
           "established" event, with the expected suite and the same `sid`.
        2. For each of four texts ("hello", empty, multi-line Unicode, and the
           4096-byte maximum), each side sends to the other. The receiver must
           emit a "message" with the exact text, the right peer and the next
           `seq` (0, 1, 2, 3 in each direction, §7.1), and the sender must
           receive a "receipt" for that `seq` (§7.2 step 4, §7.3).
        3. Something actually crossed the transport, and nobody emitted an
           "error".
    """
    from protocol import Client
    peer_factory = importlib.import_module(PEER_MODULE).Client if PEER_MODULE else Client
    network = Network()
    network.attach("alice", Client, jm1_only=jm1_only)
    network.attach("bob", peer_factory, jm1_only=jm1_only)
    responder = "bob" if initiator == "alice" else "alice"
    network.clients[initiator].start_handshake(responder)
    network.pump()
    # Step 1: both sides established the same session with the expected suite.
    expected_suite = 1 if jm1_only else 2
    for name in (initiator, responder):
        established = network.matching(name, "established")
        test.assertEqual(len(established), 1, f"{name}: expected one establishment event")
        test.assertEqual(established[0]["suite"], expected_suite)
    test.assertEqual(network.matching(initiator, "established")[0]["sid"],
                     network.matching(responder, "established")[0]["sid"])
    # Step 2: texts in both directions; each direction's seq counts 0, 1, 2, 3.
    texts = ("hello", "", "café 🦉\nsecond line", "A" * 4096)
    for seq, text in enumerate(texts):
        for sender, recipient in ((initiator, responder), (responder, initiator)):
            network.clients[sender].send_text(recipient, text)
            network.pump()
            received = network.matching(recipient, "message")
            test.assertEqual(len(received), seq + 1)
            test.assertEqual(received[-1]["text"], text)
            test.assertEqual(received[-1]["peer"], sender)
            test.assertEqual(received[-1]["seq"], seq)
            test.assertTrue(any(e["seq"] == seq for e in network.matching(sender, "receipt")),
                            f"{sender}: missing receipt for {seq}")
    # Step 3: real traffic, no errors.
    test.assertTrue(network.wire, "no protocol messages passed through transport")
    for name in ("alice", "bob"):
        test.assertFalse(network.matching(name, "error"), f"{name}: error during ordinary exchange")


class JM1Checks(unittest.TestCase):
    """Ordinary JM1 exchanges (§6.1 JM1-only offer), with your client in each role."""

    def test_student_initiates(self):
        """Your client sends HELLO offering only JM1; the peer responds."""
        exchange(self, jm1_only=True, initiator="alice")

    def test_student_responds(self):
        """The peer sends HELLO offering only JM1; your client responds."""
        exchange(self, jm1_only=True, initiator="bob")


class JM2Checks(unittest.TestCase):
    """Ordinary JM2 exchanges (the default [JM2, JM1] offer), in each role."""

    def test_student_initiates(self):
        """Your client sends the ordinary HELLO; the peer must select JM2."""
        exchange(self, jm1_only=False, initiator="alice")

    def test_student_responds(self):
        """The peer sends the ordinary HELLO; your client must select JM2."""
        exchange(self, jm1_only=False, initiator="bob")
