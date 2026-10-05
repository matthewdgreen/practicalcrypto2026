"""Tests for supplied infrastructure, independent of the student TODOs.

What this file is for
---------------------
`python run_checks.py scaffold` runs these. They check that the supplied kit
works before you write any code: encodings, the identity store, the HTTP
adapter against a real local relay, the single-threaded runtime, the
in-memory network, packaging, and the message encoders/parsers. All of them
should pass in an untouched starter kit.

What you should learn from reading it
-------------------------------------
These tests double as executable documentation of the kit's guarantees. If
you want to know exactly what `decode_base64` rejects, what happens to a
batch when a key lookup fails, or what the packager leaves out, the answer is
an assertion here. Each test's docstring names the property it checks.

What it deliberately does NOT do
--------------------------------
It never calls your protocol code, except for one subprocess check that the
driver reports an unimplemented stub as a "Student TODO" (and that check runs
only while protocol.py is still the original template).
"""

import io
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import threading
import unittest
import zipfile
from unittest.mock import Mock
from urllib.error import HTTPError

from client import dispatch, parse_command, run_loop
from jmessage_support import codec, messages as M
from jmessage_support.events import display_event, validate_event
from jmessage_support.identity import load_or_create, public_bytes
from jmessage_support.relay import make_server
from jmessage_support.runtime import Runtime
from jmessage_support.testing import Network
from jmessage_support.transport import (API, NoRedirects, PeerKeyUnavailable, TransportError,
                                        parse_envelope, server_url)
from package_submission import package


class EncodingTests(unittest.TestCase):
    """codec.py: integers, vectors, strict base64, UTF-8 and usernames (§3)."""
    def test_integer_boundaries(self):
        """Each uN round-trips 0, 1 and its maximum; -1, max+1 and True are rejected."""
        for width in (1, 2, 4, 8):
            for value in (0, 1, 2 ** (width * 8) - 1):
                reader = codec.Reader(codec.uint(value, width))
                self.assertEqual(reader.uint(width), value)
                reader.finish()
            for invalid in (-1, 2 ** (width * 8), True):
                with self.assertRaises(ValueError):
                    codec.uint(invalid, width)

    def test_vectors_and_cursor_bounds(self):
        """Vectors round-trip; Reader rejects reads past the end, lying lengths, trailing bytes."""
        reader = codec.Reader(codec.vec16(b"abc") + codec.str8("café"))
        self.assertEqual(reader.vec16(), b"abc")
        self.assertEqual(reader.str8(), "café")
        reader.finish()
        with self.assertRaises(codec.DecodeError):
            reader.take(1)
        with self.assertRaises(codec.DecodeError):
            codec.Reader(b"\x00\x05ab").vec16()
        with self.assertRaises(codec.DecodeError):
            codec.Reader(b"x").finish()
        with self.assertRaises(ValueError):
            codec.vec8(b"x" * 256)

    def test_canonical_base64(self):
        """Only canonical standard base64 is accepted (Appendix B).

        The invalid inputs cover missing padding ("YQ"), extra padding ("YQ==="),
        non-canonical trailing bits ("YR=="), surrounding whitespace and newlines,
        non-ASCII and out-of-alphabet characters, and a non-string.
        """
        for value in (b"", b"a", b"ab", b"abc", bytes(range(256))):
            self.assertEqual(codec.decode_base64(codec.encode_base64(value)), value)
        for invalid in ("YQ", "YQ===", "YR==", " YQ==", "YQ==\n", "é===", "****", 12):
            with self.subTest(value=invalid), self.assertRaises(codec.DecodeError):
                codec.decode_base64(invalid)

    def test_utf8_and_username(self):
        """Text round-trips (including NUL and emoji); 4096-byte limit; strict UTF-8; usernames."""
        text = "café\n🦉\x00"
        self.assertEqual(codec.decode_text(codec.encode_text(text)), text)
        self.assertEqual(codec.encode_text(""), b"")
        with self.assertRaises(ValueError):
            codec.encode_text("é" * 2049)
        with self.assertRaises(codec.DecodeError):
            codec.decode_text(b"\xff")
        for invalid in ("Alice", "alice/keys", "", "a" * 33, None):
            with self.assertRaises(ValueError):
                codec.username(invalid)


class IdentityTests(unittest.TestCase):
    """identity.py: key creation, stability, and refusal of unsafe key files (§5)."""
    def test_stable_keys_and_permissions(self):
        """The same key loads on every call, accounts get distinct keys, and the file is 0600."""
        with tempfile.TemporaryDirectory() as directory:
            first = load_or_create(directory, "alice")
            self.assertEqual(load_or_create(directory, "alice"), first)
            self.assertEqual(len(public_bytes(first)), 32)
            self.assertNotEqual(load_or_create(directory, "bob"), first)
            if os.name == "posix":
                mode = stat.S_IMODE((Path(directory) / "alice.ed25519").stat().st_mode)
                self.assertEqual(mode, 0o600)

    def test_corrupt_key_is_not_replaced(self):
        """A malformed key file raises and is left byte-for-byte unchanged."""
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "alice.ed25519"
            path.write_bytes(b"corrupt")
            path.chmod(0o600)
            with self.assertRaises(ValueError):
                load_or_create(directory, "alice")
            self.assertEqual(path.read_bytes(), b"corrupt")

    @unittest.skipUnless(os.name == "posix", "POSIX file permissions")
    def test_symlink_and_world_readable_key_rejected(self):
        """A symlinked key file and a group/world-readable key file are both refused."""
        with tempfile.TemporaryDirectory() as directory:
            load_or_create(directory, "bob")
            path = Path(directory) / "alice.ed25519"
            path.symlink_to(Path(directory) / "bob.ed25519")
            with self.assertRaises(ValueError):
                load_or_create(directory, "alice")
            bob = Path(directory) / "bob.ed25519"
            bob.chmod(0o644)
            with self.assertRaises(ValueError):
                load_or_create(directory, "bob")


class HTTPTests(unittest.TestCase):
    """transport.py against a real relay on a loopback port (§4).

    One relay is started for the whole class; each test uses fresh account
    names so the tests do not interfere with each other.
    """

    @classmethod
    def setUpClass(cls):
        """Start a relay on an OS-chosen loopback port in a daemon thread."""
        cls.server = make_server()
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.url = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls):
        """Stop the relay and release its port."""
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=2)

    def make_account(self, name):
        """Register and log in `name`; return its logged-in `API`."""
        api = API(self.url)
        api.register(name, "local-test-password")
        api.login(name, "local-test-password")
        return api

    def test_accounts_keys_and_ordered_destructive_mailbox(self):
        """Key upload and lookup, user list, ordered delivery, then an empty mailbox (§4.5)."""
        alice, bob = self.make_account("a_order"), self.make_account("b_order")
        alice.upload_key(b"a" * 32)
        self.assertEqual(bob.lookup_key("a_order"), b"a" * 32)
        self.assertTrue(any(row["username"] == "a_order" for row in bob.users()))
        first = alice.send("b_order", b"first")
        second = alice.send("b_order", b"second")
        batch = [parse_envelope(item) for item in bob.receive()]
        self.assertEqual([item.id for item in batch], [first, second])
        self.assertEqual([item.body for item in batch], [b"first", b"second"])
        self.assertTrue(all(item.sender == "a_order" for item in batch))
        self.assertEqual(bob.receive(), [])

    def test_relogin_invalidates_old_token(self):
        """Logging in again makes the previous API key fail with 401 (§4.2)."""
        first = self.make_account("login_test")
        second = API(self.url)
        second.login("login_test", "local-test-password")
        with self.assertRaises(TransportError) as caught:
            first.receive()
        self.assertEqual(caught.exception.status, 401)
        self.assertEqual(second.receive(), [])

    def test_failure_statuses_and_limits(self):
        """409 for a taken name, PeerKeyUnavailable for no key, and both payload-size limits."""
        api = self.make_account("limits")
        with self.assertRaises(TransportError) as caught:
            api.register("limits", "local-test-password")
        self.assertEqual(caught.exception.status, 409)
        with self.assertRaises(PeerKeyUnavailable):
            api.lookup_key("limits")
        with self.assertRaises(ValueError):
            api.send("limits", b"x" * 6145)
        with self.assertRaises(TransportError) as caught:
            api._request("POST", "/messages", {"to": "limits", "payload": "x" * 8193},
                         authenticated=True)
        self.assertEqual(caught.exception.status, 413)
        with self.assertRaises(TransportError) as caught:
            api._request("POST", "/messages", {"to": "limits", "payload": "YR=="},
                         authenticated=True)
        self.assertEqual(caught.exception.status, 400)

    def test_no_redirects_or_remote_plaintext(self):
        """server_url refuses remote HTTP, credentials, other schemes, fragments; no redirects."""
        self.assertEqual(server_url("http://127.0.0.1:1234/"), "http://127.0.0.1:1234")
        self.assertEqual(server_url("https://example.test/course/"), "https://example.test/course")
        for url in ("http://example.test", "https://user:pass@example.test", "file:///tmp/a",
                    "https://x/#a"):
            with self.assertRaises(ValueError):
                server_url(url)
        self.assertIsNone(NoRedirects().redirect_request(None, None, 302, "", {},
                                                         "https://example.test"))
        api = API(self.url)
        api._opener.open = Mock(side_effect=HTTPError("", 302, "", {}, None))
        with self.assertRaises(TransportError):
            api.receive()
        # Login is unnecessary for testing rejection of a public redirect.
        with self.assertRaises(TransportError) as caught:
            api.users()
        self.assertEqual(caught.exception.status, 302)
        self.assertEqual(api._opener.open.call_count, 1)

    def test_cli_registration_restart_and_student_todo(self):
        """The real client.py: register, restart with a stable key, re-register, and stub handling.

        Also checks that the password from --password-file never appears in output.
        """
        with tempfile.TemporaryDirectory() as directory:
            root = Path(__file__).resolve().parents[1]
            password = Path(directory) / "password.txt"
            password.write_text("local-cli-password\n")
            command = [sys.executable, str(root / "client.py"), "--server", self.url,
                       "--username", "cli_test", "--password-file", str(password),
                       "--state-dir", str(Path(directory) / "state"), "--no-auto-poll"]
            first = subprocess.run(command + ["--register"], input="users\nquit\n", text=True,
                                   capture_output=True, timeout=15)
            self.assertEqual(first.returncode, 0, first.stderr)
            self.assertEqual(json.loads(first.stdout.splitlines()[0])["type"], "ready")
            self.assertNotIn("local-cli-password", first.stdout + first.stderr)
            keyfile, = (Path(directory) / "state").rglob("*.ed25519")
            key_before = keyfile.read_bytes()
            second = subprocess.run(command, input="quit\n", text=True, capture_output=True,
                                    timeout=15)
            self.assertEqual(second.returncode, 0, second.stderr)
            self.assertEqual(keyfile.read_bytes(), key_before)
            # --register on an existing account (409) logs in instead of failing.
            third = subprocess.run(command + ["--register"], input="quit\n", text=True,
                                   capture_output=True, timeout=15)
            self.assertEqual(third.returncode, 0, third.stderr)
            self.assertIn("already exists", third.stderr)
            self.assertEqual(json.loads(third.stdout.splitlines()[0])["type"], "ready")
            # Call a stub only if this is still the original student template.
            if ('raise NotImplementedError("Implement fingerprint'
                    in (root / "protocol.py").read_text()):
                unfinished = subprocess.run(command, input="fingerprint\n", text=True,
                                            capture_output=True, timeout=15)
                self.assertEqual(unfinished.returncode, 2)
                self.assertIn("Student TODO", unfinished.stderr)


class RuntimeTests(unittest.TestCase):
    """runtime.py: ordering, failure latching and the transport_failed hook (§4.6)."""
    def make_runtime(self):
        """Return (runtime, mock API, list of output events) with a mock Client."""
        api = Mock()
        events = []
        runtime = Runtime(api, "alice", events.append)
        runtime.client = Mock()
        return runtime, api, events

    def test_poll_preserves_order_and_discards_bad_envelopes(self):
        """Valid envelopes reach receive() in order; bad and misaddressed ones are skipped."""
        runtime, api, _ = self.make_runtime()
        api.receive.return_value = [
            {"id": 9, "from": "bob", "to": "alice", "payload": "YQ=="},
            {"id": 10, "from": "bob", "to": "alice", "payload": "!"},
            {"id": 11, "from": "bob", "to": "other", "payload": "YQ=="},
            {"id": 12, "from": "bob", "to": "alice", "payload": "Yg=="},
        ]
        runtime.poll()
        self.assertEqual([call.args for call in runtime.client.receive.call_args_list],
                         [("bob", "alice", b"a"), ("bob", "alice", b"b")])
        runtime.client.check_timeouts.assert_called_once()

    def test_missing_peer_key_does_not_stop_driver(self):
        """PeerKeyUnavailable from one sender is reported; later messages are still processed."""
        # Regression: a 404 on key lookup used to surface as a TransportError,
        # so any keyless account could stop a client by sending it a message.
        runtime, api, _ = self.make_runtime()
        api.receive.return_value = [
            {"id": 1, "from": "mallory", "to": "alice", "payload": "YQ=="},
            {"id": 2, "from": "bob", "to": "alice", "payload": "Yg=="},
        ]
        def receive(sender, recipient, body):
            """Fake Client.receive: fail the key lookup for mallory only."""
            if sender == "mallory":
                raise PeerKeyUnavailable("no identity key published for mallory")
        runtime.client.receive.side_effect = receive
        runtime.poll()
        self.assertFalse(runtime.stopped)
        self.assertEqual(runtime.client.receive.call_count, 2)
        runtime.client.transport_failed.assert_not_called()

    def test_failed_send_stops_even_if_student_catches_exception(self):
        """A failed send stops the driver even if the Client swallows the TransportError.

        Also checks that transport_failed runs only after the Client's call has
        returned, and that no further send is attempted.
        """
        runtime, api, _ = self.make_runtime()
        api.send.side_effect = TransportError("uncertain send")
        active = []
        def student_call():
            """Fake Client method: emit a send and swallow the TransportError."""
            active.append(True)
            try:
                runtime.emit({"type": "send", "to": "bob", "body": b"opaque"})
            except TransportError:
                pass
            active.pop()
        runtime.client.transport_failed.side_effect = lambda peer: self.assertFalse(active)
        with self.assertRaises(TransportError):
            runtime.call(student_call, peer="bob")
        self.assertTrue(runtime.stopped)
        runtime.client.transport_failed.assert_called_once_with("bob")
        with self.assertRaises(TransportError):
            runtime.call(student_call, peer="bob")
        api.send.assert_called_once()

    def test_failed_receive_notifies_all_sessions(self):
        """A failed receive calls transport_failed(None): every session may have lost mail."""
        runtime, api, _ = self.make_runtime()
        api.receive.side_effect = TransportError("uncertain receive")
        with self.assertRaises(TransportError):
            runtime.poll()
        runtime.client.transport_failed.assert_called_once_with(None)

    def test_display_does_not_include_extra_private_state(self):
        """display_event drops keys outside the allowlist, such as a stray private key."""
        event = {"type": "established", "peer": "bob", "sid": b"s" * 16,
                 "suite": 1, "private_key": b"secret"}
        validate_event(event)
        self.assertNotIn("private_key", display_event(event))

    def test_cli_input_and_eof(self):
        """JSON commands keep exact whitespace; 'send bob' means empty text; quit ends the loop."""
        runtime, _, _ = self.make_runtime()
        command = parse_command('{"op":"send","peer":"bob","text":"  café\\n"}')
        dispatch(runtime, command)
        runtime.client.send_text.assert_called_once_with("bob", "  café\n")
        self.assertEqual(parse_command("send bob")["text"], "")
        run_loop(runtime, auto_poll=False, stream=io.StringIO("quit\n"))


class InMemoryTests(unittest.TestCase):
    """testing.py: queued, ordered, non-reentrant delivery and the fake clock."""
    def test_transport_is_queued_and_nonreentrant(self):
        """emit only queues; pump delivers in order; advance runs check_timeouts."""
        calls = []
        class Probe:
            """A stand-in Client that records deliveries and clock readings."""
            # Deliberately no protocol implementation; this only observes delivery.
            def __init__(self, name, private, lookup, emit, now, **kwargs):
                """Accept the handout §3 constructor arguments and keep the useful ones."""
                self.emit = emit
                self.name = name
                self.now = now
                self.lookup = lookup
            def receive(self, sender, recipient, body):
                """Record each delivery as (sender, recipient, body)."""
                calls.append((sender, recipient, body))
            def check_timeouts(self):
                """Record the fake time at which the timeout hook was called."""
                calls.append(self.now())
        network = Network()
        alice = network.attach("alice", Probe)
        network.attach("bob", Probe)
        alice.emit({"type": "send", "to": "bob", "body": b"one"})
        alice.emit({"type": "send", "to": "bob", "body": b"two"})
        self.assertEqual(calls, [])
        self.assertEqual(network.pump(), 2)
        self.assertEqual([entry[2] for entry in calls], [b"one", b"two"])
        self.assertEqual(len(alice.lookup("bob")), 32)
        network.advance(60)
        self.assertEqual(calls[-2:], [60, 60])

    def test_loop_budget(self):
        """Two clients that answer every message forever hit the pump delivery limit."""
        class Looper:
            """A stand-in Client that replies to every message it receives."""
            def __init__(self, name, private, lookup, emit, now, **kwargs):
                """Keep only the emit callback."""
                self.emit = emit
            def receive(self, sender, recipient, body):
                """Answer every message with another one."""
                self.emit({"type": "send", "to": sender, "body": b"loop"})
        network = Network()
        alice = network.attach("alice", Looper)
        network.attach("bob", Looper)
        alice.emit({"type": "send", "to": "bob", "body": b"loop"})
        with self.assertRaisesRegex(RuntimeError, "delivery limit"):
            network.pump(limit=5)


class PackagingTests(unittest.TestCase):
    """package_submission.py: what goes into the checkpoint archive."""
    def test_source_only_archive_and_no_overwrite(self):
        """Only required files and .py sources are archived; secrets are left out; no overwrite."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ("protocol.py", "padding.py", "padding_first_attempt.py", "helper.py",
                         "design.md", "written.md", "ai-usage.md"):
                (root / name).write_text("# fixture\n")
            for folder in (".jmessage", ".venv", "checkpoint", "exercises"):
                (root / folder).mkdir()
                (root / folder / "secret.py").write_text("do not package")
            (root / "password.txt").write_text("do not package")
            target = root / "submission.zip"
            self.assertEqual(package(root, target), 7)
            with zipfile.ZipFile(target) as archive:
                self.assertEqual(set(archive.namelist()), {
                    "protocol.py", "padding.py", "padding_first_attempt.py", "helper.py",
                    "design.md", "written.md", "ai-usage.md"})
            with self.assertRaises(FileExistsError):
                package(root, target)

    def test_first_attempt_is_not_fabricated(self):
        """Packaging fails if a required file such as padding_first_attempt.py is missing."""
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, "missing"):
                package(directory, Path(directory) / "submission.zip")


class MessagesTests(unittest.TestCase):
    """messages.py: encoders and parsers for the seven bodies (§§6-7)."""
    def test_round_trips_and_structural_rules(self):
        """Every encode/parse pair round-trips, and parse_hello enforces §3.

        The rejected HELLOs: trailing byte, truncation, empty suite list,
        duplicate suites, ek_I present without JM2, empty body, wrong type byte.
        """
        sid, x, ek, sig = b"s" * 16, b"x" * 32, b"e" * 1184, b"g" * 64
        h = M.encode_hello(sid, (M.JM2, M.JM1), x, ek)
        self.assertEqual(len(h), 1 + 16 + 1 + 4 + 32 + 2 + 1184)
        self.assertEqual(M.parse_hello(h), M.Hello(sid, (M.JM2, M.JM1), x, ek))
        core = M.encode_reply_core(sid, M.JM1, x, b"")
        r = M.parse_reply(core + sig)
        self.assertEqual((r.suite, r.ct, r.sig, r.core), (M.JM1, b"", sig, core))
        self.assertEqual(M.parse_finish(M.encode_finish(sid, sig)), M.Finish(sid, sig))
        self.assertEqual(M.parse_reject(M.encode_reject(sid, 1, sig)), M.Reject(sid, 1, sig))
        self.assertEqual(M.parse_data(M.encode_data(sid, 7, b"p" * 48)), M.Data(sid, 7, b"p" * 48))
        self.assertEqual(M.parse_control(M.encode_control(M.T_RESEND, sid, 3)),
                         M.Control(M.T_RESEND, sid, 3))
        for bad in (h + b"\x00", h[:-1], M.encode_hello(sid, (), x, b""),
                    M.encode_hello(sid, (M.JM1, M.JM1), x, b""),
                    M.encode_hello(sid, (M.JM1,), x, ek), b"", b"\x05" + sid):
            with self.subTest(bad=bad[:20]), self.assertRaises(codec.DecodeError):
                M.parse_hello(bad)
        with self.assertRaises(codec.DecodeError):
            M.parse_control(M.encode_data(sid, 0, b""))
