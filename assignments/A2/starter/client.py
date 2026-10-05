#!/usr/bin/env python3
"""Supplied interactive driver. All protocol callbacks execute on one thread."""

# (The docstring above is also the `--help` description, so the longer
# overview lives in this comment.)
#
# What this file is for
# ---------------------
# The command-line program you run to use your client (README §4):
#
#     python client.py --server http://127.0.0.1:8765 --username alice --register
#
# It logs in, loads or creates your identity key, makes sure the server has the
# matching public key, constructs your `protocol.Client`, and then runs a loop
# that reads commands from the terminal and polls the mailbox.
#
# Where it sits
# -------------
#
#       terminal --lines--> read_lines thread --queue--> run_loop (main thread)
#                                                          |  parse_command
#                                                          |  dispatch
#                                                          v
#                                          Runtime.call(core.<method>, ...)
#                                                          |
#                                                  your Client (protocol.py)
#
#     The only work done off the main thread is reading lines from stdin. Every
#     call into your Client, and every HTTP request, happens on the main thread
#     in a single sequence (see runtime.py for why).
#
# What you should learn from reading it
# -------------------------------------
# * The start-up sequence, and why it refuses to continue if your local key and
#   the server's copy disagree.
# * How a UI should talk to the protocol core: by calling `Client` methods
#   through `Runtime.call` and rendering the events that come back, never by
#   reading the client's internal state. If you build your own interface
#   (optional extra credit), follow the same shape (README §4).
#
# What it deliberately does NOT do
# --------------------------------
# No cryptography, no message formats, no protocol state. It does not retry
# anything after a transport failure; it stops with a message. Output is JSON
# lines; it never prints raw protocol bodies, keys or the password.
#
# Specification/handout sections: handout §3 (Client constructor and methods;
# `jm1_only`); spec §4.1-§4.3 (register, login, key upload), §4.5 (poll every 1
# to 5 seconds), §5 (stable identity key; fingerprint command), §6.1 (local
# JM1-only compatibility option).

import argparse
import getpass
import json
from pathlib import Path
import queue
import sys
import threading
import time

from jmessage_support.codec import encode_text, username
from jmessage_support.identity import load_or_create, public_bytes
from jmessage_support.runtime import Runtime
from jmessage_support.transport import API, PeerKeyUnavailable, TransportError

HELP = """Commands:
  handshake PEER       begin a fresh handshake
  send PEER TEXT       send text (omit TEXT for an empty message)
  fingerprint [PEER]  display your own or a peer's fingerprint
  poll                receive and process the next mailbox batch
  users               list registered users
  reset-trust PEER     invoke the optional local trust-reset hook
  help / quit
For exact whitespace or multiline text, enter JSON, for example:
  {"op":"send","peer":"bob","text":"line one\\nline two"}
"""


# ----- Output -------------------------------------------------------------------

def output(event):
    """Print one display dictionary as a single JSON line on stdout.

    `ensure_ascii=True` escapes every non-ASCII and control character
    (for example "\\u001b"), so a peer's message text cannot inject terminal
    escape sequences that recolour, hide or rewrite your screen. The cost is
    that "café" prints as "caf\\u00e9"; a real UI would render it properly.
    """
    print(json.dumps(event, ensure_ascii=True), flush=True)


# ----- Command parsing and dispatch ---------------------------------------------

def parse_command(line):
    """Turn one input line into a command dictionary.

    Args:
        line: a line of user input, possibly ending in a newline.

    Returns:
        A `dict` with at least "op", and "peer"/"text" where relevant. A blank
        line becomes {"op": "noop"}.

    Raises:
        ValueError: if a JSON command is not an object (or not valid JSON:
            `json.JSONDecodeError` is a `ValueError`), or a non-send command
            has extra words.

    Two syntaxes:
        * Plain words, split on whitespace at most twice:
          "send bob Hello there" -> op "send", peer "bob", text "Hello there".
          Everything after the peer is the text, but leading whitespace and
          the line ending are lost.
        * A JSON object, when the line starts with "{". Use this for exact
          whitespace, newlines or empty text (README §4).
    """
    line = line.rstrip("\r\n")
    if line.lstrip().startswith("{"):
        result = json.loads(line)
        if not isinstance(result, dict):
            raise ValueError("command must be a JSON object")
        return result
    parts = line.split(maxsplit=2)
    if not parts:
        return {"op": "noop"}
    op = parts[0]
    result = {"op": op}
    if len(parts) > 1:
        result["peer"] = parts[1]
    if op == "send":
        result["text"] = parts[2] if len(parts) > 2 else ""
    elif len(parts) > 2:
        raise ValueError("unexpected command arguments")
    return result


def dispatch(runtime, command):
    """Carry out one parsed command.

    Args:
        runtime: the `Runtime` that owns the client and the API.
        command: a dict from `parse_command` (or a JSON object typed by the
            user, so every field is untrusted and validated here).

    Returns:
        False if the command was "quit", otherwise True.

    Raises:
        ValueError / KeyError: for an invalid username, non-string text, text
            over 4096 UTF-8 bytes, or an unknown command. `run_loop` prints
            these as error events and keeps going.
        TransportError: from `runtime.call` after a transport failure; this
            ends the program.
        NotImplementedError: from an unfinished student method; `main`
            reports it as a "Student TODO".

    Input is validated *before* calling into your Client (usernames, and the
    §7.1 text limit via `encode_text`), so a typo at the prompt becomes an
    error message here rather than an exception inside your protocol code.
    Your `send_text` should still enforce §7.1 itself; other callers exist.
    """
    op = command.get("op")
    core = runtime.client
    if op in ("send", "handshake", "reset-trust"):
        peer = username(command.get("peer"))
        if op == "send":
            text = command.get("text", "")
            if not isinstance(text, str):
                raise ValueError("text must be a string")
            encode_text(text)
            runtime.call(core.send_text, peer, text, peer=peer)
        elif op == "handshake":
            runtime.call(core.start_handshake, peer, peer=peer)
        else:
            runtime.call(core.reset_peer_trust, peer, peer=peer)
    elif op == "fingerprint":
        # §5: the client MUST be able to display its own fingerprint and a
        # named peer's. `peer=None` asks your Client for the local user's.
        peer = command.get("peer")
        if peer is not None:
            username(peer)
        value = runtime.call(core.fingerprint, peer, peer=peer)
        runtime.output({"type": "fingerprint", "peer": peer or runtime.account, "value": value})
    elif op == "poll":
        runtime.poll()
    elif op == "users":
        runtime.output({"type": "users", "users": runtime.call(runtime.api.users)})
    elif op == "help":
        print(HELP, file=sys.stderr)
    elif op == "quit":
        return False
    elif op != "noop":
        raise ValueError("unknown command; enter help")
    return True


# ----- The main loop --------------------------------------------------------------

def read_lines(stream, commands):
    """Background thread: copy lines from `stream` into the `commands` queue.

    Puts `None` when the stream ends (or this thread fails), which tells
    `run_loop` to exit. This thread never touches the Client or the network;
    it exists only because reading stdin blocks, and the main thread must keep
    polling while you are not typing.
    """
    try:
        for line in stream:
            commands.put(line)
    finally:
        commands.put(None)


def run_loop(runtime, *, poll_interval=2, auto_poll=True, stream=None):
    """Interleave mailbox polling and user commands on the calling thread.

    Args:
        runtime: the configured `Runtime`.
        poll_interval: seconds between automatic polls (main() enforces 1-5,
            the §4.5 recommendation).
        auto_poll: if False, poll only on the "poll" command (useful for
            stepping through a handshake by hand).
        stream: input source; defaults to stdin (tests pass a StringIO).

    Returns:
        None, on "quit" or end of input.

    Raises:
        TransportError and any unexpected exception from your Client; `main`
        handles them.

    The loop waits at most 0.1 s for a command, then checks whether a poll is
    due. That keeps polling on schedule without a second thread calling into
    the Client.
    """
    commands = queue.Queue()
    # Only input reading happens off-thread. No crypto/HTTP operations do.
    threading.Thread(target=read_lines, args=(stream or sys.stdin, commands), daemon=True).start()
    next_poll = time.monotonic()
    while True:
        if auto_poll and time.monotonic() >= next_poll:
            runtime.poll()
            next_poll = time.monotonic() + poll_interval
        try:
            line = commands.get(timeout=0.1)
        except queue.Empty:
            continue
        if line is None:
            return
        try:
            if not dispatch(runtime, parse_command(line)):
                return
        except (ValueError, KeyError) as exc:
            # A bad command is the user's typo, not a reason to exit.
            runtime.output({"type": "error", "peer": None, "message": str(exc)})


# ----- Start-up -----------------------------------------------------------------

def main(argv=None):
    """Parse arguments, log in, set up the identity key and Client, and run.

    Args:
        argv: argument list for testing; defaults to sys.argv[1:].

    Returns:
        A process exit code: 0 on a normal exit, 1 on a transport or setup
        error, 2 if an unfinished student method raised NotImplementedError.

    Start-up sequence:
        1. Validate the username and server URL (plain HTTP only on loopback).
        2. Read the password from --password-file, or prompt without echo.
        3. If --register, create the account; "already exists" (409) is fine.
        4. Log in (§4.2); the API key stays in memory only.
        5. Load or create the identity key, in a directory specific to this
           server, so one username on two servers has two separate keys.
        6. Compare the local public key with the directory. If the server has
           a different key, stop rather than replace it: someone else may own
           this account, or you are using a different state directory, and
           silently uploading a new key would change your fingerprint for
           everyone who has already checked it (§5).
        7. Upload the key if none is published.
        8. Construct your Client and enter the command loop.
    """
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--server", required=True, help="course HTTPS URL or loopback HTTP URL")
    parser.add_argument("--username", required=True)
    parser.add_argument("--register", action="store_true", help="create the account before login")
    parser.add_argument("--password-file", type=Path, help="otherwise prompt without echo")
    parser.add_argument("--state-dir", type=Path, default=Path(".jmessage"))
    parser.add_argument("--jm1-only", action="store_true", help="initiate in compatibility mode")
    parser.add_argument("--poll-interval", type=float, default=2)
    parser.add_argument("--no-auto-poll", action="store_true",
                        help="process mail only on a poll command")
    args = parser.parse_args(argv)
    if not 1 <= args.poll_interval <= 5:
        parser.error("--poll-interval must be between 1 and 5 seconds")
    try:
        # Steps 1-2.
        account = username(args.username)
        api = API(args.server)
        # Strip exactly one trailing newline (and then a carriage return) that
        # an editor adds; any other whitespace is part of the password.
        password = (args.password_file.read_text(encoding="utf-8")
                    .removesuffix("\n").removesuffix("\r")
                    if args.password_file else getpass.getpass("Password: "))
        if not password:
            raise ValueError("password must not be empty")
        # Step 3.
        if args.register:
            try:
                api.register(account, password)
            except TransportError as exc:
                if exc.status != 409:
                    raise
                # Already registered (spec §4.1): fall through to login with the
                # given password, so a re-run with --register is harmless.
                print("Account already exists; logging in.", file=sys.stderr)
        # Step 4. Drop our reference to the password as soon as it is used.
        api.login(account, password)
        del password
        # Step 5. Scope local keys by server as well as username.
        # (hashlib is imported here only because nothing else in this file
        # needs it; the hash just turns a URL into a safe directory name.)
        import hashlib
        server_id = hashlib.sha256(api.server.encode("utf-8")).hexdigest()[:16]
        identity = load_or_create(args.state_dir / server_id, account)
        public = public_bytes(identity)
        # Step 6.
        try:
            published = api.lookup_key(account)
        except PeerKeyUnavailable:
            published = None
        if published is not None and published != public:
            raise ValueError(
                "local key differs from the uploaded key; use the original state directory")
        # Step 7.
        if published is None:
            api.upload_key(public)
        # Step 8. `protocol` is imported late so that the account, key and
        # network setup above work (and can be tested) before protocol.py
        # is written.
        from protocol import Client
        runtime = Runtime(api, account, output)
        # time.monotonic, not time.time: a monotonic clock never jumps when
        # the system clock is adjusted (Appendix B handshake expiry).
        runtime.client = Client(account, identity, api.lookup_key, runtime.emit,
                                time.monotonic, jm1_only=args.jm1_only)
        output({"type": "ready", "username": account, "jm1_only": args.jm1_only})
        if sys.stdin.isatty():
            print(HELP, file=sys.stderr)
        run_loop(runtime, poll_interval=args.poll_interval, auto_poll=not args.no_auto_poll)
        return 0
    except NotImplementedError as exc:
        print(f"Student TODO: {exc}", file=sys.stderr)
        return 2
    except TransportError as exc:
        print(f"Stopped: {exc}. No automatic retry was attempted.", file=sys.stderr)
        return 1
    except (ValueError, OSError) as exc:
        print(f"Setup error: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
