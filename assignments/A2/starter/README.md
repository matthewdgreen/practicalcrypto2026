# JMessage Assignment 2 starter kit

Start with the [handout](../handout.md) and [protocol specification](../specification.md).
In the downloadable ZIP, copies of both documents are beside this README.

This kit supplies infrastructure, **not a working protocol client**. You write
`protocol.py` and `padding.py`. Registering an account works immediately, but
handshakes, fingerprints, and encrypted messaging stop at explicit student TODOs
until you implement them. No reference client or exercise bots are included;
the test vectors are in specification Appendix A.

## 1. Set up Python

Use Python 3.12 or newer. In this directory:

```sh
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python check_environment.py
python run_checks.py scaffold
```

On Windows, activate with `.venv\Scripts\Activate.ps1` in PowerShell (or use
`.venv\Scripts\python.exe` directly for each command). Substitute your installed
Python launcher for `python3` as needed.

The requirements pin `cryptography` and its Python dependencies. The environment
check requires the pinned `cryptography` version. A different `cffi` or
`pycparser` version (common under conda) only produces a warning. It exercises Ed25519, X25519, ML-KEM-768, and AES-GCM using library calls, without
printing private keys or implementing JMessage. It reports backend information
so setup problems can be diagnosed. The scaffold check briefly binds a loopback
port; permit local networking if your environment prompts you.

## 2. Your files and the supplied files

**Reading guide.** Every supplied file opens with a header comment saying what it is
for, where it sits, and what it deliberately leaves to you. Read them in this order:

1. `jmessage_support/codec.py`: the §3 encodings, strict base64, and the
   bounds-checked `Reader`.
2. `jmessage_support/messages.py`: the seven message layouts byte by byte, and
   where parsing stops and your checks begin.
3. `protocol.py`: the guided skeleton, in the order we suggest you build it,
   with the spec sections for each part.
4. `jmessage_support/events.py` and `runtime.py`: the `emit` contract,
   one-thread ordering, and what happens on a transport failure.
5. `jmessage_support/testing.py` and `tests/student_checks.py`: how the public
   checks drive your client, and what they cannot detect.
6. `jmessage_support/transport.py`, `identity.py`, `relay.py`, `client.py`:
   HTTP, key storage, the local server, and the driver. Skim these for the
   security notes.

| File | Owner and purpose |
|---|---|
| `padding.py` | You: the independent Part 0 warmup |
| `protocol.py` | You: the `Client` interface from the handout |
| `design.md`, `written.md`, `ai-usage.md` | You: replace prompts with your own work |
| `jmessage_support/codec.py` | Supplied integer/vector readers, base64, UTF-8, and username validation |
| `jmessage_support/messages.py` | Supplied encoders/parsers for the seven message bodies (§§6–7) and the protocol constants |
| `jmessage_support/identity.py` | Supplied Ed25519 key generation and local storage |
| `jmessage_support/transport.py`, `runtime.py` | Supplied REST and sequential event handling |
| `jmessage_support/testing.py` | Supplied in-memory network and controllable clock |
| `client.py` | Supplied interactive driver |
| `local_relay.py` | Supplied local REST relay, with no protocol implementation |
| `run_checks.py`, `tests/` | Public scaffold and student checks |
| `package_submission.py` | Source-only checkpoint archive builder |
| `AGENTS.md` | Optional tutoring instructions for a coding assistant |
| `CLAUDE.md` | Imports the same tutoring instructions for Claude Code |
| `tools/anon-report.py` | Separate anonymous-report deposit and attendance utility; see handout §7 |

The tutoring instructions keep cryptographic reasoning and code central to
your work, with a mock review before packaging. You may override that teaching
style; the handout's independent Part 0 attempt and reporting requirements
still apply. For students who used an agent, the anonymous report and attendance
proof are required before Review Lab 2 signup; students who used no agent are
exempt. `ai-usage.md` belongs in your named submission. The anonymous report is
separate: review it before approving transmission. Keep contribution logs in
`.agent-notes/` and reports, receipts, and attendance proofs out of the submission.

Reporting dates (handout §7): register a public key by **October 23** if you
have not already registered one, and deposit your report by **November 8**.
Staff will publish the tags snapshot on **November 9**.

Finish your initial padding functions and examples independently. Then copy
that version to `padding_first_attempt.py` before using AI feedback or changing
it. That file is intentionally absent from the template: we cannot create your
first attempt for you. Use your padding functions in your JM1 implementation.

`messages.py` packs and unpacks the seven message bodies and enforces §3's
structural rules (raise `DecodeError` → you discard silently). It does not
compute transcript hashes, decide what a signature covers, derive keys, build
or check protected records, or decide what is acceptable in the current state.
Those decisions belong in your implementation. `Reader.finish()` rejects trailing bytes; `rest()` reads
the remaining bytes when the message format calls for it.

The optional robustness methods in `protocol.py` may remain no-ops. The driver
stops after a transport failure, so it does not depend on those methods to
continue safely. It never resets your counters or retries a send automatically.

A peer with no usable published key is not a transport failure. Key lookup
raises `PeerKeyUnavailable`, in both the live driver and the in-memory test
network. Catch it in your protocol code and emit an error event. If it escapes
anyway, the live driver reports it and keeps running, so another user cannot
stop your client just by messaging you without a key.

Mailbox reads are destructive. If your `receive` raises any other unexpected
exception, the driver stops with a traceback, and **the remaining messages in
that batch are lost**. They were already deleted from the server. Fix the bug
and start a fresh handshake; do not expect those messages to be redelivered.

## 3. Run the public checks

After the initial independent warmup, run:

```sh
python run_checks.py warmup
python run_checks.py review_eligible
python run_checks.py client_smoke
```

- `scaffold` tests the supplied infrastructure; it should pass before you write
  any student code.
- `warmup` checks padding boundaries and rejection of invalid inputs.
- `review_eligible` checks required files/interface, the warmup, and ordinary
  JM1 handshakes and messages with your client in both roles.
- `client_smoke` exercises both suites, both roles, empty text, Unicode, and the
  maximum supported text length. It is additional practice, not an eligibility
  requirement.

**Student groups are expected to fail in an untouched starter kit.** A
`NotImplementedError` points to a function you still need to write. Required-file
checks only check presence; they cannot determine whether your written answers
or disclosure are complete.

At this stage the exchange checks run **two copies of your implementation**.
Consistent mistakes on both sides can pass. Passing does not prove that your
wire format, cryptography, or security is correct. Once staff supplies an
independent reference module, the same exchange driver can use it:

```sh
python run_checks.py client_smoke --peer-module staff_reference
```

`staff_reference` is a placeholder name, not a bundled module. Until it is
released, check your byte layouts, transcript hashes, keys and records against
the vectors in specification Appendix A; they were produced by the staff
implementation and confirmed by an independently written client.
The public eligibility group is a minimum progress check; fuller conformance
checks determine assignment points separately.

For your own experiments, `Network.attach(name, Client, jm1_only=True)` installs
a client with fixture identity keys. Emitted sends enter a queue; `pump()` then
delivers them in order. No callback re-enters a client while it is emitting.
`network.advance(seconds)` advances the fake clock and calls the optional timeout
hooks, without sleeping. This harness handles ordinary delivery, not the later
security exercises.

## 4. Try two clients locally

In a first terminal, start the relay:

```sh
python local_relay.py --port 8765
```

In two other terminals, activate the environment and run:

```sh
python client.py --server http://127.0.0.1:8765 --username alice --register --jm1-only
```

```sh
python client.py --server http://127.0.0.1:8765 --username bob --register --jm1-only
```

Each prompts for its password without echoing it. Use fresh local exercise
passwords. On later runs you can omit `--register`; leaving it in is harmless
(an existing account just logs in).
The relay keeps accounts and mailboxes only in memory; after restarting it,
register again. Your client key remains in `.jmessage/`, so restarting a client
does not silently change its fingerprint. The relay has no `echo` account.

After implementing the necessary methods, type commands in Alice's terminal:

```text
fingerprint
fingerprint bob
handshake bob
send bob Hello, Bob!
```

Bob polls automatically and displays received text. He can reply with
`send alice Hello!`. Send and receive operations are serialized on the driver's
main thread. Use `--no-auto-poll` and the `poll` command for manual stepping.
Omit `--jm1-only` on a new run to test the default hybrid offer.

Use `help`, `users`, or `quit` as needed. To preserve exact whitespace, send
multiline text, or send an empty message, enter a JSON command:

```json
{"op":"send","peer":"bob","text":"  café\nsecond line  "}
```

The driver displays JSON events, escaping terminal control characters. It does
not display raw outgoing protocol bodies or extra internal fields in events.
Unexpected exceptions in your protocol implementation retain their traceback
for debugging; do not include secrets in exception messages.

**Building your own interface (optional extra credit; handout Part 1).** The
driver is deliberately minimal so you can replace it. Everything you need is
in `jmessage_support/runtime.py`: construct a `Runtime` with your own `output`
callback instead of the JSON printer, attach your `Client`, and call
`runtime.call(core.send_text, peer, text, peer=peer)`,
`runtime.call(core.start_handshake, peer, peer=peer)` and `runtime.poll()`
from your UI's command handlers. `Runtime` keeps every protocol call on the
thread that calls it, and the `Client` is not thread-safe. A UI with its own
event loop (tkinter, Textual, a browser talking to a local web server) must
therefore hand actions to one protocol thread, for example through a
`queue.Queue` drained by a loop like the one in `client.py`, and must not call
`Client` methods from UI callbacks directly. Render events as they arrive from
`output`; do not reach into `Client` state to display anything.

The course server is `https://jmessage.practicalcrypto.org`:

```sh
python client.py --server https://jmessage.practicalcrypto.org --username YOURNAME --register
```

Its `echo` account (fingerprint `BE 9F 94 00 02 63 66 86 A2 7E`) answers
handshakes in both suites and echoes every text; `fingerprint echo` then
`send echo hi` is the quickest end-to-end check. Usernames are first come,
first served and public, and anyone can message you, so expect the occasional
unexpected HELLO. Plain HTTP is restricted to loopback addresses. The adapter verifies TLS certificates and refuses
redirects. A password file can be supplied with `--password-file PATH` for local
automation; keep it outside your submission and protect its permissions. API
keys remain in memory.

Do not run two clients for the same account at once: logging in again
invalidates the earlier API key, and mailbox reads are destructive. If the
uploaded public key differs from your local key, the driver stops instead of
silently replacing it. Restore your original state directory or use a new local
test account.

## 5. Package the client checkpoint

Complete the required files and run the public checks, then:

```sh
python package_submission.py --output checkpoint.zip
```

The archive has the submission files at its root. It includes your Python
supporting modules and written files, and excludes virtual environments, tests,
the local key store, previous archives, `checkpoint/`, and `exercises/`. It
refuses to overwrite an existing output archive or include symlinked source.
Inspect its contents before submitting. Do not embed passwords or private keys
in source code.

Retain a copy of the actual submitted source in `checkpoint/` for the final
submission. The later Parts 2–3 kit will provide the complete final packaging
contract. This helper packages the client checkpoint only.
