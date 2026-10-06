"""Local-only, in-memory REST relay. No protocol core, bots, or exercise hooks.

What this file is for
---------------------
A small stand-in for the course server that runs on your own machine, so two
copies of your client can talk without the network (README §4). It implements
the server half of the §4 REST API: accounts, the identity-key directory, and
one mailbox per user. `local_relay.py` starts it; the scaffold tests also use
it.

Where it sits
-------------

      client.py (alice) --HTTP--+                     +-- Store (this file)
                                |--> Handler._serve --|     accounts{name: record}
      client.py (bob)   --HTTP--+    (parse request)  |     tokens{apikey: name}
                                                      +-- dispatch(method, path, body)

    Handler turns HTTP into (method, path, JSON body, Authorization header) and
    back; Store holds all state and implements each endpoint under one lock.

What you should learn from reading it
-------------------------------------
* What the server can and cannot see. It stores public keys and opaque
  base64 payloads. It never parses a message body and holds no key that could
  decrypt one. This is the "untrusted relay" of spec §1 made concrete: the
  server decides who receives what, but not what the bytes mean.
* Basic server-side hygiene: salted, slow password hashing; constant-time
  comparison; random bearer tokens; fixed size limits; generic error bodies.
* Why mailbox reads are destructive (§4.5), from the server's side: `GET
  /messages` hands over the list and replaces it with an empty one in one
  step. There is no acknowledgement; if the response is lost, so are the
  messages.

What it deliberately does NOT do
--------------------------------
No TLS (it binds to 127.0.0.1 only, which is why plain HTTP is acceptable;
see `transport.server_url`), no persistence (restarting deletes everything),
no `echo` user, no reference client, and no rate limiting beyond a mailbox
cap. It is not the course server, whose code is not distributed, though it
follows the same API.

Specification sections: §4.1-§4.5 (endpoints and status codes), §4.4 (8192-
character payload limit), §4.5 (destructive, ordered receive).
"""

import hashlib
import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import secrets
import threading
import time

from .codec import decode_base64, username


# ----- Errors -----------------------------------------------------------------

class RequestError(Exception):
    """Abort the current request with an HTTP status code (`status`, an `int`)."""

    def __init__(self, status):
        """Remember the HTTP `status` to send back."""
        self.status = status


# ----- State and endpoint logic -------------------------------------------------

class Store:
    """All relay state, plus the logic for each §4 endpoint.

    Attributes:
        lock: one re-entrant lock around every request. The HTTP server runs
            each request on its own thread, so without it two sends could race
            on `next_id` or a mailbox list. One coarse lock is slow but
            obviously correct, which is the right trade for a teaching relay.
        accounts: username -> record dict with keys "salt", "password_hash",
            "created", "lastSeen", "key" (base64 idPK or None), "token"
            (current API key or None) and "mailbox" (list of envelope dicts).
        tokens: API key -> username, for authenticating requests.
        next_id: the next message id to assign; increases forever (§4.4).
    """

    def __init__(self):
        """Start with no accounts."""
        self.lock = threading.RLock()
        self.accounts = {}
        self.tokens = {}
        self.next_id = 1

    def authenticated(self, header):
        """Return the username for a `Bearer <apikey>` header, or raise 401.

        Args:
            header: the raw Authorization header value, or "" if absent.

        Returns:
            The authenticated username (`str`). Also updates its "lastSeen".

        Raises:
            RequestError(401): missing header, wrong scheme, or unknown key.

        Simplification: this relay keeps API keys in memory exactly as issued
        and looks them up in a dict. That is acceptable for an in-memory,
        loopback-only process. A server that stores keys on disk should store
        only a hash of each key (the course server stores a SHA-256), so that
        a leaked database does not hand out working credentials.
        """
        token = header.removeprefix("Bearer ") if header.startswith("Bearer ") else ""
        account = self.tokens.get(token)
        if account is None:
            raise RequestError(401)
        self.accounts[account]["lastSeen"] = int(time.time())
        return account

    def dispatch(self, method, path, body, authorization):
        """Handle one API request and return the JSON-serialisable response.

        Args:
            method: "GET" or "POST".
            path: the request path, for example "/keys/alice".
            body: the parsed JSON object for POST (`dict`), or {} for GET.
            authorization: the Authorization header value, or "".

        Returns:
            The response value for a 200 (a dict or list).

        Raises:
            RequestError: with the §4 status for the failure (400, 401, 404,
                409, 413 or 429).
            ValueError / TypeError: for malformed input (bad username, bad
                base64); the Handler maps these to 400.

        The endpoints, in the order they are matched below:
            POST /register, POST /login      no authentication (§4.1, §4.2)
            GET  /users, GET /keys/<name>    no authentication (§4.3)
            POST /keys                       authenticated (§4.3)
            POST /messages, GET /messages    authenticated (§4.4, §4.5)
        """
        with self.lock:
            # ----- Accounts (§4.1, §4.2) -----
            if method == "POST" and path in ("/register", "/login"):
                account = username(body.get("username"))
                password = body.get("password")
                # Bound the password length: it is input to PBKDF2 on every login
                # attempt, and an unbounded value is free work for a client to
                # demand of the server.
                if not isinstance(password, str) or not 1 <= len(password.encode("utf-8")) <= 1024:
                    raise RequestError(400)
                if path == "/register":
                    if account in self.accounts:
                        raise RequestError(409)           # §4.1: username taken
                    # Never store the password itself. Store a random per-account
                    # salt and PBKDF2-HMAC-SHA256(password, salt, 100000 rounds):
                    #  - the salt means equal passwords give different hashes, so
                    #    one precomputed table cannot crack every account at once;
                    #  - the iteration count makes each guess deliberately slow
                    #    for anyone who obtains the stored hashes.
                    salt = secrets.token_bytes(16)
                    self.accounts[account] = {
                        "salt": salt,
                        "password_hash": hashlib.pbkdf2_hmac("sha256", password.encode(), salt,
                                                             100_000),
                        "created": int(time.time()), "lastSeen": int(time.time()),
                        "key": None, "token": None, "mailbox": [],
                    }
                    return {}
                # /login: an unknown user and a wrong password both get 401, so
                # the response does not say which usernames exist. (This relay
                # does not also equalise their timing.)
                record = self.accounts.get(account)
                if record is None:
                    raise RequestError(401)
                candidate = hashlib.pbkdf2_hmac("sha256", password.encode(), record["salt"],
                                                100_000)
                # compare_digest takes the same time wherever the first differing
                # byte is, so response timing does not reveal how much of the
                # hash a guess got right. `==` stops at the first difference.
                if not hmac.compare_digest(candidate, record["password_hash"]):
                    raise RequestError(401)
                # §4.2: logging in again invalidates the previous API key.
                if record["token"] is not None:
                    self.tokens.pop(record["token"], None)
                # 32 random bytes from the OS CSPRNG, URL-safe base64 encoded.
                # Its characters are all printable ASCII, as API.login requires.
                token = secrets.token_urlsafe(32)
                record["token"] = token
                record["lastSeen"] = int(time.time())
                self.tokens[token] = account
                return {"apikey": token}
            # ----- Public directory (§4.3) -----
            if method == "GET" and path == "/users":
                # Sorted here for stable output; §4.3 says clients must not
                # depend on the order.
                return [{"username": name, "created": record["created"],
                         "lastSeen": record["lastSeen"]}
                        for name, record in sorted(self.accounts.items())]
            if method == "GET" and path.startswith("/keys/"):
                # Validating the name also rejects "/keys/../x" and similar.
                account = username(path[len("/keys/"):])
                record = self.accounts.get(account)
                if record is None or record["key"] is None:
                    raise RequestError(404)
                return {"idPK": record["key"]}
            # ----- Everything below requires a valid API key -----
            if path not in ("/keys", "/messages"):
                raise RequestError(404)
            account = self.authenticated(authorization)
            if method == "POST" and path == "/keys":
                encoded = body.get("idPK")
                # Strict base64 of exactly 32 bytes (44 characters). The relay
                # checks only the shape; it cannot check whose key it is.
                if len(decode_base64(encoded, max_chars=44)) != 32:
                    raise RequestError(400)
                self.accounts[account]["key"] = encoded   # §4.3: replaces any earlier key
                return {}
            if method == "POST" and path == "/messages":
                peer = username(body.get("to"))
                if peer not in self.accounts:
                    raise RequestError(404)
                payload = body.get("payload")
                if isinstance(payload, str) and len(payload) > 8192:
                    raise RequestError(413)               # §4.4 payload limit
                decode_base64(payload)                    # strict base64, or 400
                mailbox = self.accounts[peer]["mailbox"]
                # A full mailbox gets 429 (§4) instead of growing without bound.
                if len(mailbox) >= 256:
                    raise RequestError(429)
                message_id = self.next_id
                self.next_id += 1
                # §4.4: "from" is the authenticated account, never a value the
                # sender supplies. The payload is stored as opaque text.
                mailbox.append({"id": message_id, "from": account, "to": peer, "payload": payload})
                return {"id": message_id}
            if method == "GET" and path == "/messages":
                # §4.5: return everything, in arrival order, and empty the mailbox
                # in the same locked step. No acknowledgement is involved.
                batch = self.accounts[account]["mailbox"]
                self.accounts[account]["mailbox"] = []
                return batch
            raise RequestError(404)


# ----- HTTP front end -------------------------------------------------------------

class Handler(BaseHTTPRequestHandler):
    """Translate HTTP requests into `Store.dispatch` calls and back.

    Every response is JSON with an explicit Content-Length. Error responses
    carry only a generic message, never details of what was wrong, so the
    relay does not echo request content back to the caller.
    """

    # The HTTP adapter adds no client cryptography and never logs credentials.
    def log_message(self, *args):
        """Suppress the default per-request log line (it would print paths)."""
        pass

    def _serve(self):
        """Read one request, dispatch it, and write one JSON response.

        Request-body rules:
            * "Transfer-Encoding" is refused (400). Only a plain Content-Length
              body is supported, so there is exactly one way to find where a
              request ends.
            * Content-Length above 16384 bytes is refused with 413 before
              reading anything. That comfortably exceeds the largest valid
              request (an 8192-character payload plus JSON framing).
            * A POST body must be a JSON object.
        """
        try:
            if self.headers.get("Transfer-Encoding") is not None:
                raise RequestError(400)
            length = int(self.headers.get("Content-Length", "0"))
            if length < 0:
                raise RequestError(400)
            if length > 16_384:
                raise RequestError(413)
            body = {}
            if self.command == "POST":
                body = json.loads(self.rfile.read(length))
                if not isinstance(body, dict):
                    raise RequestError(400)
            result = self.server.store.dispatch(self.command, self.path, body,
                                                self.headers.get("Authorization", ""))
            status = 200
        except RequestError as exc:
            status, result = exc.status, {"error": "request rejected"}
        except (ValueError, TypeError, UnicodeError):
            # Bad JSON, bad username, bad base64, non-integer Content-Length...
            status, result = 400, {"error": "malformed request"}
        encoded = json.dumps(result).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        try:
            self.wfile.write(encoded)
        except (BrokenPipeError, ConnectionResetError):
            # The client went away. For GET /messages this is exactly the
            # "lost response" case of §4.6: the batch was already removed.
            pass

    do_GET = _serve
    do_POST = _serve


# ----- Construction ---------------------------------------------------------------

def make_server(port=0):
    """Create (but do not start) a relay bound to 127.0.0.1.

    Args:
        port: TCP port; 0 asks the OS for any free port (the tests use this).

    Returns:
        A `ThreadingHTTPServer` with a fresh `Store` attached as `.store`.
        Call `serve_forever()` to run it; read `server_port` for the port.

    Binding to 127.0.0.1, never 0.0.0.0, means other machines cannot reach the
    relay at all, which is what makes plain HTTP acceptable here.
    `daemon_threads` lets the process exit without waiting for idle
    connections.
    """
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    server.daemon_threads = True
    server.store = Store()
    return server
