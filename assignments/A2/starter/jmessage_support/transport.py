"""Synchronous REST adapter for the JMessage server API (spec §4).

What this file is for
---------------------
This is the only file in the kit that speaks HTTP. `API` wraps the six server
endpoints of §4 (register, login, upload key, look up key, send, receive) and
turns every failure into one of two exceptions that the rest of the kit
understands: `TransportError` (the network or server failed, so delivery is
uncertain) and `PeerKeyUnavailable` (the directory has no usable key for one
user, which is not a network failure).

Where it sits
-------------

      your Client --emit(send)--> Runtime --API.send-->   HTTPS   --> server
                                  Runtime <--API.receive-- HTTPS  <-- server
                  lookup_peer_key = API.lookup_key  (GET /keys/<user>)

What you should learn from reading it
-------------------------------------
* Which parts of the system the client does *not* trust, and what that means
  in code: the server's response text is never echoed, redirects are refused,
  plain HTTP is allowed only to your own machine, and every field in a
  response is type-checked before use.
* Why a failed send is reported, never retried, and why the difference
  between "failed" and "uncertain" matters (§4.6).

What it deliberately does NOT do
--------------------------------
No cryptography and no protocol logic: a message body is opaque bytes here,
base64-encoded on the way out and strictly decoded on the way in. It never
retries a request, never reorders messages, and never decides what a failure
means for a session; the driver stops instead (README §2) and your optional
`transport_failed` hook may abandon sessions (Appendix B).

Specification sections: §4.1-§4.5 (endpoints), §4.6 (delivery assumptions),
§3 and Appendix B (strict base64), §5 (key lookup).
"""

from dataclasses import dataclass
from http.client import HTTPException
import ipaddress
import json
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from .codec import MAX_PAYLOAD_CHARS, decode_base64, encode_base64, username


# ----- Exceptions -----------------------------------------------------------------
# Two failure kinds with different consequences. The driver stops on the first
# and keeps running on the second; keep them distinct in your code too.

class TransportError(RuntimeError):
    """A request failed or its outcome is uncertain.

    Attributes:
        status: the HTTP status code as an `int` if the server answered with
            one (401, 404, 409, 413, 429, ...), otherwise `None` (connection
            failure, timeout, malformed JSON).

    "Uncertain" matters for sends (§4.6): if the connection dropped after the
    server stored the message but before you read the reply, the peer may
    still receive it. The driver therefore treats every TransportError from a
    send as possibly-delivered and stops rather than guessing.
    """

    def __init__(self, message, *, status=None):
        """Store the message and the optional HTTP `status` code."""
        super().__init__(message)
        self.status = status


class PeerKeyUnavailable(LookupError):
    """The directory has no usable identity key for this user (404 or malformed).

    Not a transport failure: the driver keeps running. Report an error for the
    affected handshake and do not proceed with it (specification §5).

    Why a separate type: any user can send you a HELLO, including one who
    never uploaded a key. If a missing key were a `TransportError`, any such
    user could stop your client just by messaging it.
    """


# ----- Redirect policy ------------------------------------------------------------

class NoRedirects(HTTPRedirectHandler):
    """A urllib handler that refuses every HTTP redirect.

    Why: by default urllib follows 3xx redirects. A redirect could send the
    next request, including its `Authorization: Bearer <apikey>` header or a
    JSON body containing your password, to a different host, or from HTTPS to
    plain HTTP. The JMessage API never needs a redirect, so the safe choice is
    to treat one as an error. The 3xx response then surfaces as an
    `HTTPError`, which `API._request` turns into a `TransportError`.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        """Return None, which tells urllib not to follow the redirect."""
        return None


# ----- Server URL validation ------------------------------------------------------

def server_url(value):
    """Validate a server base URL and return it without trailing slashes.

    Args:
        value: a URL `str` such as "https://jmessage.practicalcrypto.org" or
            "http://127.0.0.1:8765".

    Returns:
        `value` with any trailing "/" removed, so that paths like "/login" can
        be appended directly.

    Raises:
        ValueError: if the scheme is not http/https; there is no host; the URL
            embeds a username or password, a query string or a fragment; plain
            HTTP is used for a host that is not loopback; or the port is
            invalid.

    Why plain HTTP only on loopback (§4: "When you run your own server locally
    you may use plain HTTP"): every authenticated request carries your API key,
    and login carries your password. Over plain HTTP on a real network anyone
    on the path can read both. Traffic to 127.0.0.1/::1/localhost never leaves
    your machine, so the local relay can skip TLS. For HTTPS, urllib's default
    context verifies the server's certificate and host name.

    Why no credentials in the URL: "https://user:pass@host" would put a secret
    in shell history and in any error message that prints the URL.
    """
    parsed = urlsplit(value)
    if (parsed.scheme not in ("http", "https") or not parsed.hostname
            or parsed.username is not None or parsed.password is not None
            or parsed.query or parsed.fragment):
        raise ValueError("server must be an HTTP(S) URL without credentials, query, or fragment")
    if parsed.scheme == "http":
        try:
            # An IP literal: ask the ipaddress module (covers 127.0.0.0/8 and ::1).
            local = ipaddress.ip_address(parsed.hostname).is_loopback
        except ValueError:
            # A name: only the conventional loopback name is accepted.
            local = parsed.hostname == "localhost"
        if not local:
            raise ValueError(
                "plain HTTP is allowed only on loopback; use HTTPS for the course server")
    _ = parsed.port  # Validate a supplied port.
    return value.rstrip("/")


# ----- Message envelopes (§4.5) ---------------------------------------------------

@dataclass(frozen=True)
class Envelope:
    """One received mailbox entry after validation (§4.5).

    Attributes:
        id: the server's message id (`int`). A transport identifier only; it
            is not a record sequence number (§4.6).
        sender: the envelope's "from" username, set by the server to the
            authenticated sender (§4.4). It tells you which account sent the
            message, not that the contents are authentic.
        recipient: the envelope's "to" username.
        body: the decoded message body `bytes`, ready for `Client.receive`.
    """
    id: int
    sender: str
    recipient: str
    body: bytes


def parse_envelope(item):
    """Validate one element of a GET /messages response and return an `Envelope`.

    Args:
        item: one decoded JSON value from the mailbox list; untrusted.

    Returns:
        An `Envelope` with checked fields.

    Raises:
        ValueError: if `item` is not a dict, "id" is not a non-negative `int`,
            "from"/"to" are not valid usernames, or "payload" is not strict,
            canonical base64 within the payload limit (`DecodeError` is a
            `ValueError`). The driver skips such entries.

    Why validate here: the server is untrusted (§1). Checking the usernames
    once at this boundary means your `receive` is never called with a sender
    name that could not be a real account.
    """
    if not isinstance(item, dict) or type(item.get("id")) is not int or item["id"] < 0:
        raise ValueError("invalid message envelope")
    return Envelope(item["id"], username(item.get("from")),
                    username(item.get("to")), decode_base64(item.get("payload")))


# ----- The API client -------------------------------------------------------------

class API:
    """A minimal, synchronous client for the §4 JMessage REST API.

    One instance per account. It holds the API key in memory only (it is never
    written to disk) and sends it as a Bearer token on authenticated calls.
    Every method either returns a validated result or raises; none of them
    retries.

    Why no automatic retries: retrying a POST /messages whose response was
    lost can store the same message twice, and the protocol layer would never
    know. §4.6 asks clients to treat failed or uncertain sends explicitly, so
    the adapter reports them and leaves the decision to the driver.
    """

    def __init__(self, server, *, timeout=10):
        """Prepare a client for `server` (validated by `server_url`).

        Args:
            server: the base URL `str`.
            timeout: per-request socket timeout in seconds. A request that
                exceeds it raises `TransportError`.
        """
        self.server = server_url(server)
        self.timeout = timeout
        self._apikey = None
        self._opener = build_opener(NoRedirects())

    def _request(self, method, path, body=None, *, authenticated=False):
        """Send one HTTP request and return the decoded JSON response.

        Args:
            method: "GET" or "POST".
            path: the endpoint path, starting with "/".
            body: a JSON-serialisable object for POST, or `None`.
            authenticated: if True, attach `Authorization: Bearer <apikey>`.

        Returns:
            The parsed JSON value from a 200 response. Callers check its shape.

        Raises:
            TransportError: if not logged in for an authenticated call; the
                server returns any status other than 200 (with `status` set);
                or the connection, TLS, timeout, or JSON decoding fails.

        The error messages contain only the method, path, status code and
        exception class name. They deliberately do not include the server's
        response text (a hostile server could put misleading text or terminal
        control characters in it) or anything from the request, which may
        hold a password or API key. `from None` drops the chained exception
        for the same reason.
        """
        headers = {"Accept": "application/json"}
        if authenticated:
            if self._apikey is None:
                raise TransportError("log in first")
            headers["Authorization"] = f"Bearer {self._apikey}"
        data = None
        if body is not None:
            # ensure_ascii=True: the request body is pure ASCII JSON, so there
            # is no question of which text encoding the server will assume.
            data = json.dumps(body, ensure_ascii=True).encode("utf-8")
            headers["Content-Type"] = "application/json"
        request = Request(self.server + path, data=data, headers=headers, method=method)
        try:
            with self._opener.open(request, timeout=self.timeout) as response:
                if response.status != 200:
                    raise TransportError(f"{method} {path}: unexpected HTTP status",
                                         status=response.status)
                return json.load(response)
        except HTTPError as exc:
            # Do not echo a server-controlled response or request credentials.
            exc.close()
            raise TransportError(f"{method} {path}: HTTP {exc.code}", status=exc.code) from None
        except (URLError, OSError, ValueError, HTTPException) as exc:
            raise TransportError(
                f"{method} {path}: transport or JSON error ({type(exc).__name__})") from None

    # ----- Accounts (§4.1, §4.2) -----

    def register(self, account, password):
        """POST /register (§4.1). Raises TransportError with status 409 if taken."""
        return self._request("POST", "/register",
                             {"username": username(account), "password": password})

    def login(self, account, password):
        """POST /login (§4.2) and keep the returned API key in memory.

        Args:
            account: the username.
            password: the account password `str`. Sent once, over the
                validated transport; not stored by this object.

        Raises:
            TransportError: on HTTP failure, or if the response has no usable
                API key.

        The old key is cleared first, so a failed login never leaves a stale
        key in place. The key must be printable ASCII without spaces (codes
        33-126) because it is placed verbatim in an HTTP header: a carriage
        return or newline in it would let a hostile server inject extra
        headers into your later requests.
        """
        self._apikey = None
        result = self._request("POST", "/login",
                               {"username": username(account), "password": password})
        if (not isinstance(result, dict) or not isinstance(result.get("apikey"), str)
                or not result["apikey"]):
            raise TransportError("login response lacks an API key")
        if any(ord(c) < 33 or ord(c) > 126 for c in result["apikey"]):
            raise TransportError("invalid API key encoding")
        self._apikey = result["apikey"]

    # ----- Identity-key directory (§4.3, §5) -----

    def upload_key(self, raw):
        """POST /keys (§4.3): publish this account's 32-byte Ed25519 public key.

        Raises:
            ValueError: if `raw` is not 32 bytes (checked before any request).
            TransportError: on HTTP failure.
        """
        if not isinstance(raw, bytes) or len(raw) != 32:
            raise ValueError("identity public key must be 32 bytes")
        self._request("POST", "/keys", {"idPK": encode_base64(raw)}, authenticated=True)

    def lookup_key(self, account):
        """GET /keys/<account> (§4.3): fetch a user's raw 32-byte public key.

        This is the function the driver passes to your `Client` as
        `lookup_peer_key` (handout §3).

        Args:
            account: the username to look up.

        Returns:
            The raw 32-byte Ed25519 public key as `bytes`.

        Raises:
            PeerKeyUnavailable: the server returned 404, or the stored value is
                not canonical base64 of exactly 32 bytes. Report an error for
                that handshake and stop it (§5).
            TransportError: any other HTTP or network failure.
            ValueError: if `account` is not a valid username.

        What this does not do: authenticate the key. The server is untrusted,
        and a key from the directory is only as trustworthy as the server
        that returned it. Comparing fingerprints out of band is the defence
        (§5). It also does not cache: per §5, *your* code fetches the key once
        per handshake, stores those exact bytes, and uses them for every
        signature check in that handshake.
        """
        try:
            result = self._request("GET", "/keys/" + username(account))
        except TransportError as exc:
            if exc.status == 404:
                raise PeerKeyUnavailable(f"no identity key published for {account}") from None
            raise
        try:
            # 44 characters is exactly the canonical base64 length of 32 bytes.
            raw = decode_base64(result["idPK"], max_chars=44)
            if len(raw) != 32:
                raise ValueError("wrong key length")
            return raw
        except (ValueError, KeyError, TypeError):
            raise PeerKeyUnavailable(f"invalid identity key published for {account}") from None

    def users(self):
        """GET /users (§4.3). Returns the list as sent; the order is not meaningful."""
        result = self._request("GET", "/users")
        if not isinstance(result, list):
            raise TransportError("invalid user-list response")
        return result

    # ----- Mailboxes (§4.4, §4.5) -----

    def send(self, peer, body):
        """POST /messages (§4.4): deliver one opaque body to `peer`'s mailbox.

        Args:
            peer: the recipient username.
            body: the binary message body; base64-encoded here.

        Returns:
            The server-assigned message id (`int`).

        Raises:
            ValueError: if the encoded payload exceeds 8192 characters; checked
                before sending, so nothing reached the server.
            TransportError: the request failed. Delivery is uncertain: the
                server may or may not have stored the message (§4.6).
        """
        payload = encode_base64(body)
        if len(payload) > MAX_PAYLOAD_CHARS:
            raise ValueError("message exceeds server payload limit")
        result = self._request("POST", "/messages", {"to": username(peer), "payload": payload},
                               authenticated=True)
        if not isinstance(result, dict) or type(result.get("id")) is not int or result["id"] < 0:
            raise TransportError("invalid send response; delivery is uncertain")
        return result["id"]

    def receive(self):
        """GET /messages (§4.5): fetch and empty this account's mailbox.

        Returns:
            The raw list of envelope objects, in server order. Each one still
            needs `parse_envelope`.

        Raises:
            TransportError: on any failure.

        Mailbox reads are destructive: the server deletes the messages as it
        returns them (§4.5). If the response is lost in transit, those
        messages are gone, and nothing here can get them back (§4.6). That is
        why the driver treats a failed receive as affecting every session.
        """
        result = self._request("GET", "/messages", authenticated=True)
        if not isinstance(result, list):
            raise TransportError("invalid mailbox response; delivery is uncertain")
        return result
