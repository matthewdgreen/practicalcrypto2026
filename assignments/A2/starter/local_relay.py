#!/usr/bin/env python3
"""Run an ephemeral teaching relay on loopback. Restarting deletes all accounts."""

# (The docstring above is also the `--help` description, so the longer
# overview lives in this comment.)
#
# What this file is for: a two-line launcher for `jmessage_support.relay`, the
# in-memory stand-in for the course server (README §4). Run it in one terminal,
# then point two `client.py` processes at http://127.0.0.1:<port>.
#
# Where it sits:
#
#     client.py (alice) --HTTP-->  local_relay.py -> relay.make_server()  <--HTTP-- client.py (bob)
#
# What to learn: nothing protocol-specific happens here. Read `relay.py` to see
# what a server in this design stores (accounts, public keys, opaque mailboxes)
# and, just as important, what it never sees (any key that decrypts a message).
#
# What it deliberately does NOT do: no TLS (loopback only), no persistence, no
# `echo` user and no reference client. Spec §4 defines the API it serves.

import argparse

from jmessage_support.relay import make_server


def main():
    """Parse `--port`, start the relay on 127.0.0.1, and serve until Ctrl-C.

    The relay binds to the loopback address only, so it is unreachable from
    other machines; this is why clients may use plain HTTP with it (spec §4).
    All state lives in memory and disappears when the process exits.
    """
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()
    # `with` closes the listening socket on exit, even after Ctrl-C.
    with make_server(args.port) as server:
        print(f"Local relay: http://127.0.0.1:{server.server_port}", flush=True)
        print("In-memory accounts and mailboxes; no echo bot or reference client.", flush=True)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass


if __name__ == "__main__":
    main()
