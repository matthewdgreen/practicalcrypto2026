"""Supplied infrastructure. Protocol and padding exercises live outside this package.

Everything in `jmessage_support/` is glue that the starter kit provides so you
can spend your time on the cryptographic core (AGENTS.md, "The three zones").
Suggested reading order, bottom layer first:

    codec.py      §3 encodings: u8..u64, vec8/vec16, str8, strict base64/UTF-8, Reader
    messages.py   §§6-7 byte layouts of the seven message bodies, and the constants
    events.py     the handout §3 event dictionaries your Client emits
    identity.py   creating and loading your long-term Ed25519 key (§5)
    transport.py  the §4 REST API over HTTPS, and its two exception types
    runtime.py    one thread, ordered calls: Client <-> transport
    testing.py    an in-memory network and fake clock for experiments
    relay.py      a loopback-only server for running two clients locally

Your own code goes in `protocol.py` and `padding.py`, outside this package.
"""
