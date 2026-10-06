#!/usr/bin/env python3
"""Check library availability without implementing any JMessage protocol step.

What this file is for
---------------------
Run once after installing requirements.txt (README §1). It confirms that your
Python and `cryptography` versions are the pinned ones and that the OpenSSL
backend actually supports every primitive JMessage needs (spec §2): Ed25519
signatures, X25519 key agreement, ML-KEM-768 encapsulation, and AES-GCM.

Why a package version is not enough (handout §3): `cryptography` delegates to
OpenSSL, and ML-KEM in particular depends on the OpenSSL build. A correct
version number with a backend that lacks ML-KEM would install cleanly and then
fail in the middle of your first JM2 handshake. This script finds that out in
advance by performing one real operation with each primitive.

What it deliberately does NOT do
--------------------------------
It implements no JMessage step: no transcripts, no key schedule, no record
format. It prints the OpenSSL version but never prints any key. The random
keys it generates are thrown away when it exits.
"""

import sys


def main():
    """Run the checks and return 0 on success or 1 on any failure.

    Each check is a round trip whose result is known in advance: sign then
    verify; two X25519 parties agree; Encaps then Decaps gives the same
    secret; AES-GCM decrypts what it encrypted. Any exception, from a missing
    module to an unsupported algorithm, is reported as FAIL.
    """
    print(f"Python {sys.version.split()[0]}")
    if sys.version_info < (3, 12):
        print("FAIL: use Python 3.12 or newer")
        return 1
    try:
        # Imports are inside the try so that a missing or broken install is
        # reported as FAIL with advice, not as a traceback.
        from importlib.metadata import version
        from cryptography.hazmat.backends.openssl.backend import backend
        from cryptography.hazmat.primitives.asymmetric import ed25519, x25519, mlkem
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        for package, pinned in (("cryptography", "49.0.0"), ("cffi", "2.0.0"),
                                ("pycparser", "3.0")):
            actual = version(package)
            print(f"{package} {actual}")
            if actual != pinned:
                # Only cryptography's version matters for the protocol; the others are
                # build-time dependencies, so a mismatch (e.g. under conda) is a warning.
                if package == "cryptography":
                    raise RuntimeError(f"install requirements.txt (expected {package}=={pinned})")
                print(f"WARNING: expected {package}=={pinned}; continuing")
        print(backend.openssl_version_text())
        # Ed25519 (identity signatures, §2, §5).
        identity = ed25519.Ed25519PrivateKey.generate()
        signature = identity.sign(b"environment check")
        identity.public_key().verify(signature, b"environment check")
        # X25519 (classical key agreement, §2, §6.7): both sides get the same secret.
        a, b = x25519.X25519PrivateKey.generate(), x25519.X25519PrivateKey.generate()
        if a.exchange(b.public_key()) != b.exchange(a.public_key()):
            raise RuntimeError("X25519 check failed")
        # ML-KEM-768 (post-quantum key agreement, §2, §6.4-§6.5).
        kem = mlkem.MLKEM768PrivateKey.generate()
        secret, ciphertext = kem.public_key().encapsulate()
        if kem.decapsulate(ciphertext) != secret:
            raise RuntimeError("ML-KEM check failed")
        # AES-256-GCM (JM2 records, §7.1). A random nonce is fine for this
        # one-off check; JMessage itself derives its nonces from sequence
        # numbers (§7.1).
        aead = AESGCM(AESGCM.generate_key(bit_length=256))
        import os
        nonce = os.urandom(12)
        ciphertext = aead.encrypt(nonce, b"environment check", b"")
        if aead.decrypt(nonce, ciphertext, b"") != b"environment check":
            raise RuntimeError("AES-GCM check failed")
    except Exception as exc:
        print(f"FAIL: {type(exc).__name__}: {exc}")
        print("Install the pinned requirements in a virtual environment, then try again.")
        return 1
    print("PASS: required asymmetric and AEAD operations are available")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
