"""Local storage of this client's long-term Ed25519 identity key (spec §5).

What this file is for
---------------------
Each JMessage client has one long-term Ed25519 keypair `(idSK, idPK)` (§5).
This module generates the private key the first time you run a client for an
account, stores its raw 32 bytes in a file only you can read, and loads the
same key on every later run. A stable key is what makes a fingerprint mean
anything: if the key changed at every start-up, your fingerprint would too.

Where it sits
-------------

      client.py main()
         | load_or_create(state_dir/<server-id>, account)  -> 32 raw bytes
         | public_bytes(raw)                                -> idPK, uploaded (§4.3)
         v
      your Client(username, identity_private_key=raw, ...)

What you should learn from reading it
-------------------------------------
* How to create a secret file safely: atomically, with restrictive
  permissions from the first byte, without following symbolic links, and
  without ever overwriting an existing key.
* Why a damaged key file is an error to report, not something to "repair"
  by generating a new key.

What it deliberately does NOT do
--------------------------------
It does not compute fingerprints (§5) and does not sign anything. Your
`Client` receives the raw private-key bytes and does both; the fingerprint
function is one of the small "core" pieces you write yourself.

Specification sections: §5 (identity keys and fingerprints), §2 (Ed25519 raw
32-byte keys).
"""

import os
from pathlib import Path
import stat

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .codec import username


# ----- Public key derivation --------------------------------------------------

def public_bytes(private_bytes):
    """Return the raw 32-byte Ed25519 public key for a raw private key.

    Args:
        private_bytes: the 32-byte raw Ed25519 private key (RFC 8032 seed).

    Returns:
        The 32-byte raw public key, idPK, in the form the server stores (§4.3)
        and the fingerprint hashes (§5).

    Raises:
        ValueError: if `private_bytes` is not a valid 32-byte private key.
    """
    return Ed25519PrivateKey.from_private_bytes(private_bytes).public_key().public_bytes_raw()


# ----- Load or create the private key ---------------------------------------------

def load_or_create(directory, account):
    """Never replace an existing key automatically, even if it is malformed.

    Load the identity private key for `account` from `directory`, creating a
    fresh one only if no key file exists yet.

    Args:
        directory: a path (`str` or `Path`) for key files. Created with mode
            0700 if missing. `client.py` passes `.jmessage/<server-id>/`, so
            the same username on two servers gets two different keys.
        account: the local username; validated, then used as the file name
            `<account>.ed25519`.

    Returns:
        The raw 32-byte Ed25519 private key as `bytes`.

    Raises:
        ValueError: if `account` is not a valid username; the key file is a
            symlink or not a regular file; it is readable or writable by other
            users (POSIX only); it is not exactly 32 bytes; or it does not
            import as an Ed25519 key.
        OSError: for file-system errors (for example, a missing parent
            directory you cannot create).

    Design notes, in the order the code runs:

    1. Create with `O_CREAT | O_EXCL` and mode 0600. `O_EXCL` makes "create
       only if absent" a single atomic step in the kernel. The alternative,
       "if not path.exists(): write it", has a gap between the check and the
       write in which another process (or a second copy of this client) could
       create the file, and one key would silently overwrite the other. Passing
       the mode to `os.open` means the file is private from the moment it
       exists; creating it and calling `chmod` afterwards would leave a short
       window in which it is readable.
    2. If the file already exists, do nothing to it. In particular, never
       regenerate a key because the existing one looks wrong. A replaced key
       changes your fingerprint without your knowledge, and the server would
       then hold a public key that no longer matches (the driver checks this
       and stops). A loud error that you resolve by hand is better.
    3. Open for reading with `O_NOFOLLOW`, after also rejecting a symlink by
       name. A symlink at the key path could point at some other file you can
       read, or at a file an attacker controls; either way you would load a
       key that is not the one you created. `O_NOFOLLOW` makes the open itself
       fail on a symlink, closing the gap between the `is_symlink` check and
       the open. (`getattr(..., 0)` keeps the code portable to Windows, which
       lacks the flag; there the `is_symlink` check still applies.)
    4. Check the *open file descriptor* with `fstat`, not the path. The checks
       then apply to exactly the file being read, even if the name is changed
       to point elsewhere after the open.
    5. Refuse a key file that group or others can access (mode & 0o077). A
       private key that other local users can read is no longer private.
       The message tells you the one-line fix.
    6. Read up to 33 bytes and require exactly 32. Reading one extra byte is
       how "too long" is detected without reading an arbitrarily large file.
    7. Import the key once to check it is valid, without printing it.
    """
    account = username(account)
    directory = Path(directory)
    # mode=0o700 applies only to directories this call creates (and is further
    # reduced by the process umask); an existing directory keeps its mode.
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    path = directory / f"{account}.ed25519"
    # Step 1: atomic create-if-absent with private permissions.
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    try:
        fd = os.open(path, flags, 0o600)
    except FileExistsError:
        pass  # Step 2: an existing key is always kept, whatever its contents.
    else:
        # Only reached when this call created the file. The key comes from the
        # library's generator, which uses the operating system's CSPRNG (§2).
        raw = Ed25519PrivateKey.generate().private_bytes_raw()
        with os.fdopen(fd, "wb") as stream:
            stream.write(raw)
            stream.flush()
            # fsync so that a crash right after the first run cannot leave an
            # empty key file, which step 6 would then refuse to load.
            os.fsync(stream.fileno())
    # Step 3: never follow a symlink at the key path.
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    if path.is_symlink():
        raise ValueError("identity file must not be a symlink")
    fd = os.open(path, flags)
    with os.fdopen(fd, "rb") as stream:
        # Step 4: inspect the file we actually opened.
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode):
            raise ValueError("identity must be a regular file")
        # Step 5: POSIX permission bits; Windows has a different permission model.
        if os.name == "posix" and info.st_mode & 0o077:
            raise ValueError(f"identity file is accessible to other users; run chmod 600 {path}")
        # Step 6: one byte more than expected, to detect an oversized file.
        raw = stream.read(33)
    if len(raw) != 32:
        raise ValueError("identity file must contain exactly 32 bytes; refusing to replace it")
    public_bytes(raw)  # Validate import, without displaying secret material.
    return raw
