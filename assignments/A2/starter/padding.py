"""Part 0: implement these yourself before requesting generated code.

Save your first attempt as padding_first_attempt.py before subsequent revisions.

PKCS#7 padding
--------------
A block cipher mode such as CBC works on whole blocks, so a message must be
extended to a multiple of the block size before encryption and the extension
removed after decryption. PKCS#7 (RFC 5652 §6.3) does this by appending N
bytes, each with the value N, where N is between 1 and the block size and is
chosen so that the result is a whole number of blocks.

Two worked examples with the default block size of 16:

    15-byte input  41 41 41 41 41 41 41 41 41 41 41 41 41 41 41
                   (one byte short of a block, so N = 1)
    padded (16)    41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 01

    16-byte input  41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41
                   (already block-aligned, so N = 16: a whole extra block)
    padded (32)    41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41
                   10 10 10 10 10 10 10 10 10 10 10 10 10 10 10 10

Unpadding reverses this: read the last byte to learn N, check that the last N
bytes all equal N, and remove them.

The contract (handout Part 0)
-----------------------------
* `pkcs7_pad(data: bytes, block_size: int = 16) -> bytes`
* `pkcs7_unpad(data: bytes, block_size: int = 16) -> bytes`
* Support block sizes 1 through 255.
* Padding always appends at least one byte, including a full block when the
  input is already aligned.
* Unpadding raises `ValueError` for an invalid block size, empty input,
  non-block-aligned input, or invalid padding.
* Use these functions for JM1 (specification §7.1-§7.2).

The handout also asks for your own examples (empty input, an aligned input,
an input one byte short of a block, and invalid padding) and your own
explanation of why padding is always added. Write the first version of these
functions and examples without generated code or a library padding helper.
"""


def pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    """Return `data` with PKCS#7 padding for `block_size` (see the module docstring)."""
    raise NotImplementedError("Complete the independent padding warmup")


def pkcs7_unpad(data: bytes, block_size: int = 16) -> bytes:
    """Return `data` with valid PKCS#7 padding removed, or raise ValueError."""
    raise NotImplementedError("Complete the independent padding warmup")
