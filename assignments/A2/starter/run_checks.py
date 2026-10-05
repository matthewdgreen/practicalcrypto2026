#!/usr/bin/env python3
"""Run public checks. Unimplemented student stubs are expected to fail."""

# (The docstring above is also the `--help` description, so the longer
# overview lives in this comment.)
#
# What this file is for: one entry point for the four public check groups
# (README §3, handout §6):
#
#     python run_checks.py scaffold          the supplied kit works (no student code needed)
#     python run_checks.py warmup            Part 0: pkcs7_pad / pkcs7_unpad
#     python run_checks.py review_eligible   files + interface + warmup + JM1 both roles
#     python run_checks.py client_smoke      JM1 and JM2, both roles, edge-case texts
#
# Where it sits: it loads tests from `tests/` and runs them with unittest.
# `tests/test_scaffold.py` exercises jmessage_support/; `tests/student_checks.py`
# drives your `protocol.Client` through the in-memory `testing.Network`.
#
# What to learn: passing these checks means two copies of your client agree
# with each other. It does not mean you agree with the specification, because
# a mistake made the same way on both sides cancels out. `--peer-module` swaps
# the second copy for an independent implementation once staff publish one.

import argparse
from pathlib import Path
import sys
import unittest


def main(argv=None):
    """Run one check group and return a process exit code.

    Args:
        argv: argument list for testing; defaults to sys.argv[1:].

    Returns:
        0 if every test in the group passed, otherwise 1.

    `--peer-module NAME` imports NAME and uses its `Client` as the peer in the
    exchange checks, instead of a second copy of your own `protocol.Client`.
    """
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("group", choices=("scaffold", "warmup", "review_eligible", "client_smoke"))
    parser.add_argument("--peer-module", help="optional staff-supplied independent Client module")
    args = parser.parse_args(argv)
    root = Path(__file__).resolve().parent
    loader = unittest.TestLoader()
    if args.group == "scaffold":
        suite = loader.discover(str(root / "tests"), pattern="test_scaffold*.py",
                                top_level_dir=str(root))
    else:
        # Imported only here, because these checks import your protocol.py and
        # padding.py; the scaffold group must work before those exist.
        from tests import student_checks as checks
        # A module-level setting read by `student_checks.exchange`.
        checks.PEER_MODULE = args.peer_module
        classes = {
            "warmup": [checks.WarmupChecks],
            "review_eligible": [checks.SubmissionChecks, checks.WarmupChecks, checks.JM1Checks],
            "client_smoke": [checks.JM1Checks, checks.JM2Checks],
        }[args.group]
        suite = unittest.TestSuite(loader.loadTestsFromTestCase(cls) for cls in classes)
        if args.group != "warmup":
            print("Peer: " + (args.peer_module
                              or "a second copy of your client (self-interoperability only)"),
                  file=sys.stderr, flush=True)
            print("These checks do not certify protocol security or independent conformance.",
                  file=sys.stderr, flush=True)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
