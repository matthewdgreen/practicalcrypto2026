#!/usr/bin/env python3
"""Package Part 0/1 source and written files; never collect the local identity store."""

# (The docstring above is also the `--help` description, so the longer
# overview lives in this comment.)
#
# What this file is for: build `checkpoint.zip` for the client checkpoint
# (README §5, handout §7): the required files, plus any supporting .py modules
# you wrote, and nothing else.
#
# What to learn: packaging is a place where secrets leak. The rules below are
# an allowlist (only *.py files and the six required files), with explicit
# exclusions for the places secrets live (.jmessage/ holds your private key;
# virtual environments; checkpoint/ and exercises/). Symlinks are refused,
# because a symlink named helper.py could point at a file outside this
# directory, such as a key file, and zipfile would archive its target.
#
# What it deliberately does NOT do: it does not check that your written files
# are complete or that your code is correct, and it does not package the later
# Parts 2-3 exercises. Inspect the archive before you submit it.

import argparse
from pathlib import Path
import zipfile

# The six files every submission must contain (handout §7).
REQUIRED = ("protocol.py", "padding.py", "padding_first_attempt.py",
            "design.md", "written.md", "ai-usage.md")
# Directories never searched for source: VCS data, virtual environments, the
# local key store, caches, the public tests, and the folders packaged later.
SKIP_DIRS = {".git", ".venv", "venv", ".jmessage", "__pycache__", "tests", "checkpoint",
             "exercises"}
# Supplied top-level scripts that are part of the kit, not your submission.
DRIVERS = {"client.py", "local_relay.py", "check_environment.py", "run_checks.py",
           "package_submission.py"}


def source_files(root):
    """Yield every .py file under `root` that belongs in the submission.

    Args:
        root: the resolved starter directory (`Path`).

    Yields:
        `Path` objects for .py files outside hidden or skipped directories,
        excluding the supplied top-level drivers. `jmessage_support/` is
        included, so the archive imports on its own.

    Raises:
        ValueError: if a candidate file, or any directory between it and
            `root`, is a symbolic link.
    """
    for path in root.rglob("*.py"):
        relative = path.relative_to(root)
        # Check only the directory components (parts[:-1]); any hidden
        # directory (".anything") is skipped, not just those named above.
        if any(part.startswith(".") or part in SKIP_DIRS for part in relative.parts[:-1]):
            continue
        if len(relative.parts) == 1 and path.name in DRIVERS:
            continue
        if path.is_symlink() or any(parent.is_symlink() for parent in path.parents
                                    if parent != root.parent):
            raise ValueError(f"refusing symlinked source: {relative}")
        yield path


def package(root, output):
    """Write the submission archive and return how many files it contains.

    Args:
        root: the starter directory (`str` or `Path`).
        output: the archive path to create.

    Returns:
        The number of files written (`int`).

    Raises:
        ValueError: if a required file is missing or is a symlink, or a source
            file is symlinked.
        FileExistsError: if `output` already exists. Mode "x" refuses to
            overwrite, so an earlier archive (perhaps the one you submitted)
            is never silently replaced.
        OSError: for other file-system errors.

    Files are stored at the archive root under their paths relative to `root`,
    in sorted order, so the same inputs always give the same listing.
    """
    root = Path(root).resolve()
    output = Path(output)
    for name in REQUIRED:
        path = root / name
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"missing or symlinked {name}; complete the submission first")
    files = set(source_files(root)) | {root / name for name in REQUIRED}
    with zipfile.ZipFile(output, "x", compression=zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(files):
            archive.write(path, path.relative_to(root).as_posix())
    return len(files)


def main():
    """Command-line entry point: package this directory into `--output`."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("checkpoint.zip"))
    args = parser.parse_args()
    try:
        count = package(Path(__file__).resolve().parent, args.output)
    except (ValueError, OSError) as exc:
        parser.exit(1, f"Packaging failed: {exc}\n")
    print(f"Wrote {count} source/document files to {args.output}")
    print("Inspect the archive before submission. "
          "It excludes checkpoints, exercises, and local credentials.")
    print("The Parts 2–3 kit will supply final-submission packaging instructions.")


if __name__ == "__main__":
    main()
