#!/usr/bin/env python3
"""Verify the exported file list and SHA-256 hashes; not a signature or audit.

Run on a trusted, quiescent local directory. Concurrent modifications, an
untrusted manifest, permissions, provenance authenticity and build correctness
are outside this check's scope. No files are modified.
"""
import argparse
import hashlib
import os
from pathlib import Path
import re
import stat
import sys

MANIFEST = "SOURCE_MANIFEST.sha256"
MAX_MANIFEST_BYTES = 16 * 1024 * 1024
RECORD = re.compile(r"^([0-9a-f]{64})  (.+)$")


def safe_name(name):
    parts = name.split("/")
    return (all(part and part not in (".", "..") for part in parts)
            and not any(c in name for c in "\\:\n\r\0")
            and name.splitlines() == [name]
            and name != MANIFEST)


def verify(root):
    root = Path(root)
    if root.is_symlink() or not root.is_dir():
        raise ValueError("export root must be a non-symlink directory")
    root = root.resolve()
    manifest = root / MANIFEST
    info = manifest.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_MANIFEST_BYTES:
        raise ValueError("manifest must be a bounded regular file")
    expected = {}
    for line in manifest.read_text(encoding="utf-8").splitlines():
        match = RECORD.fullmatch(line)
        if not match or not safe_name(match.group(2)):
            raise ValueError("invalid manifest record")
        digest, name = match.groups()
        if name in expected:
            raise ValueError(f"duplicate manifest entry: {name!r}")
        expected[name] = digest
    if not expected:
        raise ValueError("empty manifest")
    actual = set()
    for directory, dirs, files in os.walk(root, followlinks=False):
        for name in dirs:
            path = Path(directory) / name
            if path.is_symlink() or not path.is_dir():
                raise ValueError(f"unexpected directory entry: {path.relative_to(root)}")
        for name in files:
            path = Path(directory) / name
            relative = path.relative_to(root).as_posix()
            if relative == MANIFEST:
                continue
            if not safe_name(relative) or not stat.S_ISREG(path.lstat().st_mode):
                raise ValueError(f"unexpected file entry: {relative!r}")
            if relative not in expected:
                raise ValueError(f"unlisted file: {relative!r}")
            digest = hashlib.sha256()
            with path.open("rb") as source:
                while chunk := source.read(1024 * 1024):
                    digest.update(chunk)
            if digest.hexdigest() != expected[relative]:
                raise ValueError(f"hash mismatch: {relative!r}")
            actual.add(relative)
    missing = expected.keys() - actual
    if missing:
        raise ValueError(f"missing file: {sorted(missing)[0]!r}")
    return len(actual)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path, help="export root containing SOURCE_MANIFEST.sha256")
    args = parser.parse_args()
    try:
        count = verify(args.root)
    except (OSError, UnicodeError, ValueError) as error:
        print(f"Export verification failed: {error}", file=sys.stderr)
        return 1
    print(f"Verified {count} file hashes and manifest membership; no authenticity or build assurance")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
