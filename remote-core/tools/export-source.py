#!/usr/bin/env python3
"""Materialize a candidate standalone source tree from committed Git objects.

No repositories are created and no builds or tests are run. The exported
workspace remains experimental and is not a license clearance or a release.
"""
import argparse
import hashlib
import io
import os
from pathlib import Path, PurePosixPath
import subprocess
import sys
import tarfile

SOURCE = Path(__file__).resolve().parents[2]
BASE = "23e5bb471a040d62f0a6ad52591fb30784265b73"
COMMON = "fae47e024dd83cef6aaecde0aa7d11731df11649"
SOURCE_PATHS = ["LICENCE", "Cargo.lock", "libs/base", "libs/scrap", "libs/enigo", "libs/libxdo-sys-stub"]


def git(repo, *args):
    return subprocess.check_output(["git", "-C", str(repo), *args])


def archive(repo, commit, paths=(), prefix=None):
    cmd = ["archive", "--format=tar"]
    if prefix:
        cmd.append(f"--prefix={prefix}")
    return git(repo, *cmd, commit, *paths)


def unpack(data, destination):
    # Source is restricted to committed Git trees. Reject archive links and
    # traversal even so; do not let a crafted tree write outside the export.
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:") as bundle:
        for item in bundle:
            parts = PurePosixPath(item.name).parts
            if not parts or item.name.startswith("/") or any(part in (".", "..") for part in parts):
                raise ValueError(f"unsafe archive path: {item.name!r}")
            if not (item.isfile() or item.isdir()):
                raise ValueError(f"unsupported archive entry: {item.name!r}")
            out = destination.joinpath(*parts)
            if item.isdir():
                out.mkdir(parents=True, exist_ok=True)
            else:
                out.parent.mkdir(parents=True, exist_ok=True)
                src = bundle.extractfile(item)
                if src is None:
                    raise ValueError(f"missing archive data: {item.name!r}")
                # 'xb' prevents an archive from silently replacing earlier files.
                with out.open("xb") as target:
                    while chunk := src.read(1024 * 1024):
                        target.write(chunk)
                out.chmod(item.mode & 0o777)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path, help="a new output directory outside the RustDesk checkout")
    parser.add_argument("--core-commit", default="HEAD", help="committed prototype revision (default: HEAD)")
    args = parser.parse_args()
    destination = args.output.expanduser().resolve()
    if destination == SOURCE or SOURCE in destination.parents:
        parser.error("output must be outside the RustDesk checkout")
    if destination.exists():
        parser.error("output must not already exist")
    if not destination.parent.is_dir():
        parser.error("output parent directory must already exist")

    core = git(SOURCE, "rev-parse", "--verify", f"{args.core_commit}^{{commit}}").decode().strip()
    # A core revision must derive from the recorded RustDesk baseline.
    subprocess.run(["git", "-C", str(SOURCE), "merge-base", "--is-ancestor", BASE, core], check=True)
    submodule = git(SOURCE, "ls-tree", BASE, "libs/hbb_common").decode().strip().split()
    if len(submodule) != 4 or submodule[0:2] != ["160000", "commit"] or submodule[2] != COMMON:
        raise ValueError("baseline hbb_common submodule commit differs from recorded provenance")
    common_repo = SOURCE / "libs/hbb_common"
    if not (common_repo / "Cargo.toml").is_file():
        raise ValueError("initialize the hbb_common submodule before exporting")

    # Capture exact objects, not uncommitted working-tree files. A missing
    # object/path is a hard failure, before creating the destination.
    source_tar = archive(SOURCE, BASE, SOURCE_PATHS)
    core_tar = archive(SOURCE, core, ["remote-core"])
    common_tar = archive(common_repo, COMMON, prefix="libs/hbb_common/")
    destination.mkdir()
    try:
        unpack(source_tar, destination)
        unpack(core_tar, destination)
        unpack(common_tar, destination)
        # The pinned upstream lock is a resolution starting point. New prototype
        # crates are absent from it, so --locked is not expected to work yet.
        (destination / "remote-core/Cargo.lock").write_bytes((destination / "Cargo.lock").read_bytes())
        lines = [
            "# Export provenance — experimental, not a release", "",
            f"RustDesk source baseline: `{BASE}`",
            f"Prototype core commit: `{core}`",
            f"hbb_common submodule commit: `{COMMON}`", "",
            "Exported only committed files; uncommitted changes are not included.",
            "Source archives (SHA-256):", "",
            f"- RustDesk selected libraries and root files: `{hashlib.sha256(source_tar).hexdigest()}`",
            f"- remote-core workspace: `{hashlib.sha256(core_tar).hexdigest()}`",
            f"- hbb_common: `{hashlib.sha256(common_tar).hexdigest()}`", "",
            "Run Cargo from `remote-core/`. The inherited lockfile is a starting point,",
            "not a confirmed locked build; the new workspace may need resolution.",
            "No build, test, security review, or license clearance is implied.",
            "Original upstream notices are preserved; root `LICENCE` is AGPL-3.0.",
            "Third-party and per-file licensing still requires review before release.", "",
        ]
        (destination / "SOURCE_PROVENANCE.md").write_text("\n".join(lines), encoding="utf-8")
    except Exception:
        # Leave partial output for inspection; never delete user files here.
        print(f"Export failed; incomplete directory left at {destination}", file=sys.stderr)
        raise
    print(f"Exported experimental source tree to {destination}")
    print("This is not yet a tested, audited, or independently versioned repository.")


if __name__ == "__main__":
    main()
