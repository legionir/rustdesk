#!/usr/bin/env python3
"""Conservatively inspect local Cargo path dependencies in a candidate export.

This is not Cargo metadata, dependency resolution, a build, a license/security
review, or a complete file-closure check. It does not evaluate cfg/features,
remote crates, build scripts, includes, workspace inheritance or native links.
Use on a trusted, quiescent tree with Python 3.11+. The script reads only.
"""
import argparse
from collections import deque
from pathlib import Path, PureWindowsPath
import sys
import tomllib

MAX_MANIFEST = 4 * 1024 * 1024
MAX_PACKAGES = 1024
SECTIONS = ("dependencies", "dev-dependencies", "build-dependencies")


def inside(root, path):
    resolved = path.resolve()
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise ValueError(f"path escapes candidate root: {path}") from exc
    return resolved


def read_manifest(root, directory):
    directory = inside(root, directory)
    # A manifest itself may be a symlink, not just the package directory.
    manifest = inside(root, directory / "Cargo.toml")
    if not manifest.is_file():
        raise ValueError(f"missing Cargo.toml: {directory.relative_to(root)}")
    if manifest.stat().st_size > MAX_MANIFEST:
        raise ValueError(f"manifest too large: {manifest.relative_to(root)}")
    with manifest.open("rb") as source:
        return directory, tomllib.load(source)


def dep_paths(table, label):
    if not isinstance(table, dict):
        raise ValueError(f"malformed dependency table: {label}")
    for name, value in table.items():
        if not isinstance(value, dict):
            continue
        if value.get("workspace") is True:
            # Guessing the inherited workspace base can silently accept the
            # wrong path; require Cargo or explicit support rather than guess.
            raise ValueError(f"workspace dependency inheritance unsupported: {label}.{name}")
        if "path" in value:
            if not isinstance(value["path"], str) or not value["path"]:
                raise ValueError(f"invalid path dependency: {label}.{name}")
            yield f"{label}.{name}", value["path"]


def dependencies(manifest):
    for section in SECTIONS:
        yield from dep_paths(manifest.get(section, {}), section)
    target = manifest.get("target", {})
    if not isinstance(target, dict):
        raise ValueError("malformed target table")
    for cfg, config in target.items():
        if not isinstance(config, dict):
            raise ValueError("malformed target entry")
        for section in SECTIONS:
            yield from dep_paths(config.get(section, {}), f"target.{cfg}.{section}")
    for table_name in ("patch", "replace"):
        table = manifest.get(table_name, {})
        if not isinstance(table, dict):
            raise ValueError(f"malformed {table_name} table")
        if table_name == "patch":
            for registry, packages in table.items():
                yield from dep_paths(packages, f"patch.{registry}")
        else:
            yield from dep_paths(table, "replace")
    workspace = manifest.get("workspace", {})
    if not isinstance(workspace, dict):
        raise ValueError("malformed workspace table")
    yield from dep_paths(workspace.get("dependencies", {}), "workspace.dependencies")


def portable_relative(path):
    return bool(path) and not Path(path).is_absolute() and not PureWindowsPath(path).drive and "\\" not in path


def audit(root):
    root = Path(root)
    if root.is_symlink() or not root.is_dir():
        raise ValueError("candidate root must be a non-symlink directory")
    root = root.resolve()
    workspace_dir, workspace_manifest = read_manifest(root, root / "remote-core")
    workspace = workspace_manifest.get("workspace")
    if not isinstance(workspace, dict) or not isinstance(workspace.get("members"), list):
        raise ValueError("workspace members not explicitly listed")
    exclusions = workspace.get("exclude", [])
    if not isinstance(exclusions, list) or len(exclusions) > MAX_PACKAGES:
        raise ValueError("invalid workspace exclusions")
    excluded = []
    for item in exclusions:
        if not isinstance(item, str) or not portable_relative(item) or any(c in item for c in "*?[]"):
            raise ValueError("workspace exclusion globs or nonportable paths are not supported")
        path = inside(root, workspace_dir / item)
        if path == workspace_dir or workspace_dir not in path.parents:
            raise ValueError("workspace exclusion must be within the workspace")
        excluded.append(path)
    members = workspace["members"]
    if not members or len(members) > MAX_PACKAGES:
        raise ValueError("invalid workspace member count")
    queue = deque([workspace_dir])
    for member in members:
        if not isinstance(member, str) or not portable_relative(member) or any(c in member for c in "*?[]"):
            raise ValueError("workspace member globs are not supported")
        path = inside(root, workspace_dir / member)
        if any(path == excluded_path or excluded_path in path.parents for excluded_path in excluded):
            raise ValueError("explicit workspace member is excluded")
        queue.append(path)
    visited = set()
    edges = 0
    while queue:
        directory = inside(root, queue.popleft())
        if directory in visited:
            continue
        if len(visited) >= MAX_PACKAGES:
            raise ValueError("too many local packages")
        directory, manifest = read_manifest(root, directory)
        visited.add(directory)
        package = manifest.get("package", {})
        if not isinstance(package, dict) or "workspace" in package:
            raise ValueError("explicit package workspace is not interpreted by this auditor")
        for label, relative in dependencies(manifest):
            # Do not accept absolute paths even when they happen to be inside
            # the current tree: they would not remain portable when relocated.
            if not portable_relative(relative):
                raise ValueError(f"non-portable {label} in {directory.relative_to(root)}")
            queue.append(inside(root, directory / relative))
            edges += 1
    return len(visited), edges


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path, help="candidate root containing remote-core and libs")
    args = parser.parse_args()
    try:
        packages, edges = audit(args.root)
    except (OSError, ValueError, tomllib.TOMLDecodeError) as error:
        print(f"Local Cargo path audit failed: {error}", file=sys.stderr)
        return 1
    print(f"Inspected {packages} local manifests and {edges} path edges; not a build or dependency resolution")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
