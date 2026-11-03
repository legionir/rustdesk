"""Deferred fixtures; no Cargo, native dependencies or network are used."""
import importlib.util
from pathlib import Path
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "audit-path-dependencies.py"
spec = importlib.util.spec_from_file_location("audit_paths", SCRIPT)
audit_paths = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit_paths)


class AuditTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.write("remote-core/Cargo.toml", '[workspace]\nmembers = ["app"]\n[patch.crates-io]\nlocal = {path = "../libs/local"}\n')
        self.write("remote-core/app/Cargo.toml", '[package]\nname = "app"\nversion = "0.0.0"\n[target.\'cfg(windows)\'.dependencies]\nlocal = {path = "../../libs/local"}\n')
        self.write("libs/local/Cargo.toml", '[package]\nname = "local"\nversion = "0.0.0"\n')

    def tearDown(self):
        self.temp.cleanup()

    def write(self, relative, contents):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(contents, encoding="utf-8")

    def test_target_and_patch_paths_are_traversed(self):
        self.assertEqual(audit_paths.audit(self.root), (3, 2))
        (self.root / "libs/local/Cargo.toml").unlink()
        with self.assertRaisesRegex(ValueError, "missing Cargo.toml"):
            audit_paths.audit(self.root)

    def test_escape_and_absolute_paths_are_rejected(self):
        for path in ("../../../outside", "/absolute", "C:/absolute", "C:relative", "dir\\\\item"):
            self.write("remote-core/app/Cargo.toml", f'[package]\nname = "app"\nversion = "0.0.0"\n[dependencies]\nx = {{path = "{path}"}}\n')
            with self.assertRaises(ValueError):
                audit_paths.audit(self.root)

    def test_inheritance_and_globs_fail_instead_of_guessing(self):
        self.write("remote-core/app/Cargo.toml", '[package]\nname = "app"\nversion = "0.0.0"\n[dependencies]\nx = {workspace = true}\n')
        with self.assertRaisesRegex(ValueError, "inheritance unsupported"):
            audit_paths.audit(self.root)
        self.write("remote-core/Cargo.toml", '[workspace]\nmembers = ["app*"]\n')
        with self.assertRaisesRegex(ValueError, "globs"):
            audit_paths.audit(self.root)

    def test_manifest_symlink_escape_fails(self):
        outside = tempfile.TemporaryDirectory()
        try:
            foreign = Path(outside.name) / "Cargo.toml"
            foreign.write_text('[package]\nname = "foreign"\nversion = "0.0.0"\n', encoding="utf-8")
            manifest = self.root / "libs/local/Cargo.toml"
            manifest.unlink()
            try:
                manifest.symlink_to(foreign)
            except OSError as error:
                self.skipTest(f"symlink creation unavailable: {error}")
            with self.assertRaisesRegex(ValueError, "escapes"):
                audit_paths.audit(self.root)
        finally:
            outside.cleanup()

    def test_symlink_escape_fails(self):
        outside = tempfile.TemporaryDirectory()
        try:
            try:
                (self.root / "remote-core/link").symlink_to(outside.name, target_is_directory=True)
            except OSError as error:
                self.skipTest(f"symlink creation unavailable: {error}")
            self.write("remote-core/Cargo.toml", '[workspace]\nmembers = ["link"]\n')
            with self.assertRaisesRegex(ValueError, "escapes"):
                audit_paths.audit(self.root)
        finally:
            outside.cleanup()


if __name__ == "__main__":
    unittest.main()
