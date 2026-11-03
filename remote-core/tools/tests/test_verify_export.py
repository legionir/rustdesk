"""Deferred synthetic fixtures for candidate verification; not a release audit."""
import hashlib
import importlib.util
import pathlib
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("verify_export", pathlib.Path(__file__).parents[1] / "verify-export.py")
verify_export = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verify_export)


class VerifyExport(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.temp.name)
        self.file = self.root / "folder" / "file.txt"
        self.file.parent.mkdir()
        self.file.write_bytes(b"pinned content")
        self.digest = hashlib.sha256(b"pinned content").hexdigest()
        self.manifest = self.root / "SOURCE_MANIFEST.sha256"
        self.manifest.write_text(f"{self.digest}  folder/file.txt\n", encoding="utf-8")

    def tearDown(self):
        self.temp.cleanup()

    def test_complete_tree(self):
        self.assertEqual(verify_export.verify(self.root), 1)

    def test_changed_missing_and_extra_files(self):
        self.file.write_bytes(b"modified")
        with self.assertRaisesRegex(ValueError, "hash mismatch"):
            verify_export.verify(self.root)
        self.file.unlink()
        with self.assertRaisesRegex(ValueError, "missing file"):
            verify_export.verify(self.root)
        (self.root / "extra").write_bytes(b"extra")
        with self.assertRaisesRegex(ValueError, "unlisted file"):
            verify_export.verify(self.root)

    def test_duplicate_and_traversal(self):
        line = f"{self.digest}  folder/file.txt\n"
        self.manifest.write_text(line + line, encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "duplicate"):
            verify_export.verify(self.root)
        for name in ("../escape", "/absolute", "C:/file", "a\\b", "a/./b", "a//b", "SOURCE_MANIFEST.sha256"):
            self.manifest.write_text(f"{self.digest}  {name}\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "invalid manifest"):
                verify_export.verify(self.root)

    def test_symlink_is_never_followed(self):
        self.file.unlink()
        try:
            self.file.symlink_to(self.manifest)
        except (OSError, NotImplementedError):
            self.skipTest("platform does not permit symlinks")
        with self.assertRaisesRegex(ValueError, "unexpected file"):
            verify_export.verify(self.root)


if __name__ == "__main__":
    unittest.main()
