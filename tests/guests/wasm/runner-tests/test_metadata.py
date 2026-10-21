import importlib.util
import os
import pathlib
import stat
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[4]
SPEC = importlib.util.spec_from_file_location(
    "wasm_metadata", ROOT / "tests/guests/wasm/fixture_metadata.py"
)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class MetadataTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.temporary.name)
        self.addCleanup(self.temporary.cleanup)

    def test_empty_root_directory(self):
        self.assertEqual(MODULE.snapshot_metadata(self.root)["."]["kind"], "directory")

    def test_file_hash(self):
        (self.root / "file").write_bytes(b"")
        self.assertEqual(
            MODULE.snapshot_metadata(self.root)["file"]["sha256"],
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        )
        self.assertEqual(MODULE.snapshot_metadata(self.root)["file"]["content_base64"], "")

    def test_content_capture_is_bounded(self):
        (self.root / "small").write_bytes(b"\x00\xff")
        (self.root / "large").write_bytes(b"x" * 65537)
        result = MODULE.snapshot_metadata(self.root)
        self.assertEqual(result["small"]["content_base64"], "AP8=")
        self.assertNotIn("content_base64", result["large"])

    def test_permissions(self):
        path = self.root / "file"
        path.write_bytes(b"a")
        path.chmod(0o644)
        self.assertEqual(MODULE.snapshot_metadata(self.root)["file"]["mode"], 0o644)

    def test_symlink_target_without_following(self):
        (self.root / "link").symlink_to("missing")
        self.assertEqual(
            MODULE.snapshot_metadata(self.root)["link"],
            {
                "kind": "symlink",
                "mode": stat.S_IMODE((self.root / "link").lstat().st_mode),
                "target": "missing",
                "mtime_ns": (self.root / "link").lstat().st_mtime_ns,
            },
        )

    def test_initial_epoch_preparation(self):
        (self.root / "file").write_bytes(b"content")
        receipt = MODULE.prepare_epoch_fixture(self.root)
        self.assertEqual(receipt["paths"], ["file"])
        self.assertEqual(MODULE.snapshot_metadata(self.root)["file"]["mtime_ns"], 0)

    def test_nested_directory(self):
        (self.root / "nested").mkdir()
        self.assertEqual(MODULE.snapshot_metadata(self.root)["nested"]["kind"], "directory")

    def test_hardlink_identity(self):
        source = self.root / "a"
        source.write_bytes(b"content")
        os.link(source, self.root / "b")
        result = MODULE.snapshot_metadata(self.root)
        self.assertEqual(result["a"]["identity"], result["b"]["identity"])
        self.assertEqual(result["b"]["links"], 2)

    def test_equal_content_does_not_imply_hardlink(self):
        for name in ("a", "b"):
            (self.root / name).write_bytes(b"same")
        result = MODULE.snapshot_metadata(self.root)
        self.assertNotEqual(result["a"]["identity"], result["b"]["identity"])
