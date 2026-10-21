"""Input-mode records cannot hide fixture metadata mismatches."""

import contextlib
import io
import json
import pathlib
import shutil
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
import metadata


class MetadataTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.fixture = pathlib.Path(self.temporary.name) / "fixture"
        shutil.copytree(metadata.HERE / "fixtures", self.fixture)

    def test_exact_guest_paths_and_0644(self):
        self.assertEqual(
            metadata.fixture_inputs(self.fixture),
            {
                "/package.json": 0o644,
                "/filedep/package.json": 0o644,
                "/outside/linked/package.json": 0o644,
            },
        )

    def test_executable_fixture_rejected(self):
        (self.fixture / "app/filedep/package.json").chmod(0o755)
        with self.assertRaises(ValueError):
            metadata.fixture_inputs(self.fixture)

    def test_readonly_fixture_rejected(self):
        (self.fixture / "outside/linked/package.json").chmod(0o444)
        with self.assertRaises(ValueError):
            metadata.fixture_inputs(self.fixture)

    def test_missing_fixture_rejected(self):
        (self.fixture / "app/package.json").unlink()
        with self.assertRaises(FileNotFoundError):
            metadata.fixture_inputs(self.fixture)

    def test_generated_packages_do_not_replace_initial_inputs(self):
        generated = self.fixture / "app/node_modules/package/package.json"
        generated.parent.mkdir(parents=True)
        generated.write_text("{}")
        self.assertEqual(len(metadata.fixture_inputs(self.fixture)), 3)

    def test_native_child_retains_regular_type_bits(self):
        stream = io.StringIO()
        with contextlib.redirect_stdout(stream):
            metadata.child(self.fixture)
        record = json.loads(stream.getvalue())
        self.assertEqual(
            record["mode_boundaries"], {"493": 0o100755, "420": 0o100644, "0": 0o100000}
        )

    def test_unsupported_oracle_platform_rejected(self):
        with (
            mock.patch("metadata.platform.system", return_value="Windows"),
            self.assertRaises(RuntimeError),
        ):
            metadata.observe(self.fixture / "unused.json")


if __name__ == "__main__":
    unittest.main()
