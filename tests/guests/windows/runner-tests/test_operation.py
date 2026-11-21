import pathlib
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / "tests/guests/windows"))
sys.path.insert(1, str(ROOT / "tests/guests/programs"))
import coreutils  # noqa: E402
import operation  # noqa: E402


def guest_run(directory, fixture, write):
    """A stand-in for the Rust child: it records the modes before the guest
    runs, as the harness does, and then lets `write` change the fixture."""

    def fake(command, *, cwd, env):
        modes = coreutils.inputs(fixture)
        (directory / "fixture-modes").write_text(
            "".join(path + "\t" + str(mode) + "\n" for path, mode in modes.items()),
            encoding="utf-8",
        )
        write(fixture)
        for name, text in (("stdout", ""), ("stderr", ""), ("exit", "0"), ("seconds", "0.1")):
            (directory / name).write_text(text, encoding="utf-8")
        (directory / "stop").write_text("", encoding="utf-8")
        return {"exit": 0, "timed_out": False}

    return fake


class OperationTests(unittest.TestCase):
    def check(self, write):
        with tempfile.TemporaryDirectory() as scratch:
            scratch = pathlib.Path(scratch)
            fixture = coreutils.fresh_fixture(scratch / "fixture")
            given = coreutils.inputs(fixture)
            directory = scratch / "operation"
            with patch.object(operation, "run", guest_run(directory, fixture, write)):
                row = operation.operation(
                    scratch / "harness.exe",
                    scratch / "coreutils",
                    ["cp", "fruits.txt", "docs/copy.txt"],
                    directory,
                    {},
                    fixture,
                    mounted=True,
                    inputs=coreutils.inputs,
                    program="/coreutils",
                )
            self.assertEqual(row["fixture_input_modes"], given)
            return row

    def test_a_created_file_is_not_an_input(self):
        def cp(fixture):
            (fixture / "app/docs/copy.txt").write_bytes((fixture / "app/fruits.txt").read_bytes())

        row = self.check(cp)
        self.assertIn("app/docs/copy.txt", row["filesystem"])

    def test_a_moved_input_is_still_compared_as_given(self):
        def mv(fixture):
            (fixture / "app/table.csv").rename(fixture / "app/docs/moved.csv")

        row = self.check(mv)
        self.assertNotIn("app/table.csv", row["filesystem"])


if __name__ == "__main__":
    unittest.main()
