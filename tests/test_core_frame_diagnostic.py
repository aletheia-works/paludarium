import importlib.util
import subprocess
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

SPEC = importlib.util.spec_from_file_location(
    "frame_diagnostic", Path(__file__).parents[1] / "scripts/core-frame-diagnostic.py"
)
diagnostic = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(diagnostic)


class FrameDiagnosticTests(unittest.TestCase):
    def test_wrong_archive_rejected_before_extraction(self):
        with (
            patch.object(Path, "read_bytes", return_value=b"not original"),
            self.assertRaisesRegex(ValueError, "archive digest mismatch"),
        ):
            diagnostic.original(Path("unused"))

    def test_timeout_remains_failure_and_preserves_output(self):
        child = MagicMock(pid=123)
        child.communicate.side_effect = [
            subprocess.TimeoutExpired("fixture", 30),
            (b"partial", b"error"),
        ]
        with (
            patch.object(subprocess, "Popen", return_value=child),
            patch.object(diagnostic.os, "killpg") as kill,
        ):
            out, err, code, timeout, elapsed = diagnostic.bounded(["fixture"], environment={})
        kill.assert_called_once_with(123, diagnostic.signal.SIGKILL)
        self.assertEqual(child.communicate.call_count, 2)
        self.assertEqual((out, err, code, timeout), (b"partial", b"error", None, True))
        self.assertGreaterEqual(elapsed, 0)

    def test_signal_and_empty_environment_preserved(self):
        child = MagicMock(returncode=-11)
        child.communicate.return_value = (b"", b"")
        with patch.object(subprocess, "Popen", return_value=child) as run:
            self.assertEqual(
                diagnostic.bounded(["fixture"], environment={}, executable="/original")[2], -11
            )
        self.assertEqual(run.call_args.kwargs["env"], {})
        child.communicate.assert_called_once_with(timeout=30)
        self.assertTrue(run.call_args.kwargs["start_new_session"])
        self.assertEqual(run.call_args.kwargs["executable"], "/original")

    def test_debugger_direct_exec_and_normal_exit(self):
        commands = diagnostic.capture_commands()
        self.assertNotIn("set exec-wrapper", commands)
        self.assertNotIn("exec-wrapper env", commands)
        self.assertIn("set disable-randomization off\n", commands)
        self.assertIn("if gdb.selected_inferior().threads():", commands)
        self.assertIn("DIAGNOSTIC_NORMAL_EXIT_NO_REGISTERS", commands)
        self.assertIn("'info registers', 'x/32gx $rsp', 'x/16i $rip', 'bt'", commands)


if __name__ == "__main__":
    unittest.main()
