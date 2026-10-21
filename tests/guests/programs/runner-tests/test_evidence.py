import pathlib
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from evidence import digest, static_elf, validate


def elf(*, pie=False, interpreter=False, needed=False):
    image = bytearray(512)
    image[:7] = b"\x7fELF\x02\x01\x01"
    struct.pack_into("<HH", image, 16, 3 if pie else 2, 62)
    struct.pack_into("<Q", image, 32, 64)
    count = 1 + int(pie) + int(interpreter)
    struct.pack_into("<HH", image, 54, 56, count)
    struct.pack_into("<IIQQQQQQ", image, 64, 1, 5, 0, 0, 0, 512, 512, 4096)
    if pie:
        struct.pack_into("<IIQQQQQQ", image, 120, 2, 6, 400, 400, 0, 32, 32, 8)
        struct.pack_into("<qQ", image, 400, 1 if needed else 7, 0)
        struct.pack_into("<qQ", image, 416, 0, 0)
    if interpreter:
        struct.pack_into("<IIQQQQQQ", image, 64 + (count - 1) * 56, 3, 4, 450, 450, 0, 16, 16, 1)
    return image


class BuildEvidence(unittest.TestCase):
    def test_push_never_runs_diagnostic_or_formal_measurement(self):
        root = pathlib.Path(__file__).resolve().parents[4]
        # u14-cost-diagnostic.yml was removed in the CI cleanup, so no push can run it.
        self.assertFalse((root / ".github/workflows/u14-cost-diagnostic.yml").exists())
        acceptance = (root / ".github/workflows/jit-wasm-programs.yml").read_text()
        # The frozen performance measurement runs only by hand or on the nightly schedule, never on push or pull_request.
        self.assertIn(
            "- name: Frozen paired full-probe performance\n"
            "        # Measured by hand before a release and by the nightly schedule (ci-config.md); never on push or pull_request.\n"
            "        if: matrix.environment == 'node' && (github.event_name == 'workflow_dispatch' || github.event_name == 'schedule')\n",
            acceptance,
        )

    def test_accepts_static_exec(self):
        self.assertTrue(static_elf(elf()))

    def test_accepts_self_relocating_static_pie(self):
        self.assertTrue(static_elf(elf(pie=True)))

    def test_rejects_external_interpreter(self):
        with self.assertRaisesRegex(ValueError, "interpreter"):
            static_elf(elf(pie=True, interpreter=True))

    def test_rejects_needed_library_without_interpreter(self):
        with self.assertRaisesRegex(ValueError, "DT_NEEDED"):
            static_elf(elf(pie=True, needed=True))

    def test_rejects_wrong_architecture(self):
        data = elf()
        struct.pack_into("<H", data, 18, 183)
        with self.assertRaisesRegex(ValueError, "x86-64"):
            static_elf(data)

    def test_rejects_truncated_dynamic_table(self):
        data = elf(pie=True)
        struct.pack_into("<Q", data, 120 + 32, 31)
        with self.assertRaisesRegex(ValueError, "dynamic table"):
            static_elf(data)

    def test_rejects_tampered_binary_hash(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            for name in ("probe", "aube"):
                (root / name).write_bytes(elf())
            receipt = {
                "exit": 0,
                "source_unchanged": True,
                "binaries": {n: {"sha256": digest(root / n)} for n in ("probe", "aube")},
            }
            (root / "aube").write_bytes(b"tampered")
            with self.assertRaisesRegex(ValueError, "hash differs"):
                validate(root, receipt)
