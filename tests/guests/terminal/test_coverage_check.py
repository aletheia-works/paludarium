import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
SPEC = importlib.util.spec_from_file_location(
    "terminal_coverage_check", ROOT / "scripts/coverage-check.py"
)
C = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(C)


class CoverageCheck(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="terminal-check-", dir=ROOT / "target")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.scope = json.loads(C.SCOPE.read_bytes())
        paths = [path for group in self.scope["groups"].values() for path in group]
        prefix = self.scope["allowed_sf_prefixes"][0]
        self.lcov = "".join(
            "SF:" + prefix + n + "\nDA:1,1\nLF:2\nLH:2\nend_of_record\n" for n in paths
        ).encode()
        raw_json = {
            "type": "llvm.coverage.json.export",
            "data": [
                {
                    "files": [
                        {
                            "filename": prefix + n,
                            "summary": {"lines": {"count": 2, "covered": 2, "percent": 100}},
                        }
                        for n in paths
                    ]
                }
            ],
        }
        raws = {
            "lcov": self.lcov,
            "json": json.dumps(raw_json).encode(),
            "report": b"TOTAL 1 0 100% 1 0 100% 46 0 100%\n",
            "profdata": b"profile",
        }
        files = {}
        for k, raw in raws.items():
            (self.root / k).write_bytes(raw)
            files[k] = dict(path=k, sha256=C.sha(raw))
        (self.root / "binary").write_bytes(b"instrumented")
        snapshots = {}
        for n in paths:
            p = self.root / n
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(b"source")
            snapshots[n] = C.sha(b"source")
        for n in ("Cargo.lock", "fuzz/Cargo.lock"):
            p = self.root / n
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(b"lock")
        commands = [
            dict(
                argv=["cargo", "test", "--test", "diff_terminal"],
                tests=1,
                ignored=0,
                exit=0,
                timed_out=False,
            )
        ]
        for kind in ("lcov", "json", "report"):
            commands.append(
                dict(
                    argv=["cargo", "llvm-cov", "--" + kind],
                    export=kind,
                    exit=0,
                    timed_out=False,
                    profdata_sha256=files["profdata"]["sha256"],
                    binary_hashes=[C.sha(b"instrumented")],
                )
            )
        self.evidence = dict(
            schema=1,
            head="1" * 40,
            official=dict(
                head="1" * 40,
                repository="Marukome0743/paludarium",
                run=1,
                job=2,
                artifact=3,
                artifact_digest="sha256:" + "2" * 64,
            ),
            compiler=dict(
                llvm="23.1.3", rustc_verbose="pinned", cargo_llvm_cov="pinned", flags=["coverage"]
            ),
            source_prefix=prefix,
            source_before=snapshots,
            source_after=dict(snapshots),
            locks={n: C.sha(b"lock") for n in ("Cargo.lock", "fuzz/Cargo.lock")},
            commands=commands,
            files=files,
            binaries=[dict(path="binary", sha256=C.sha(b"instrumented"))],
        )

    def check(self):
        return C.validate(self.lcov, self.scope, self.evidence, self.root, self.root)

    def test_summary_diff_is_not_da_redefinition(self):
        r = self.check()
        self.assertEqual(r["groups"]["original13"]["lines"], 26)
        self.assertEqual(next(iter(r["files"].values()))["da_lines"], 1)

    def test_missing_sf(self):
        self.lcov = self.lcov.split(b"end_of_record\n", 1)[1]
        self.evidence["files"]["lcov"]["sha256"] = C.sha(self.lcov)
        (self.root / "lcov").write_bytes(self.lcov)
        with self.assertRaises(ValueError):
            self.check()

    def test_duplicate_sf(self):
        with self.assertRaises(ValueError):
            C.parse_lcov(self.lcov + self.lcov, self.evidence["source_prefix"])

    def test_negative_count(self):
        with self.assertRaises(ValueError):
            C.parse_lcov(self.lcov.replace(b"DA:1,1", b"DA:1,-1"), self.evidence["source_prefix"])

    def test_duplicate_da(self):
        with self.assertRaises(ValueError):
            C.parse_lcov(
                self.lcov.replace(b"DA:1,1", b"DA:1,1\nDA:1,2"), self.evidence["source_prefix"]
            )

    def test_other_head(self):
        self.evidence["official"]["head"] = "3" * 40
        with self.assertRaises(ValueError):
            self.check()

    def test_changed_source(self):
        (self.root / next(iter(self.evidence["source_before"]))).write_bytes(b"changed")
        with self.assertRaises(ValueError):
            self.check()

    def test_changed_lock(self):
        (self.root / "Cargo.lock").write_bytes(b"changed")
        with self.assertRaises(ValueError):
            self.check()

    def test_wrong_compiler(self):
        self.evidence["compiler"]["llvm"] = "other"
        with self.assertRaises(ValueError):
            self.check()

    def test_zero_diff(self):
        self.evidence["commands"][0]["tests"] = 0
        with self.assertRaises(ValueError):
            self.check()

    def test_ignored_diff(self):
        self.evidence["commands"][0]["ignored"] = 1
        with self.assertRaises(ValueError):
            self.check()

    def test_missing_profile(self):
        (self.root / "profdata").unlink()
        with self.assertRaises(ValueError):
            self.check()

    def test_raw_digest(self):
        self.evidence["files"]["json"]["sha256"] = "0" * 64
        with self.assertRaises(ValueError):
            self.check()

    def test_export_profile_substitution(self):
        self.evidence["commands"][1]["profdata_sha256"] = "0" * 64
        with self.assertRaises(ValueError):
            self.check()

    def test_scope_floor(self):
        self.scope["floor_percent"] = 79
        with self.assertRaises(ValueError):
            self.check()

    def replace_raw(self, kind, raw):
        (self.root / kind).write_bytes(raw)
        self.evidence["files"][kind]["sha256"] = C.sha(raw)

    def test_one_group_below80_not_hidden_by_other(self):
        text = self.lcov.decode()
        for n in self.scope["groups"]["original13"]:
            block = "SF:" + self.evidence["source_prefix"] + n + "\nDA:1,1\nLF:2\nLH:2"
            text = text.replace(block, block[:-1] + "1")
        self.lcov = text.encode()
        self.replace_raw("lcov", self.lcov)
        j = json.loads((self.root / "json").read_bytes())
        for row in j["data"][0]["files"]:
            if (
                row["filename"][len(self.evidence["source_prefix"]) :]
                in self.scope["groups"]["original13"]
            ):
                row["summary"]["lines"].update(covered=1, percent=50)
        self.replace_raw("json", json.dumps(j).encode())
        self.replace_raw("report", b"TOTAL 1 0 100% 1 0 100% 46 13 71.74%\n")
        with self.assertRaisesRegex(ValueError, "one U9 group"):
            self.check()

    def test_json_summary_difference(self):
        j = json.loads((self.root / "json").read_bytes())
        j["data"][0]["files"][0]["summary"]["lines"]["count"] = 3
        self.replace_raw("json", json.dumps(j).encode())
        with self.assertRaisesRegex(ValueError, "summary difference"):
            self.check()

    def test_report_difference(self):
        self.replace_raw("report", b"TOTAL 1 0 100% 1 0 100% 45 0 100%\n")
        with self.assertRaisesRegex(ValueError, "total mismatch"):
            self.check()

    def test_command_failure(self):
        self.evidence["commands"][0]["exit"] = 1
        with self.assertRaises(ValueError):
            self.check()

    def test_command_timeout(self):
        self.evidence["commands"][0]["timed_out"] = True
        with self.assertRaises(ValueError):
            self.check()

    def test_unknown_prefix(self):
        with self.assertRaises(ValueError):
            C.parse_lcov(self.lcov, b"/other/".decode())

    def test_traversal(self):
        with self.assertRaises(ValueError):
            C.relative("a/../Cargo.lock")

    def test_bool_exit_not_zero(self):
        self.evidence["commands"][0]["exit"] = False
        with self.assertRaises(ValueError):
            self.check()

    def test_bool_ignore_not_zero(self):
        self.evidence["commands"][0]["ignored"] = False
        with self.assertRaises(ValueError):
            self.check()

    def test_bool_test_count(self):
        self.evidence["commands"][0]["tests"] = True
        with self.assertRaises(ValueError):
            self.check()

    def test_nan_json_percentage(self):
        j = json.loads((self.root / "json").read_bytes())
        j["data"][0]["files"][0]["summary"]["lines"]["percent"] = float("nan")
        self.replace_raw("json", json.dumps(j).encode())
        with self.assertRaises(ValueError):
            self.check()

    def test_da_overflow(self):
        with self.assertRaises(ValueError):
            C.parse_lcov(
                self.lcov.replace(b"DA:1,1", b"DA:1,18446744073709551616"),
                self.evidence["source_prefix"],
            )


if __name__ == "__main__":
    unittest.main()
