"""Fail-closed dedicated U9 evidence aggregation. Never runs a test or guest."""

import argparse
import hashlib
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCOPE = ROOT / "tests/guests/u9/coverage-scope.json"


def need(value, message):
    if not value:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def read(path):
    need(
        path.is_file() and not any(p.is_symlink() for p in (path, *path.parents)),
        "missing or linked evidence: " + str(path),
    )
    return path.read_bytes()


def relative(name):
    need(
        isinstance(name, str)
        and name
        and not Path(name).is_absolute()
        and "\\" not in name
        and all(p not in ("", ".", "..") for p in name.split("/")),
        "unsafe relative path",
    )
    return name


def normalize(name, prefix):
    need(name.startswith(prefix), "unknown SF prefix")
    return relative(name[len(prefix) :])


def parse_lcov(raw, prefix):
    rows = {}
    for block in raw.decode("utf-8").split("end_of_record"):
        if not block.strip():
            continue
        file = None
        da = {}
        summaries = {}
        for line in block.splitlines():
            if not line:
                continue
            key, sep, value = line.partition(":")
            need(sep, "malformed LCOV")
            if key == "SF":
                need(file is None, "duplicate SF in record")
                file = normalize(value, prefix)
            elif key == "DA":
                need(re.fullmatch(r"[1-9][0-9]*,[0-9]+", value), "invalid DA integer/count")
                number, count = map(int, value.split(","))
                need(number <= 0xFFFFFFFF and count <= 0xFFFFFFFFFFFFFFFF, "DA overflow")
                need(number not in da, "duplicate DA line")
                da[number] = count
            elif key in ("LF", "LH"):
                need(
                    key not in summaries and re.fullmatch(r"[0-9]+", value),
                    "invalid or duplicate summary",
                )
                summaries[key] = int(value)
        need(
            file and file not in rows and set(summaries) == {"LF", "LH"},
            "missing/duplicate SF or summary",
        )
        need(
            0 <= summaries["LH"] <= summaries["LF"] and summaries["LF"] > 0 and da,
            "invalid line population",
        )
        rows[file] = dict(
            summary_lines=summaries["LF"],
            summary_hit=summaries["LH"],
            da_lines=len(da),
            da_hit=sum(v > 0 for v in da.values()),
            uncovered_da_lines=sorted(n for n, count in da.items() if count == 0),
        )
    return rows


def validate(lcov_raw, scope, evidence, root=ROOT, evidence_root=ROOT):
    need(scope == json.loads(read(SCOPE)), "fixed U9 scope changed")
    need(
        evidence["schema"] == 1 and re.fullmatch(r"[0-9a-f]{40}", evidence["head"]),
        "invalid evidence head",
    )
    official = evidence["official"]
    need(
        official["head"] == evidence["head"]
        and official["repository"] == "Marukome0743/paludarium"
        and type(official["run"]) is int
        and official["run"] > 0
        and type(official["job"]) is int
        and official["job"] > 0
        and type(official["artifact"]) is int
        and official["artifact"] > 0
        and re.fullmatch(r"sha256:[0-9a-f]{64}", official["artifact_digest"]),
        "official artifact identity missing",
    )
    need(
        evidence["compiler"]["llvm"] == scope["llvm_version"]
        and evidence["compiler"]["rustc_verbose"]
        and evidence["compiler"]["cargo_llvm_cov"]
        and evidence["compiler"]["flags"],
        "compiler provenance missing",
    )
    prefix = evidence["source_prefix"]
    need(prefix in scope["allowed_sf_prefixes"], "unapproved source prefix")
    paths = scope["groups"]["original13"] + scope["groups"]["additional10"]
    need(
        len(paths) == len(set(paths)) == 23
        and len(scope["groups"]["original13"]) == 13
        and len(scope["groups"]["additional10"]) == 10
        and scope["floor_percent"] == 80,
        "fixed group denominator",
    )
    need(
        evidence["source_before"] == evidence["source_after"]
        and set(evidence["source_before"]) == set(paths),
        "source snapshot mismatch",
    )
    for name, digest in evidence["source_before"].items():
        need(sha(read(root / relative(name))) == digest, "source bytes differ")
    need(
        set(evidence["locks"]) == {"Cargo.lock", "fuzz/Cargo.lock"}, "both lock identities required"
    )
    for name, digest in evidence["locks"].items():
        need(sha(read(root / name)) == digest, "lock changed")
    commands = evidence["commands"]
    need(
        commands
        and all(
            type(r["exit"]) is int
            and r["exit"] == 0
            and r["timed_out"] is False
            and isinstance(r["argv"], list)
            and r["argv"]
            and all(isinstance(x, str) for x in r["argv"])
            for r in commands
        ),
        "coverage command failed",
    )
    diff = [r for r in commands if "--test" in r["argv"] and "diff_u9" in r["argv"]]
    need(
        diff
        and all(
            type(r["tests"]) is int
            and r["tests"] > 0
            and type(r["ignored"]) is int
            and r["ignored"] == 0
            for r in diff
        ),
        "diff_u9 zero/ignored population",
    )
    need(
        any("llvm-cov" in r["argv"] and "--lcov" in r["argv"] for r in commands)
        and any("llvm-cov" in r["argv"] and "--json" in r["argv"] for r in commands),
        "same-profile exports missing",
    )
    files = evidence["files"]
    need(set(files) == {"lcov", "json", "report", "profdata"}, "raw profile/export files missing")
    raw = {}
    for kind, row in files.items():
        raw[kind] = read(evidence_root / relative(row["path"]))
        need(sha(raw[kind]) == row["sha256"], "raw digest differs")
    need(raw["lcov"] == lcov_raw and evidence["binaries"], "LCOV/binary identity missing")
    for row in evidence["binaries"]:
        need(
            sha(read(evidence_root / relative(row["path"]))) == row["sha256"],
            "instrumented binary differs",
        )
    exports = [r for r in commands if r.get("export")]
    need(
        len(exports) == 3 and {r["export"] for r in exports} == {"lcov", "json", "report"},
        "three explicit exports required",
    )
    need(
        all(
            r["profdata_sha256"] == files["profdata"]["sha256"]
            and r["binary_hashes"] == [x["sha256"] for x in evidence["binaries"]]
            for r in exports
        ),
        "exports use different binary/profile",
    )
    rows = parse_lcov(lcov_raw, prefix)
    need(set(rows) == set(paths), "missing or extra U9 SF")
    exported = json.loads(raw["json"])
    need(
        exported["type"] == "llvm.coverage.json.export" and len(exported["data"]) == 1,
        "LLVM JSON shape",
    )
    summaries = {}
    for row in exported["data"][0]["files"]:
        name = normalize(row["filename"], prefix)
        need(name not in summaries, "duplicate JSON file")
        summaries[name] = row["summary"]["lines"]
    need(set(summaries) == set(paths), "JSON scope differs")
    for name, row in rows.items():
        summary = summaries[name]
        need(
            type(summary["count"]) is int
            and type(summary["covered"]) is int
            and type(summary["percent"]) in (int, float)
            and summary["count"] == row["summary_lines"]
            and summary["covered"] == row["summary_hit"],
            "unexplained LCOV/JSON summary difference",
        )
        need(
            abs(summary["percent"] - 100 * row["summary_hit"] / row["summary_lines"]) < 0.011,
            "JSON summary percentage differs",
        )
    totals = [
        line.split() for line in raw["report"].decode().splitlines() if line.startswith("TOTAL ")
    ]
    need(len(totals) == 1 and len(totals[0]) >= 10, "LLVM report TOTAL missing")
    total_lines = sum(r["summary_lines"] for r in rows.values())
    total_hit = sum(r["summary_hit"] for r in rows.values())
    need(
        totals[0][7].isdigit()
        and totals[0][8].isdigit()
        and int(totals[0][7]) == total_lines
        and int(totals[0][8]) == total_lines - total_hit,
        "LLVM report/JSON/LCOV total mismatch",
    )
    # LLVM's file summary aggregates function/instantiation summaries, whereas
    # DA uses the merged file-line iterator. They are intentionally separate.
    result = {}
    for group, names in scope["groups"].items():
        hit = sum(rows[n]["summary_hit"] for n in names)
        total = sum(rows[n]["summary_lines"] for n in names)
        result[group] = dict(
            hit=hit, lines=total, percent=100 * hit / total, passed=hit / total >= 0.8
        )
    need(all(r["passed"] for r in result.values()), "one U9 group below fixed80 floor")
    return dict(
        schema=1,
        head=evidence["head"],
        passed=True,
        groups=result,
        files=rows,
        definition=scope["definition"],
        source_unchanged=True,
        new_measurement=False,
    )


def main():
    p = argparse.ArgumentParser()
    for name in ("lcov", "scope", "evidence", "output"):
        p.add_argument("--" + name, required=True, type=Path)
    args = p.parse_args()
    need(not args.output.exists(), "refusing to overwrite verdict")
    evidence = json.loads(read(args.evidence))
    result = validate(
        read(args.lcov), json.loads(read(args.scope)), evidence, evidence_root=args.evidence.parent
    )
    with args.output.open("x", encoding="utf-8") as stream:
        stream.write(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result["groups"]))


if __name__ == "__main__":
    main()
