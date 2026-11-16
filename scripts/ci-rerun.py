"""Reruns a CI run whose only failures are jobs no runner took.

GitHub cancels a job that no hosted runner acquires (macOS arm64 runners
run short of capacity) with an annotation and no step run. Such a run is
rerun with `gh run rerun --failed`, at most MAX_EXTRA times. A job that ran a
step and failed is never rerun: then nothing is. ci-ok, which fails because
of those jobs, is the one other failure allowed, and it runs again with them.
"""

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

CI = Path(__file__).resolve().parents[1] / ".github/workflows/ci.yml"

NOT_ACQUIRED = "was not acquired by Runner"
MAX_EXTRA = 2
# Jobs that fail when a job they need did not run, and that rerun with it.
GATES = frozenset({"ci-ok"})
FAILED = frozenset({"failure", "cancelled", "timed_out", "startup_failure"})


def unacquired(job, annotations):
    """Whether no runner took the job: no step, no runner, the annotation."""
    return (
        job["conclusion"] in ("failure", "cancelled")
        and not job.get("steps")
        and not job.get("runner_name")
        and any(NOT_ACQUIRED in note for note in annotations)
    )


def decide(run, jobs, annotations, superseded):
    """(rerun, reasons): whether to rerun `run`, and why, line by line.

    `jobs` are the run attempt's jobs, `annotations` maps a job id to its
    annotation messages, and `superseded` is whether a later run of the same
    workflow, branch and event exists.
    """
    reasons = []
    if run["conclusion"] not in ("failure", "cancelled"):
        return False, [f"run concluded {run['conclusion']}: nothing to rerun"]
    if run["run_attempt"] > MAX_EXTRA:
        return False, [f"attempt {run['run_attempt']}: already rerun {MAX_EXTRA} times"]
    if superseded:
        return False, ["a later run of this branch exists: its head was replaced"]
    waiting, other = [], []
    for job in jobs:
        if job["conclusion"] not in FAILED:
            continue
        if unacquired(job, annotations.get(job["id"], [])):
            waiting.append(job["name"])
        elif job["name"] in GATES:
            reasons.append(f"{job['name']}: {job['conclusion']}, a gate, reruns with the others")
        else:
            other.append(job["name"])
            steps = len(job.get("steps") or [])
            reasons.append(f"{job['name']}: {job['conclusion']} after {steps} steps, not rerun")
    for name in waiting:
        reasons.append(f"{name}: no runner took it")
    if other:
        return False, [*reasons, "a job ran and failed: nothing is rerun"]
    if not waiting:
        return False, [*reasons, "no job was left without a runner: nothing is rerun"]
    return True, [*reasons, f"rerunning the failed jobs (attempt {run['run_attempt'] + 1})"]


def gh(*args):
    out = subprocess.run(["gh", *args], check=True, capture_output=True, text=True)
    return out.stdout


def main_rerun(repo, run_id, attempt=None, dry_run=False):
    run = json.loads(gh("api", f"repos/{repo}/actions/runs/{run_id}"))
    if attempt:
        run = json.loads(gh("api", f"repos/{repo}/actions/runs/{run_id}/attempts/{attempt}"))
    attempt = run["run_attempt"]
    jobs = []
    page = 1
    while True:
        batch = json.loads(
            gh(
                "api",
                f"repos/{repo}/actions/runs/{run_id}/attempts/{attempt}/jobs"
                f"?per_page=100&page={page}",
            )
        )["jobs"]
        jobs += batch
        if len(batch) < 100:
            break
        page += 1
    annotations = {}
    for job in jobs:
        if job["conclusion"] in FAILED and not job.get("steps"):
            notes = json.loads(gh("api", f"repos/{repo}/check-runs/{job['id']}/annotations"))
            annotations[job["id"]] = [note["message"] for note in notes]
    later = json.loads(
        gh(
            "api",
            f"repos/{repo}/actions/workflows/{run['workflow_id']}/runs"
            f"?branch={run['head_branch']}&event={run['event']}&per_page=1",
        )
    )["workflow_runs"]
    superseded = bool(later) and later[0]["id"] != run["id"]
    rerun, reasons = decide(run, jobs, annotations, superseded)
    print(
        f"run {run_id} attempt {attempt} ({run['event']} {run['head_branch']} {run['head_sha'][:9]}):"
    )
    for reason in reasons:
        print(f"  {reason}")
    if rerun and not dry_run:
        gh("run", "rerun", str(run_id), "--failed", "-R", repo)


def self_test():
    def job(name, conclusion, steps=1, runner="GitHub Actions 1", jid=None):
        return {
            "id": jid or name,
            "name": name,
            "conclusion": conclusion,
            "steps": [{}] * steps,
            "runner_name": "" if steps == 0 else runner,
        }

    note = ["The job was not acquired by Runner of type hosted even after multiple attempts"]
    run = {"conclusion": "failure", "run_attempt": 1}
    mac = job("unit tests (macos-latest)", "cancelled", steps=0)
    ok = job("ci-ok", "failure", steps=2)
    cases = [
        # (name, run, jobs, annotations, superseded, rerun)
        (
            "one job without a runner",
            run,
            [mac, ok, job("lint", "success")],
            {mac["id"]: note},
            False,
            True,
        ),
        (
            "a failed test",
            run,
            [mac, job("unit tests (ubuntu-latest)", "failure"), ok],
            {mac["id"]: note},
            False,
            False,
        ),
        (
            "cancelled without the annotation",
            run,
            [mac, ok],
            {mac["id"]: ["The operation was canceled."]},
            False,
            False,
        ),
        (
            "cancelled after a step",
            run,
            [job("unit tests (macos-latest)", "cancelled", steps=3), ok],
            {},
            False,
            False,
        ),
        ("only ci-ok failed", run, [ok], {}, False, False),
        (
            "two extra attempts made",
            {**run, "run_attempt": 3},
            [mac, ok],
            {mac["id"]: note},
            False,
            False,
        ),
        (
            "second extra attempt",
            {**run, "run_attempt": 2},
            [mac, ok],
            {mac["id"]: note},
            False,
            True,
        ),
        ("superseded", run, [mac, ok], {mac["id"]: note}, True, False),
        ("success", {**run, "conclusion": "success"}, [job("lint", "success")], {}, False, False),
        (
            "timed out",
            run,
            [job("coverage", "timed_out", steps=5), mac, ok],
            {mac["id"]: note},
            False,
            False,
        ),
        (
            "skipped and waiting",
            run,
            [mac, job("fuzz", "skipped", steps=0), ok],
            {mac["id"]: note},
            False,
            True,
        ),
    ]
    for name, r, jobs, notes, superseded, wanted in cases:
        got, reasons = decide(r, jobs, notes, superseded)
        if got != wanted or not reasons:
            raise AssertionError(f"{name}: rerun {got}, wanted {wanted}: {reasons}")
    text = CI.read_text(encoding="utf-8")
    for gate in GATES:
        if f"\n  {gate}:\n" not in text:
            raise AssertionError(f"{gate} is no job of ci.yml")
    if "\nname: CI\n" not in text:
        raise AssertionError("rerun-unacquired.yml follows the workflow named CI")
    print(f"ci-rerun ready: {len(cases)} cases and {len(GATES)} gate checked")


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--run", help="the run's ID (default: $RUN_ID)")
    parser.add_argument("--repo", help="owner/name (default: $GITHUB_REPOSITORY)")
    parser.add_argument("--attempt", type=int, help="decide for this attempt instead of the last")
    parser.add_argument("--dry-run", action="store_true", help="decide and log, but rerun nothing")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return
    run_id = args.run or os.environ.get("RUN_ID")
    repo = args.repo or os.environ.get("GITHUB_REPOSITORY")
    if not run_id or not repo:
        sys.exit("a run ID and a repository are needed")
    main_rerun(repo, run_id, args.attempt, args.dry_run)


if __name__ == "__main__":
    main()
