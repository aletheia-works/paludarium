"""Narrow, explicit normalization; no suppression of guest failures."""

import re


def normalized(text, fixture_root):
    text = re.sub(r"\x1b\[[0-9;]*m", "", text)
    text = text.replace(str(fixture_root), "<FIXTURE>")
    return re.sub(r"(?<= in )\d+(?:\.\d+)?(?:ms|s)(?=\b)", "<ELAPSED>", text)


def compare(expected, actual, expected_root, actual_root):
    if expected["timed_out"] or actual["timed_out"]:
        raise ValueError("operation timed out")
    if expected["exit"] != actual["exit"]:
        raise ValueError("exit mismatch")
    if normalized(expected["stdout"], expected_root) != normalized(actual["stdout"], actual_root):
        raise ValueError("stdout mismatch")
    if normalized(expected["stderr"], expected_root) != normalized(actual["stderr"], actual_root):
        raise ValueError("stderr mismatch")


def probe_pass(result, items):
    if result["timed_out"] or result["exit"] != 0:
        raise ValueError("probe exit/timeout")
    if result["stdout"].splitlines() != ["PASS " + item for item in items]:
        raise ValueError("probe missing, duplicate, FAIL or unexpected item")
