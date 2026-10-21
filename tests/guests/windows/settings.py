"""Frozen U10 inventory, with the approved append-only comparison reporter."""

import json

PROBE_ITEMS = (
    "tokio-timer",
    "unix-stream-pair",
    "rayon",
    "mutex-condvar",
    "fs-basic",
    "fs-hardlink",
    "fs-symlink",
    "fs-flock",
)


def configuration(root, *, original=False):
    config = json.loads((root / "tests/guests/programs/cases.json").read_text())
    if (
        config["schema"] != 1
        or config["deadline_seconds"] != 30
        or tuple(config["probe"]) != PROBE_ITEMS
    ):
        raise ValueError("fixed U13 inventory/deadline changed")
    expected = [
        ("version", ["--version"]),
        ("install", ["install"]),
        ("frozen", ["install", "--frozen-lockfile"]),
        ("list", ["list"]),
    ]
    if [(row["name"], row["args"]) for row in config["aube"]] != expected:
        raise ValueError("fixed aube arguments changed")
    if config["aube"][2].get("before") != "remove-node-modules":
        raise ValueError("frozen cleanup changed")
    if config["environment"]["PATH"] != "/no-node":
        raise ValueError("node absence boundary changed")
    if any(config["comparison"][key] is not True for key in ("stdout", "stderr", "exit")):
        raise ValueError("required comparison removed")
    for row in config["aube"]:
        if not original and row["name"] in ("install", "frozen"):
            row["args"].append("--reporter=append-only")
    return config
