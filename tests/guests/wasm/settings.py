"""Small runner contract; reuses the immutable U10 guest and case definitions."""

import json


def validate(config):
    if config.get("schema") != 1 or config.get("deadline_seconds") != 30:
        raise ValueError("invalid U11 case schema or external operation deadline")
    expected = [
        "tokio-timer",
        "unix-stream-pair",
        "rayon",
        "mutex-condvar",
        "fs-basic",
        "fs-hardlink",
        "fs-symlink",
        "fs-flock",
    ]
    if config.get("probe") != expected:
        raise ValueError("fixed probe inventory changed")
    commands = [
        ("version", ["--version"]),
        ("install", ["install"]),
        ("frozen", ["install", "--frozen-lockfile"]),
        ("list", ["list"]),
    ]
    reporter_commands = [
        ("version", ["--version"]),
        ("install", ["install", "--reporter=append-only"]),
        ("frozen", ["install", "--frozen-lockfile", "--reporter=append-only"]),
        ("list", ["list"]),
    ]
    if [(row.get("name"), row.get("args")) for row in config.get("aube", [])] not in (
        commands,
        reporter_commands,
    ):
        raise ValueError("fixed aube inventory changed")
    if config["aube"][2].get("before") != "remove-node-modules":
        raise ValueError("frozen command must remove node_modules")
    if config.get("environment", {}).get("PATH") != "/u10-no-node":
        raise ValueError("node absence boundary changed")
    if not all(
        config.get("comparison", {}).get(key) is True for key in ("stdout", "stderr", "exit")
    ):
        raise ValueError("all result streams must be compared")
    return config


def configuration(root):
    config = validate(json.loads((root / "tests/guests/programs/cases.json").read_text()))
    for row in config["aube"]:
        if row["name"] in ("install", "frozen"):
            row["args"].append("--reporter=append-only")
    return validate(config)
