"""Accept only complete fresh Linux expectations for the unchanged guest bytes."""

import json
import math

from evidence import digest, validate
from settings import configuration


def load(path, guests, root, *, original=False):
    receipt = json.loads((guests / "build-receipt.json").read_text())
    validate(guests, receipt)
    data = json.loads(path.read_text())
    config = configuration(root, original=original)
    expected = ["probe-" + name for name in config["probe"] + ["all", "environment"]]
    expected += [case["name"] for case in config["aube"]]
    if data.get("schema") != 1 or data.get("native_complete") is not True:
        raise ValueError("incomplete Linux oracle")
    if data.get("case_config") != config:
        raise ValueError("oracle argument configuration mismatch")
    if not str(data.get("machine", "")).startswith("Linux-"):
        raise ValueError("oracle must originate on Linux")
    if not data.get("network_namespace") or data.get("route", "").splitlines()[1:]:
        raise ValueError("oracle network isolation missing")
    if list(data.get("rows", {})) != expected:
        raise ValueError("oracle rows missing, duplicated or reordered")
    if data.get("binary_hashes") != {name: digest(guests / name) for name in ("probe", "aube")}:
        raise ValueError("oracle guest hash mismatch")
    for name, row in data["rows"].items():
        duration = row.get("wall_seconds")
        if (
            type(duration) not in (int, float)
            or not math.isfinite(duration)
            or not 0 <= duration <= config["deadline_seconds"]
        ):
            raise ValueError("invalid oracle duration: " + name)
        if (
            type(row.get("exit")) is not int
            or row["exit"] != 0
            or row.get("timed_out") is not False
        ):
            raise ValueError("oracle failure or timeout: " + name)
    return data
