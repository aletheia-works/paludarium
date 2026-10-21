"""Strict inventory/schema checks; numeric guest expectations come from Linux."""

import json
import math

SSE_CASES = (
    "sse-pshufd-00",
    "sse-pshufd-1b",
    "sse-pshufd-b1",
    "sse-pshufd-e4",
    "sse-pmuludq-max",
    "sse-pmuludq-upper-ignored",
    "sse-paddd-wraparound",
    "sse-psubd-wraparound",
    "sse-pslld-counts",
    "sse-psrld-counts",
    "sse-packuswb-saturation",
    "sse-punpckldq",
    "sse-movdqa-register",
    "sse-logic-register",
    "sse-jcc-loop",
)
CASES = (
    "move64",
    "add64-carry",
    "sub64-overflow",
    "jne-zf1-not-taken",
    "jne-zf0-taken",
    "je-zf1-taken",
    "je-zf0-not-taken",
    "memory-read-write",
    "unsupported-sse-fallback",
    "unmapped-data-fault",
    "division-fault",
    "self-modifying-code",
    "cross-page-instruction",
    *SSE_CASES,
)
HEX_FIELDS = ("rax", "first_rax", "flags", "flag_mask", "memory")
# Integer-SSE rows carry the loaded and observed register files. RSP (GPR 4)
# is an address and is never loaded or observed, so it must read as zero.
SSE_HEX_FIELDS = ("in_flags", "flags", "flag_mask", "rip")
SSE_LIST_FIELDS = {"in_gpr": 16, "gpr": 16, "in_xmm": 32, "xmm": 32}
SSE_FIELDS = ("code", *SSE_HEX_FIELDS, *SSE_LIST_FIELDS)
RSP = 4


def _is_hex(value, digits):
    return (
        type(value) is str
        and len(value) == digits
        and all(char in "0123456789abcdef" for char in value)
    )


def _check_sse(row):
    for name, digits in SSE_LIST_FIELDS.items():
        values = row[name]
        if (
            type(values) is not list
            or len(values) != 16
            or not all(_is_hex(value, digits) for value in values)
        ):
            raise ValueError("native SSE register file must hold sixteen fixed-width hex strings")
    if row["in_gpr"][RSP] != "0" * 16 or row["gpr"][RSP] != "0" * 16:
        raise ValueError("RSP is an address and must not be observed")
    code = row["code"]
    if (
        type(code) is not str
        or not code
        or len(code) % 2
        or any(char not in "0123456789abcdef" for char in code)
    ):
        raise ValueError("native SSE code must be lowercase hex bytes")
    data = bytes.fromhex(code)
    if data[-1] != 0xC3 or 0xC3 in data[:-1]:
        raise ValueError("native SSE code must end in its only RET byte")
    if int(row["rip"], 16) != len(data) - 1:
        raise ValueError("native SSE RIP must be the offset of the final RET")
    if int(row["flags"], 16) & ~int(row["flag_mask"], 16):
        raise ValueError("native SSE flags exceed their mask")


def validate(stdout, *, seconds, exit_code):
    if (
        type(seconds) not in (int, float)
        or not math.isfinite(seconds)
        or not 0 <= seconds <= 30
        or type(exit_code) is not int
        or exit_code != 0
    ):
        raise ValueError("native process failed or exceeded thirty seconds")
    rows = [json.loads(line) for line in stdout.splitlines()]
    if tuple(row.get("name") for row in rows) != CASES:
        raise ValueError("missing, duplicate, reordered or extra native cases")
    for row in rows:
        if type(row.get("signal")) is not int or not 0 <= row["signal"] < 65:
            raise ValueError("invalid Linux signal")
        sse = row["name"] in SSE_CASES
        observed = SSE_FIELDS if sse else HEX_FIELDS
        fields = (
            {"name", "signal", "child_exit"}
            if row["signal"]
            else {"name", "signal", "child_exit", *observed}
        )
        if set(row) != fields:
            raise ValueError("native row schema changed")
        if row["signal"]:
            if row["child_exit"] is not None:
                raise ValueError("signaled child cannot have an exit code")
        elif type(row["child_exit"]) is not int or row["child_exit"] != 0:
            raise ValueError("native child did not exit successfully")
        for name in fields & set(SSE_HEX_FIELDS if sse else HEX_FIELDS):
            if not _is_hex(row[name], 16):
                raise ValueError("native register must be a sixteen-digit hex string")
        fault = row["name"] in ("unmapped-data-fault", "division-fault")
        if bool(row["signal"]) != fault:
            raise ValueError("unexpected native success or signal")
        if fault and row["signal"] != (11 if row["name"] == "unmapped-data-fault" else 8):
            raise ValueError("wrong native fault signal")
        if sse:
            _check_sse(row)
    return rows
