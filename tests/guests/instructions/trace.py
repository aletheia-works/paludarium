"""Bounded native GDB inventory; a budget stop is explicitly incomplete."""

import collections
import json
import os
import time

import gdb

started = time.monotonic()
start_point = os.environ.get("INSTRUCTIONS_TRACE_START", "elf-entry")
start_evidence = {"pc": hex(int(gdb.selected_frame().pc()))}
if start_point == "first-fixture-open":
    while True:
        try:
            path_register = "$rdi" if int(gdb.parse_and_eval("$orig_rax")) == 2 else "$rsi"
            filename = gdb.parse_and_eval("(char *)" + path_register).string(errors="replace")
        except gdb.error:
            filename = ""
        if filename.endswith(("package.json", "aube.lock", "aube.lockb")):
            break
        gdb.execute("continue", to_string=True)
    start_evidence["fixture_path"] = filename
    start_evidence["pc"] = hex(int(gdb.selected_frame().pc()))
    started = time.monotonic()
if start_point == "first-stdout-write":
    while int(gdb.parse_and_eval("$rdi")) != 1:
        gdb.execute("continue", to_string=True)
    count = int(gdb.parse_and_eval("$rdx"))
    address = int(gdb.parse_and_eval("$rsi"))
    if int(gdb.parse_and_eval("$orig_rax")) == 20:
        payload = bytearray()
        for index in range(min(count, 16)):
            vector = bytes(gdb.selected_inferior().read_memory(address + index * 16, 16))
            base = int.from_bytes(vector[:8], "little")
            size = int.from_bytes(vector[8:], "little")
            payload.extend(gdb.selected_inferior().read_memory(base, min(size, 256 - len(payload))))
            if len(payload) == 256:
                break
    else:
        payload = bytes(gdb.selected_inferior().read_memory(address, min(count, 256)))
    start_evidence["stdout_buffer"] = bytes(payload).decode("utf-8", errors="replace")
    start_evidence["pc"] = hex(int(gdb.selected_frame().pc()))
    started = time.monotonic()
forms = collections.Counter()
samples = {}
steps = 0
reason = "budget"
try:
    while steps < 20000 and time.monotonic() - started < 20:
        frame = gdb.selected_frame()
        pc = int(frame.pc())
        decoded = frame.architecture().disassemble(pc, count=2)
        text = decoded[0]["asm"]
        raw = bytes(gdb.selected_inferior().read_memory(pc, decoded[1]["addr"] - pc)).hex()
        forms[text] += 1
        samples.setdefault(text, raw)
        steps += 1
        gdb.execute("stepi", to_string=True)
except gdb.error as error:
    reason = "inferior-exited" if not gdb.selected_inferior().pid else str(error)
output = os.environ["INSTRUCTIONS_TRACE_OUTPUT"]
with open(output, "w", encoding="utf-8") as stream:
    json.dump(
        {
            "steps": steps,
            "reason": reason,
            "complete_runtime_inventory": False,
            "sample_completed": reason == "inferior-exited",
            "start_point": start_point,
            "start_evidence": start_evidence,
            "forms": [
                {"asm": form, "bytes": samples[form], "count": count}
                for form, count in sorted(forms.items())
            ],
        },
        stream,
        indent=2,
    )
print("INSTRUCTIONS_TRACE", steps, reason, output)
if gdb.selected_inferior().pid:
    gdb.execute("kill", to_string=True)
