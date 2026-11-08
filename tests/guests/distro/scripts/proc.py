"""What /proc says about the process itself and about the system."""

import os
import subprocess
import sys
import threading
import time

with open("/proc/self/status") as status:
    fields = dict(line.split(":", 1) for line in status if ":" in line)
print("name", fields["Name"].strip(), "state", fields["State"].split()[0])
event = threading.Event()
thread = threading.Thread(target=event.wait)
thread.start()
with open("/proc/self/status") as status:
    print("threads", [line.split()[1] for line in status if line.startswith("Threads:")])
print("tasks", len(os.listdir("/proc/self/task")))
event.set()
thread.join()
# join() returns once the thread has signalled that it is done, before the kernel
# has removed the task, on Linux too. Wait, within a bound, until it is gone, so
# that the count read from /proc/self/stat below does not race.
deadline = time.monotonic() + 30
while len(os.listdir("/proc/self/task")) > 1 and time.monotonic() < deadline:
    time.sleep(0.01)
print("cwd", os.readlink("/proc/self/cwd"))
fd = os.open("/etc/os-release", os.O_RDONLY)
print("fd link", os.readlink(f"/proc/self/fd/{fd}"))
os.close(fd)
with open("/proc/self/maps") as maps:
    print("maps has python", any("python" in line for line in maps))
with open("/proc/self/stat") as stat:
    line = stat.read()
fields = line[line.rindex(")") + 2 :].split()
print("stat fields", len(fields) + 2, "state", fields[0], "threads", fields[17])
print(
    "stat ids",
    int(line.split()[0]) == os.getpid(),
    int(fields[1]) == os.getppid(),
    int(fields[2]) == os.getpgrp(),
    int(fields[3]) == os.getsid(0),
)
with open("/proc/self/cmdline", "rb") as cmdline:
    print("cmdline", cmdline.read().split(b"\0")[1:])
with open("/proc/self/comm") as comm:
    print("comm", comm.read().strip())
with open("/proc/self/exe", "rb") as exe, open(sys.executable, "rb") as program:
    print("exe is this program", exe.read() == program.read())
# A program execve loaded names itself with its links resolved.
print(
    "exec'd exe",
    subprocess.run(
        ["/bin/sh", "-c", "readlink /proc/self/exe"], capture_output=True, text=True
    ).stdout,
)
with open("/proc/loadavg") as loadavg:
    load = loadavg.read().split()
print("loadavg fields", len(load), "running/tasks", "/" in load[3])
with open("/proc/meminfo") as meminfo:
    memory = dict(line.split(":", 1) for line in meminfo)
total, free = (int(memory[name].split()[0]) for name in ("MemTotal", "MemFree"))
print("meminfo", "MemAvailable" in memory, 0 < free <= total)
with open("/proc/uptime") as uptime:
    print("uptime fields", len(uptime.read().split()))
