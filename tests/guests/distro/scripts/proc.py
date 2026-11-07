"""What /proc says about the process itself."""

import os
import threading

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
print("cwd", os.readlink("/proc/self/cwd"))
fd = os.open("/etc/os-release", os.O_RDONLY)
print("fd link", os.readlink(f"/proc/self/fd/{fd}"))
os.close(fd)
with open("/proc/self/maps") as maps:
    print("maps has python", any("python" in line for line in maps))
