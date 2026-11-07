"""Signals: handlers, an interval timer, a blocked signal waited for, and a child's end."""

import os
import signal
import time

got = []
signal.signal(signal.SIGUSR1, lambda number, frame: got.append("usr1"))
os.kill(os.getpid(), signal.SIGUSR1)
print("handler", got)

ticks = []
signal.signal(signal.SIGALRM, lambda number, frame: ticks.append(1))
signal.setitimer(signal.ITIMER_REAL, 0.01, 0.01)
while len(ticks) < 3:
    signal.pause()
signal.setitimer(signal.ITIMER_REAL, 0)
print("timer ticks", len(ticks))

signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGUSR2})
os.kill(os.getpid(), signal.SIGUSR2)
print("pending", signal.SIGUSR2 in signal.sigpending())
print("waited", signal.sigwait({signal.SIGUSR2}) == signal.SIGUSR2)

children = []
signal.signal(signal.SIGCHLD, lambda number, frame: children.append(1))
pid = os.fork()
if pid == 0:
    os._exit(7)
_, status = os.waitpid(pid, 0)
print("child exit", os.waitstatus_to_exitcode(status), "sigchld", len(children) > 0)

pid = os.fork()
if pid == 0:
    time.sleep(30)
    os._exit(0)
os.kill(pid, signal.SIGTERM)
_, status = os.waitpid(pid, 0)
print("killed", os.WIFSIGNALED(status), os.WTERMSIG(status))
