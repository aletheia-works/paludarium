"""Pseudo-terminals through Python's pty, tty and termios modules: openpty and the line
discipline, a child on its own terminal with pty.fork, signals and window sizes from the
terminal, and the ends of either side."""

import errno
import fcntl
import os
import pty
import select
import signal
import struct
import termios
import tty


def drain(fd):
    """What fd gives until it stays quiet for 100 ms: Linux passes what one side writes to
    the other from a work queue, so one read may not see it all."""
    data = b""
    while select.select([fd], [], [], 0.1)[0]:
        try:
            chunk = os.read(fd, 4096)
        except OSError as error:
            return data + b"<%s>" % errno.errorcode[error.errno].encode()
        if not chunk:
            break
        data += chunk
    return data


def to_end(fd):
    """Everything the master reads until the slave's last description closes (EIO)."""
    data = b""
    while True:
        try:
            chunk = os.read(fd, 4096)
        except OSError as error:
            return data + b"<%s>" % errno.errorcode[error.errno].encode()
        if not chunk:
            return data + b"<eof>"
        data += chunk


def until(fd, marker):
    data = b""
    while marker not in data:
        data += os.read(fd, 4096)
    return data


def attempt(call):
    try:
        return call()
    except OSError as error:
        return errno.errorcode[error.errno]


master, slave = pty.openpty()
name = os.ttyname(slave)
print("isatty", os.isatty(master), os.isatty(slave), name.startswith("/dev/pts/"))
print("same file", os.stat(name).st_ino == os.fstat(slave).st_ino)
print("named", os.path.basename(name) in os.listdir("/dev/pts"))
attributes = termios.tcgetattr(slave)
print("termios", [oct(flag) for flag in attributes[:4]], attributes[4], attributes[5])
print("cc", attributes[6][: termios.VEOL2 + 1])

os.write(master, b"hello\rwor\x7fld\nx\x15y\x04")
print("lines", [os.read(slave, 100) for _ in range(3)])
print("echo", drain(master))
os.write(slave, b"out\n")
print("output", drain(master))

tty.setraw(slave)
os.write(master, b"a\r\x03b")
print("raw", drain(slave), drain(master))
os.write(slave, b"x\ny")
print("raw output", drain(master))
attributes = termios.tcgetattr(slave)
attributes[6][termios.VMIN] = 0
attributes[6][termios.VTIME] = 0
termios.tcsetattr(slave, termios.TCSANOW, attributes)
print("min 0", os.read(slave, 10))
tty.setcbreak(slave)
os.write(master, b"c\x03")
print("cbreak", drain(slave), drain(master))

attributes = termios.tcgetattr(slave)
attributes[2] |= termios.PARENB
attributes[4] = attributes[5] = termios.B9600
termios.tcsetattr(master, termios.TCSANOW, attributes)
attributes = termios.tcgetattr(slave)
print("speed", attributes[4], attributes[5], attributes[2] & termios.PARENB)

fcntl.ioctl(master, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 80, 0, 0))
print("size", os.get_terminal_size(slave), termios.tcgetwinsize(master))
os.close(slave)
os.write(master, b"after")
print("slave closed", drain(master), attempt(lambda: os.read(master, 1)))
os.close(master)

# The master closed: the slave is hung up.
master, slave = pty.openpty()
os.close(master)
print("hung up", os.read(slave, 1), attempt(lambda: os.write(slave, b"x")))
try:
    termios.tcgetattr(slave)
except termios.error as error:
    print("tcgetattr", errno.errorcode[error.args[0]])
poller = select.poll()
poller.register(slave)
print("poll", poller.poll(0))
os.close(slave)

# A child on its own terminal, as pty.spawn starts one.
pid, fd = pty.fork()
if pid == pty.CHILD:
    print(
        "child",
        os.isatty(0),
        os.getsid(0) == os.getpid(),
        os.tcgetpgrp(0) == os.getpgrp(),
        flush=True,
    )
    with open("/dev/tty", "wb", buffering=0) as terminal:
        terminal.write(b"through /dev/tty\n")
    os._exit(3)
print("forked", to_end(fd))
print("status", os.waitstatus_to_exitcode(os.waitpid(pid, 0)[1]))
os.close(fd)


# The terminal's signals reach the child, which writes what it got.
def child_reporting(*numbers):
    pid, fd = pty.fork()
    if pid == pty.CHILD:

        def report(number, frame):
            os.write(1, b"got %d %s\n" % (number, b"%dx%d" % os.get_terminal_size(0)))
            if number == signal.SIGINT:
                os._exit(0)

        for number in numbers:
            signal.signal(number, report)
        os.write(1, b"ready\n")
        while True:
            signal.pause()
    until(fd, b"ready\r\n")
    return pid, fd


pid, fd = child_reporting(signal.SIGINT, signal.SIGWINCH)
fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", 30, 100, 0, 0))
print("winch", until(fd, b"\n"))
os.write(fd, b"zz\x03")
print("interrupt", to_end(fd))
print("status", os.waitstatus_to_exitcode(os.waitpid(pid, 0)[1]))
os.close(fd)

# Closing the master hangs up the child's session, whose leader gets SIGHUP.
pid, fd = child_reporting()
os.close(fd)
print("hangup", os.waitstatus_to_exitcode(os.waitpid(pid, 0)[1]))
