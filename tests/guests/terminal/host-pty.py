"""Internal Host regression: actual Linux stdin PTY, stdout remains a pipe."""

import fcntl
import os
import pty
import struct
import subprocess
import sys
import termios

master, slave = pty.openpty()
try:
    cc = [b"\0"] * termios.NCCS
    cc[termios.VMIN] = 1
    termios.tcsetattr(slave, termios.TCSANOW, [0, 0, 0xBF, 0, termios.B38400, termios.B38400, cc])
    fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 37, 101, 0, 0))
    result = subprocess.run(
        [sys.argv[1], "--exact", "terminal_tests::u9_native_managed_pty", "--nocapture"],
        stdin=slave,
        capture_output=True,
        env={**os.environ, "PALUDARIUM_U9_HOST_CHILD": "1"},
        timeout=30,
    )
    sys.stdout.buffer.write(result.stdout)
    sys.stderr.buffer.write(result.stderr)
    sys.exit(result.returncode)
finally:
    os.close(slave)
    os.close(master)
