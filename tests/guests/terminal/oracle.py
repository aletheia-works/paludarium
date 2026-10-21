"""Run each native Linux guest under a controlled pipe or stdin-only PTY.
No expected output is saved: callers compare results from this execution.
"""

import fcntl
import os
import pty
import struct
import subprocess
import sys
import tempfile
import termios
from pathlib import Path


def run(directory, case):
    master = slave = None
    try:
        if case in (6, 7, 8, 9, 10, 13):
            master, slave = pty.openpty()
            cc = [b"\0"] * termios.NCCS
            cc[termios.VMIN] = 1
            termios.tcsetattr(
                slave,
                termios.TCSANOW,
                [
                    0,
                    0,
                    termios.CS8 | termios.CREAD | termios.B38400,
                    0,
                    termios.B38400,
                    termios.B38400,
                    cc,
                ],
            )
            fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 37, 101, 0, 0))
        arguments = ["u9", "", "two words"]
        with tempfile.TemporaryDirectory(prefix="paludarium-u9-") as fixture:
            if case == 11:
                file = Path(fixture) / "regular"
                file.write_bytes(b"fixture")
                arguments[1] = str(file)
            streams = (
                {"stdin": slave} if slave is not None else {"input": b"abc" if case == 1 else b""}
            )
            result = subprocess.run(
                arguments,
                executable=str(Path(directory).resolve() / f"io-{case}"),
                env={"U9_TEST": "value with spaces"},
                **streams,
                capture_output=True,
                timeout=30,
            )
        print(f"{case}|{result.returncode}|{result.stdout.hex()}|{result.stderr.hex()}", flush=True)
    finally:
        if slave is not None:
            os.close(slave)
        if master is not None:
            os.close(master)


if __name__ == "__main__":
    directory = sys.argv[1]
    for case in [int(sys.argv[2])] if len(sys.argv) > 2 else range(14):
        run(directory, case)
