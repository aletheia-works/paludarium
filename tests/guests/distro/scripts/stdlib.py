"""More of Python's library: process pools, selectors, mmap, resource limits and fcntl."""

import concurrent.futures
import fcntl
import mmap
import os
import resource
import selectors
import socket
import struct
import tempfile


def cube(n):
    return n**3


if __name__ == "__main__":
    with concurrent.futures.ProcessPoolExecutor(3) as pool:
        print("pool", list(pool.map(cube, range(6))))
    with concurrent.futures.ThreadPoolExecutor(4) as pool:
        print("threads", sorted(pool.map(cube, range(6))))

    left, right = socket.socketpair()
    selector = selectors.DefaultSelector()
    selector.register(left, selectors.EVENT_READ)
    right.send(b"ping")
    events = selector.select(timeout=1)
    print("selector", [key.fileobj is left for key, _ in events], left.recv(4))

    with tempfile.TemporaryFile() as f:
        f.write(b"\0" * 4096)
        f.flush()
        with mmap.mmap(f.fileno(), 4096) as m:
            m[:5] = b"hello"
            m.flush()
        f.seek(0)
        print("mmap", f.read(5))
        flags = fcntl.fcntl(f.fileno(), fcntl.F_GETFL)
        print("fcntl append", bool(flags & os.O_APPEND))

    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    resource.setrlimit(resource.RLIMIT_NOFILE, (min(256, hard), hard))
    print("nofile", resource.getrlimit(resource.RLIMIT_NOFILE)[0])
    print("affinity", len(os.sched_getaffinity(0)) == os.cpu_count())
    r, w = os.pipe()
    print("FIONREAD", struct.unpack("i", fcntl.ioctl(r, 0x541B, b"\0" * 4))[0])
    os.write(w, b"abc")
    print("FIONREAD", struct.unpack("i", fcntl.ioctl(r, 0x541B, b"\0" * 4))[0])
