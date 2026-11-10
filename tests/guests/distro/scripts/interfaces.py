"""The loopback through netlink: iproute2's ip (links, addresses and
routes), and glibc's getifaddrs and if_nameindex. Only lo is shown, as a
container has its own interfaces too; setting it needs CAP_NET_ADMIN,
which neither an unprivileged container's root nor a user has, so a user
tries."""

import ctypes
import socket
import subprocess
import sys

# lo has ::1 only where IPv6 is enabled on it. The output compared expects it,
# as the CI runner's container has it; this setting, on standard error, which
# is not compared, tells such a difference apart from an emulator bug.
try:
    with open("/proc/sys/net/ipv6/conf/lo/disable_ipv6") as setting:
        print("disable_ipv6", setting.read().strip(), file=sys.stderr)
except OSError as error:
    print("disable_ipv6 unreadable:", error, file=sys.stderr)


def run(*argv):
    process = subprocess.run(argv, capture_output=True, text=True)
    print(" ".join(argv[-4:]), "->", process.returncode)
    print(process.stdout, end="")


run("/usr/bin/ip", "-o", "link", "show", "lo")
run("/usr/bin/ip", "-o", "addr", "show", "lo")
run("/usr/bin/ip", "-o", "-4", "addr", "show", "dev", "lo")
# Routes through lo alone: the kernel's for 127.0.0.1/8 and ::1, in the
# local table.
run("/usr/bin/ip", "-4", "route", "show", "table", "all", "dev", "lo")
run("/usr/bin/ip", "-6", "route", "show", "table", "all", "dev", "lo")
# Lookups of a loopback address, the table entry it matched, and ::1.
run("/usr/bin/ip", "route", "get", "127.1.2.3")
run("/usr/bin/ip", "route", "get", "fibmatch", "127.1.2.3")
run("/usr/bin/ip", "-6", "route", "get", "::1")
run(
    "/usr/bin/setpriv",
    "--reuid=65534",
    "--regid=65534",
    "--clear-groups",
    "/usr/bin/ip",
    "link",
    "set",
    "lo",
    "up",
)


class SockAddr(ctypes.Structure):
    _fields_ = [("family", ctypes.c_ushort), ("data", ctypes.c_ubyte * 26)]


class IfAddrs(ctypes.Structure):
    pass


IfAddrs._fields_ = [
    ("next", ctypes.POINTER(IfAddrs)),
    ("name", ctypes.c_char_p),
    ("flags", ctypes.c_uint),
    ("addr", ctypes.POINTER(SockAddr)),
    ("netmask", ctypes.POINTER(SockAddr)),
    ("broadaddr", ctypes.c_void_p),
    ("data", ctypes.c_void_p),
]


def text(address):
    """An AF_INET or AF_INET6 address as text, empty for another family."""
    if not address:
        return ""
    raw = bytes(address.contents.data)
    family = address.contents.family
    if family == socket.AF_INET:
        return socket.inet_ntop(family, raw[2:6])
    if family == socket.AF_INET6:
        return socket.inet_ntop(family, raw[6:22])
    return ""


libc = ctypes.CDLL("libc.so.6", use_errno=True)
head = ctypes.POINTER(IfAddrs)()
print("getifaddrs", libc.getifaddrs(ctypes.byref(head)))
entry = head
while entry:
    e = entry.contents
    if e.name == b"lo":
        family = e.addr.contents.family if e.addr else -1
        flags = e.flags & (0x1 | 0x8 | 0x40)
        print("lo", family, hex(flags), text(e.addr), text(e.netmask), bool(e.data))
    entry = e.next
libc.freeifaddrs(head)

print("nameindex", [pair for pair in socket.if_nameindex() if pair[1] == "lo"])
print("nametoindex", socket.if_nametoindex("lo"), "indextoname", socket.if_indextoname(1))
try:
    socket.if_nametoindex("nosuchif")
except OSError as error:
    print("nosuchif", error.errno)
