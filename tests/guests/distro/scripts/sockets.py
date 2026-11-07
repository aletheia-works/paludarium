"""Sockets on the loopback: socket pairs, Unix and TCP streams, UDP, and select, poll and epoll."""

import os
import select
import socket
import tempfile
import threading

a, b = socket.socketpair()
a.sendall(b"pair")
print("socketpair", b.recv(10))

path = os.path.join(tempfile.mkdtemp(), "s")
server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
server.bind(path)
server.listen()


def echo(listener):
    connection, _ = listener.accept()
    with connection:
        while data := connection.recv(4096):
            connection.sendall(data.upper())


threading.Thread(target=echo, args=(server,), daemon=True).start()
client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
client.connect(path)
client.sendall(b"unix")
print("unix", client.recv(10))
client.close()

tcp = socket.create_server(("127.0.0.1", 0))
threading.Thread(target=echo, args=(tcp,), daemon=True).start()
with socket.create_connection(tcp.getsockname()) as connection:
    payload = bytes(range(256)) * 400
    connection.sendall(payload)
    connection.shutdown(socket.SHUT_WR)
    received = b""
    while data := connection.recv(65536):
        received += data
    print("tcp", len(received), received == payload.upper())

udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
udp.bind(("127.0.0.1", 0))
sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sender.sendto(b"datagram", udp.getsockname())
print("udp", udp.recvfrom(100)[0])

r, w = os.pipe()
print("select empty", select.select([r], [], [], 0)[0])
os.write(w, b"x")
print("select ready", select.select([r], [], [], 1)[0] == [r])
poller = select.poll()
poller.register(r, select.POLLIN)
print("poll", [(fd == r, mask & select.POLLIN != 0) for fd, mask in poller.poll(1000)])
epoll = select.epoll()
epoll.register(r, select.EPOLLIN)
print("epoll", [(fd == r, mask & select.EPOLLIN != 0) for fd, mask in epoll.poll(1)])
os.close(w)
print("eof", os.read(r, 10), os.read(r, 10))
