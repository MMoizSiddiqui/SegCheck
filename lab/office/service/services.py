"""Office system emulator: TCP listeners and a DNS responder for the ports in $SERVICES."""
import os
import socket
import threading


def tcp(port):
    server = socket.socket()
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", port))
    server.listen(32)
    while True:
        connection, _ = server.accept()
        connection.close()


def udp_dns(port):
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.bind(("0.0.0.0", port))
    while True:
        query, peer = server.recvfrom(512)
        if len(query) >= 12:
            server.sendto(query[:2] + b"\x81\x83" + query[4:6] + b"\x00" * 6 + query[12:], peer)


for spec in os.environ.get("SERVICES", "").split():
    proto, port = spec.split(":")
    threading.Thread(target=tcp if proto == "tcp" else udp_dns, args=(int(port),), daemon=True).start()
print(f"{os.environ.get('NAME', 'service')} up: {os.environ.get('SERVICES')}", flush=True)
threading.Event().wait()
