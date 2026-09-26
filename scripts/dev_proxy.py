#!/usr/bin/env python3
"""Minimal HTTP CONNECT proxy (dev helper for Docker builds).

Why this exists: on this machine a VPN client on the Wi-Fi network silently
kills long TLS streams coming from Docker containers (pip/npm downloads die
with "[SSL] record layer failure") while the host's own connections work.
Docker Desktop exposes the host to containers as `host.docker.internal`, so
routing container traffic through this tiny host-side proxy restores working
package downloads.

Usage:
    python scripts/dev_proxy.py            # listen on 0.0.0.0:3128

Then build with the proxy (see README "Docker behind a VPN"):
    docker compose build --build-arg PIP_PROXY=http://host.docker.internal:3128

Only HTTPS CONNECT tunneling is implemented (bytes are relayed opaquely; the
proxy never sees decrypted content). Stdlib only, no dependencies.
"""
from __future__ import annotations

import select
import socket
import sys
import threading

LISTEN_ADDR = ("0.0.0.0", 3128)
IDLE_TIMEOUT = 120
BUFSIZE = 65536


def _relay(a: socket.socket, b: socket.socket) -> None:
    """Bidirectional byte relay between two sockets until either side closes."""
    sockets = [a, b]
    try:
        while True:
            readable, _, _ = select.select(sockets, [], [], IDLE_TIMEOUT)
            if not readable:
                break  # idle timeout
            for s in readable:
                data = s.recv(BUFSIZE)
                if not data:
                    return
                other = b if s is a else a
                other.sendall(data)
    except OSError:
        pass
    finally:
        for s in sockets:
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass


class ProxyHandler(threading.Thread):
    def __init__(self, client: socket.socket) -> None:
        super().__init__(daemon=True)
        self.client = client

    def run(self) -> None:
        try:
            self.client.settimeout(30)
            request = b""
            while b"\r\n\r\n" not in request:
                chunk = self.client.recv(8192)
                if not chunk:
                    return
                request += chunk
                if len(request) > 65536:
                    return
            head = request.split(b"\r\n", 1)[0].decode(errors="ignore")
            method, target, _version = (head.split(" ", 2) + ["", ""])[:3]

            if method.upper() != "CONNECT":
                # Plain HTTP is not needed for pip/npm (all HTTPS); reject clearly.
                self.client.sendall(
                    b"HTTP/1.1 405 Method Not Allowed\r\n"
                    b"Proxy-support: CONNECT-only\r\n\r\n"
                )
                return

            host, _, port = target.rpartition(":")
            port = int(port) if port else 443
            remote = socket.create_connection((host, port), timeout=30)
            remote.settimeout(None)
            self.client.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
            self.client.settimeout(None)
            _relay(self.client, remote)
        except OSError:
            pass
        finally:
            try:
                self.client.close()
            except OSError:
                pass


def main() -> None:
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(LISTEN_ADDR)
    server.listen(64)
    print(f"dev_proxy: listening on {LISTEN_ADDR[0]}:{LISTEN_ADDR[1]} (CONNECT only)", flush=True)
    try:
        while True:
            client, addr = server.accept()
            ProxyHandler(client).start()
    except KeyboardInterrupt:
        print("\ndev_proxy: stopped", file=sys.stderr)
    finally:
        server.close()


if __name__ == "__main__":
    main()
