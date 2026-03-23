#!/usr/bin/env python3
"""
Banner Grabber Module
Attempts to grab service banners from open ports.
"""

import socket


def grab_banner(sock: socket.socket, port: int, timeout: float = 2.0) -> str:
    """
    Attempt to grab a service banner from an open socket.

    Args:
        sock: Connected socket object
        port: Port number (used to send appropriate probe)
        timeout: Read timeout in seconds

    Returns:
        Banner string (stripped), or empty string if none found
    """
    try:
        sock.settimeout(timeout)

        # For HTTP ports, send an HTTP request to get a response header
        if port in (80, 8080, 8000, 8443, 8888):
            sock.send(b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n")

        # For SMTP
        elif port in (25, 587, 465):
            pass  # SMTP sends banner on connect

        # For FTP
        elif port == 21:
            pass  # FTP sends banner on connect

        # For HTTPS/SSL — can't grab plaintext banner
        elif port == 443:
            return "SSL/TLS — use openssl s_client"

        # For SSH
        elif port == 22:
            pass  # SSH sends banner on connect

        # Generic probe for others
        else:
            sock.send(b"\r\n")

        banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
        # Return first line only (cleanest)
        return banner.splitlines()[0] if banner else ""

    except Exception:
        return ""
