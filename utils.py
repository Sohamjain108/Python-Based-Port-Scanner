#!/usr/bin/env python3
"""
Utility Functions for Port Scanner
"""

import socket
import re
from datetime import datetime


# ANSI color codes
COLORS = {
    "green":  "\033[92m",
    "red":    "\033[91m",
    "yellow": "\033[93m",
    "cyan":   "\033[96m",
    "white":  "\033[97m",
    "reset":  "\033[0m",
}


def colorize(text: str, color: str) -> str:
    """Return colored text using ANSI codes."""
    return f"{COLORS.get(color, '')}{text}{COLORS['reset']}"


def validate_target(target: str) -> bool:
    """Validate that target is a valid IP or hostname."""
    try:
        socket.gethostbyname(target)
        return True
    except socket.error:
        return False


def parse_ports(port_str: str) -> list:
    """
    Parse port specification string into a list of integers.

    Supports:
        - Single port:  "80"
        - Range:        "1-1024"
        - List:         "22,80,443"
        - Mixed:        "22,80,1000-2000"
    """
    ports = set()

    for part in port_str.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-", 1)
            ports.update(range(int(start), int(end) + 1))
        else:
            ports.add(int(part))

    return sorted(ports)


def print_header(target: str, port_count: int, threads: int):
    """Print a formatted scan header."""
    separator = "=" * 62
    print(colorize(separator, "cyan"))
    print(colorize("        Python Port Scanner v1.0 | github.com/YOUR_USERNAME", "white"))
    print(colorize(separator, "cyan"))
    print(colorize(f"  [*] Target     : {target}", "white"))
    print(colorize(f"  [*] Ports      : {port_count} ports", "white"))
    print(colorize(f"  [*] Threads    : {threads}", "white"))
    print(colorize(f"  [*] Started    : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", "white"))
    print(colorize("-" * 62, "cyan"))


def print_footer(open_count: int, duration: float):
    """Print a formatted scan footer."""
    separator = "=" * 62
    print(colorize("-" * 62, "cyan"))
    print(colorize(f"  [*] Open Ports : {open_count}", "green" if open_count > 0 else "white"))
    print(colorize(f"  [*] Duration   : {duration:.2f} seconds", "white"))
    print(colorize(separator, "cyan"))
