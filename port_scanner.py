#!/usr/bin/env python3
"""
Python Port Scanner v1.0
Author: Your Name
Description: Multi-threaded TCP port scanner with banner grabbing
             and service identification capabilities.
Legal: Only use on systems you own or have explicit permission to test.
"""

import socket
import argparse
import threading
import json
import sys
import ipaddress
from datetime import datetime
from queue import Queue
from concurrent.futures import ThreadPoolExecutor, as_completed

from common_ports import COMMON_PORTS, TOP_1000_PORTS
from banner_grabber import grab_banner
from utils import validate_target, parse_ports, colorize, print_header, print_footer


# ─────────────────────────────────────────────
#  Core Scanner
# ─────────────────────────────────────────────

class PortScanner:
    """
    Multi-threaded TCP port scanner.

    Performs a TCP Connect scan (full 3-way handshake) against
    specified target(s) and port ranges.
    """

    def __init__(self, target: str, ports: list, threads: int = 100,
                 timeout: float = 1.0, banner: bool = False,
                 verbose: bool = False, output: str = None):
        self.target = target
        self.ports = ports
        self.threads = threads
        self.timeout = timeout
        self.banner = banner
        self.verbose = verbose
        self.output = output
        self.open_ports = []
        self.lock = threading.Lock()

    def scan_port(self, host: str, port: int) -> dict | None:
        """
        Attempt a TCP connect to host:port.
        Returns a result dict if open, None if closed/filtered.
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((host, port))  # 0 = success (open)

            if result == 0:
                service = COMMON_PORTS.get(port, "unknown")
                banner_text = ""
                if self.banner:
                    banner_text = grab_banner(sock, port)
                sock.close()

                return {
                    "port": port,
                    "protocol": "tcp",
                    "state": "open",
                    "service": service,
                    "banner": banner_text
                }
            else:
                sock.close()
                if self.verbose:
                    print(colorize(f"[-] Port {port:5d}/tcp  CLOSED", "red"))
                return None

        except socket.timeout:
            return None
        except socket.error:
            return None
        except Exception as e:
            if self.verbose:
                print(colorize(f"[!] Error on port {port}: {e}", "yellow"))
            return None

    def scan_host(self, host: str):
        """Scan all specified ports on a single host."""
        print(colorize(f"\n[*] Scanning {host} ...", "cyan"))

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self.scan_port, host, port): port
                       for port in self.ports}

            for future in as_completed(futures):
                result = future.result()
                if result:
                    with self.lock:
                        self.open_ports.append(result)
                    banner_str = f"  Banner: {result['banner']}" if result['banner'] else ""
                    print(colorize(
                        f"[+] Port {result['port']:5d}/{result['protocol']}  "
                        f"OPEN  {result['service']:<12}{banner_str}", "green"
                    ))

    def run(self):
        """Main entry point — resolve targets, run scans, export results."""
        print_header(self.target, len(self.ports), self.threads)

        start_time = datetime.now()

        # Expand CIDR or scan single host
        try:
            network = ipaddress.ip_network(self.target, strict=False)
            hosts = [str(ip) for ip in network.hosts()]
        except ValueError:
            hosts = [self.target]

        for host in hosts:
            if not validate_target(host):
                print(colorize(f"[!] Invalid target: {host}", "red"))
                continue
            self.scan_host(host)

        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()

        print_footer(len(self.open_ports), duration)

        if self.output:
            self.export_results(self.open_ports, self.output, duration)

    def export_results(self, results: list, filename: str, duration: float):
        """Export scan results to JSON or TXT."""
        report = {
            "target": self.target,
            "scan_time": datetime.now().isoformat(),
            "duration_seconds": round(duration, 2),
            "open_ports": results
        }

        if filename.endswith(".json"):
            with open(filename, "w") as f:
                json.dump(report, f, indent=4)
        else:
            with open(filename, "w") as f:
                f.write(f"Port Scan Report\n")
                f.write(f"Target: {self.target}\n")
                f.write(f"Date: {report['scan_time']}\n")
                f.write(f"Duration: {duration:.2f}s\n\n")
                for p in results:
                    f.write(f"[OPEN] {p['port']}/tcp  {p['service']}  {p['banner']}\n")

        print(colorize(f"\n[*] Results saved to: {filename}", "cyan"))


# ─────────────────────────────────────────────
#  CLI Argument Parser
# ─────────────────────────────────────────────

def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Python Port Scanner — TCP Connect Scan with Banner Grabbing",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("-t", "--target", required=True,
                        help="Target IP, hostname, or CIDR (e.g. 192.168.1.1 or 192.168.1.0/24)")
    parser.add_argument("-p", "--ports", default="top1000",
                        help="Ports to scan: range (1-1024), list (22,80,443), or 'top1000' (default)")
    parser.add_argument("--threads", type=int, default=100,
                        help="Number of threads (default: 100)")
    parser.add_argument("--timeout", type=float, default=1.0,
                        help="Socket timeout in seconds (default: 1.0)")
    parser.add_argument("--banner", action="store_true",
                        help="Enable banner grabbing")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Show closed ports too")
    parser.add_argument("--output",
                        help="Save results to file (.json or .txt)")
    return parser.parse_args()


# ─────────────────────────────────────────────
#  Entry Point
# ─────────────────────────────────────────────

if __name__ == "__main__":
    args = parse_arguments()

    if args.ports == "top1000":
        ports = TOP_1000_PORTS
    else:
        ports = parse_ports(args.ports)

    scanner = PortScanner(
        target=args.target,
        ports=ports,
        threads=args.threads,
        timeout=args.timeout,
        banner=args.banner,
        verbose=args.verbose,
        output=args.output
    )

    try:
        scanner.run()
    except KeyboardInterrupt:
        print(colorize("\n\n[!] Scan interrupted by user.", "yellow"))
        sys.exit(0)
