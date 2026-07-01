"""Command-line interface for TracePort scanner."""

import argparse
import sys
import json
from typing import Optional
import logging

from traceport.scanner import PortScanner
from traceport.utils import setup_logging, is_valid_port_range, parse_port_range

logger = logging.getLogger(__name__)

def setup_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="TracePort - High-performance Network Port Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  %(prog)s localhost
  %(prog)s 192.168.1.1 -p 1-1000
  %(prog)s example.com -p 80,443,8080 --threads 50
  %(prog)s 10.0.0.1 -p 1-1000 --json output.json
        """
    )

    parser.add_argument('target', help='Target host (IP address or hostname)')
    parser.add_argument('-p', '--ports', help='Port range or list (e.g., 1-1000, 80,443,8080)', default=None)
    parser.add_argument('-t', '--threads', type=int, default=100, help='Maximum number of threads (default: 100)')
    parser.add_argument('--timeout', type=int, default=3, help='Connection timeout in seconds (default: 3)')
    parser.add_argument('--no-banner', action='store_true', help='Disable banner grabbing')
    parser.add_argument('-o', '--output', help='Output file for results (JSON format)')
    parser.add_argument('--csv', help='Export results as CSV file')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    parser.add_argument('--version', action='version', version='%(prog)s 1.0.0')

    return parser

def validate_arguments(args: argparse.Namespace) -> bool:
    if args.ports and not is_valid_port_range(args.ports):
        print(f"Error: Invalid port range '{args.ports}", file=sys.stderr)
        return False
    if args.threads < 1 or args.threads > 500:
        print("Error: Threads must be between 1 and 500", file=sys.stderr)
        return False
    if args.timeout < 1 or args.timeout > 30:
        print("Error: Timeout must be between 1 and 30 seconds", file=sys.stderr)
        return False
    return True

def display_results(scanner_result, verbose: bool = False):
    print("\n" + "="*60)
    print("TracePort Scan Results")
    print("="*60 + "\n")

    print(f"Target:           {scanner_result.target}")
    print(f"IP Address:       {scanner_result.ip_address or 'N/A'}")
    print(f"Hostname:         {scanner_result.hostname or 'N/A'}")
    print(f"Status:           {scanner_result.status}")
    print(f"Scan Duration:    {scanner_result.scan_duration:.2f}s" if scanner_result.scan_duration else "Scan Duration:    N/A")
    print(f"Ports Scanned:    {scanner_result.total_ports_scanned}")
    print(f"Open Ports Found: {scanner_result.open_ports_count}\n")

    if scanner_result.error_message:
        print(f"Error: {scanner_result.error_message}\n")
        return

    if scanner_result.open_ports:
        print("Open Ports:")
        print("-" * 60)
        print(f"  {', '.join(map(str, scanner_result.open_ports))}\n")

    if scanner_result.services:
        print("Service Information:")
        print("-" * 60)
        for service in scanner_result.services:
            print(f"Port {service.port}: {service.service_name} {service.version or ''}")
            if service.banner:
                print(f"  Banner: {service.banner[:60]}")

    print("\n" + "="*60 + "\n")

def export_json(result, filename: str):
    try:
        with open(filename, 'w') as f:
            f.write(result.to_json())
        print(f"Results exported to {filename}")
    except Exception as e:
        print(f"Error exporting to JSON: {e}", file=sys.stderr)

def export_csv(result, filename: str):
    try:
        with open(filename, 'w') as f:
            f.write("Port,Service,Version,Banner\n")
            for service in result.services:
                banner = service.banner.replace('"', '""') if service.banner else ""
                f.write(f'{service.port},"{service.service_name or "unknown"}","{service.version or ""}","{banner}"\n')
        print(f"Results exported to {filename}")
    except Exception as e:
        print(f"Error exporting to CSV: {e}", file=sys.stderr)

def main():
    parser = setup_argument_parser()
    args = parser.parse_args()

    log_level = logging.DEBUG if args.verbose else logging.INFO
    setup_logging(level=log_level)

    if not validate_arguments(args):
        sys.exit(1)

    ports = None
    if args.ports:
        ports = parse_port_range(args.ports)

    scanner = PortScanner(
        max_threads=args.threads,
        timeout=args.timeout,
        banner_grab=not args.no_banner
    )

    try:
        print(f"\nStarting scan of {args.target}...\n")
        result = scanner.scan(args.target, ports=ports)
        display_results(result, verbose=args.verbose)

        if args.output:
            export_json(result, args.output)
        if args.csv:
            export_csv(result, args.csv)

    except KeyboardInterrupt:
        print("\n\nScan interrupted by user", file=sys.stderr)
        sys.exit(130)
    except Exception as e:
        print(f"\nError: {e}", file=sys.stderr)
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
