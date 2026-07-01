"""Upgraded Core Port Scanning Engine - TracePort v2"""

import socket
from datetime import datetime
from typing import Optional, List, Callable, Set, Dict
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging

from traceport.models import ScanResult, ServiceInfo
from traceport.utils import validate_ip, resolve_hostname, parse_port_range
from traceport.risk import get_risk   # 🔥 NEW

logger = logging.getLogger(__name__)


class PortScanner:
    """High-performance advanced port scanner."""

    # 🔥 Improved service database
    SERVICES: Dict[int, str] = {
        20: "FTP-DATA",
        21: "FTP",
        22: "SSH",
        23: "TELNET",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        110: "POP3",
        139: "NETBIOS",
        143: "IMAP",
        443: "HTTPS",
        445: "SMB",
        3389: "RDP",
        8080: "HTTP-PROXY",
    }

    def __init__(self, max_threads=100, timeout=2, banner_grab=True):
        self.max_threads = max_threads
        self.timeout = timeout
        self.banner_grab = banner_grab
        self.stop_flag = False
        self.progress_callback: Optional[Callable] = None

    # ---------------- MAIN SCAN ---------------- #

    def scan(self, target: str, ports: Optional[List[int]] = None, port_range: Optional[str] = None) -> ScanResult:

        result = ScanResult(target=target)
        result.scan_start_time = datetime.now()
        result.status = "scanning"

        try:
            # Resolve target
            result.ip_address = validate_ip(target)
            if not result.ip_address:
                result.ip_address = socket.gethostbyname(target)
                result.hostname = target
            else:
                result.hostname = resolve_hostname(result.ip_address)

            # Ports
            ports_to_scan = self._get_ports(ports, port_range)
            result.total_ports_scanned = len(ports_to_scan)

            # Scan ports
            open_ports = self._scan_ports(result.ip_address, ports_to_scan)
            result.open_ports = sorted(open_ports)

            # Banner grabbing
            if self.banner_grab and open_ports:
                result.services = self._grab_services(result.ip_address, open_ports)

            result.status = "completed"

        except Exception as e:
            result.status = "failed"
            result.error_message = str(e)
            logger.error(f"Scan error: {e}")

        finally:
            result.scan_end_time = datetime.now()

        return result

    # ---------------- PORT LIST ---------------- #

    def _get_ports(self, ports, port_range):
        if ports:
            return ports
        if port_range:
            return parse_port_range(port_range)
        return list(self.SERVICES.keys())

    # ---------------- SCAN ENGINE ---------------- #

    def _scan_ports(self, host: str, ports: List[int]) -> Set[int]:
        open_ports = set()
        total = len(ports)

        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = {executor.submit(self._check_port, host, p): p for p in ports}

            for i, future in enumerate(as_completed(futures), 1):
                if self.stop_flag:
                    break

                port = futures[future]
                try:
                    if future.result():
                        open_ports.add(port)
                except:
                    pass

                if self.progress_callback:
                    self.progress_callback(i, total)

        return open_ports

    # ---------------- PORT CHECK ---------------- #

    def _check_port(self, host: str, port: int) -> bool:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(self.timeout)
                return s.connect_ex((host, port)) == 0
        except:
            return False

    # ---------------- BANNER + SERVICE DETECTION ---------------- #

    def _grab_services(self, host: str, ports: List[int]) -> List[ServiceInfo]:
        results = []

        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {executor.submit(self._detect_service, host, p): p for p in ports}

            for future in as_completed(futures):
                try:
                    results.append(future.result())
                except:
                    pass

        return sorted(results, key=lambda x: x.port)

    def _detect_service(self, host: str, port: int) -> ServiceInfo:
        service = ServiceInfo(
            port=port,
            service_name=self.SERVICES.get(port, "UNKNOWN"),
        )

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(self.timeout)
                s.connect((host, port))

                banner = b""

                # 🔥 HTTP detection
                if port in [80, 8080, 443]:
                    s.send(b"GET / HTTP/1.1\r\nHost: %b\r\n\r\n" % host.encode())
                    banner = s.recv(4096)

                # 🔥 SSH detection
                elif port == 22:
                    banner = s.recv(1024)

                # 🔥 SMB / others
                else:
                    banner = s.recv(1024)

                text = banner.decode(errors="ignore").strip()

                if text:
                    service.banner = text

                    # HTTP parsing
                    if "HTTP/" in text:
                        service.service_name = "HTTP"
                        if "Server:" in text:
                            service.version = text.split("Server:")[1].split("\r\n")[0].strip()

                    # SSH parsing
                    elif "SSH" in text:
                        service.service_name = "SSH"
                        service.version = text.split("-")[1] if "-" in text else None

                # 🔥 Risk classification
                service.risk = get_risk(port, service.service_name)

        except:
            service.risk = get_risk(port, service.service_name)

        return service

    # ---------------- STOP ---------------- #

    def stop(self):
        self.stop_flag = True

    # ---------------- CALLBACK ---------------- #

    def set_progress_callback(self, cb: Callable[[int, int], None]):
        self.progress_callback = cb
