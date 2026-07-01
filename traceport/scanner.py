"""Core port scanning engine with multi-threading support."""

import socket
import threading
from typing import Optional, List, Callable, Set
from datetime import datetime
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed

from traceport.models import ScanResult, ServiceInfo
from traceport.utils import validate_ip, resolve_hostname, is_valid_port_range

logger = logging.getLogger(__name__)

class PortScanner:
    """High-performance port scanner with multi-threading support."""

    COMMON_SERVICES = {
        20: 'ftp-data', 21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp',
        53: 'dns', 80: 'http', 110: 'pop3', 143: 'imap', 443: 'https',
        445: 'smb', 3306: 'mysql', 3389: 'rdp', 5432: 'postgresql',
        5900: 'vnc', 8080: 'http-alt', 8443: 'https-alt', 9200: 'elasticsearch',
        27017: 'mongodb', 6379: 'redis',
    }

    BANNER_TIMEOUT = 2
    CONNECTION_TIMEOUT = 3

    def __init__(self, max_threads: int = 100, timeout: int = 3, banner_grab: bool = True):
        self.max_threads = max_threads
        self.timeout = timeout
        self.banner_grab = banner_grab
        self.stop_flag = False
        self.progress_callback: Optional[Callable] = None

    def scan(self, target: str, ports: Optional[List[int]] = None, port_range: Optional[str] = None) -> ScanResult:
        result = ScanResult(target=target)
        result.status = "scanning"
        result.scan_start_time = datetime.now()

        try:
            result.ip_address = validate_ip(target)
            if not result.ip_address:
                result.ip_address = socket.gethostbyname(target)
                result.hostname = target
            else:
                result.hostname = resolve_hostname(result.ip_address)

            ports_to_scan = self._parse_ports(ports, port_range)
            result.total_ports_scanned = len(ports_to_scan)

            open_ports = self._scan_ports(result.ip_address, ports_to_scan)
            result.open_ports = sorted(open_ports)

            if self.banner_grab:
                result.services = self._grab_banners(result.ip_address, result.open_ports)

            result.status = "completed"

        except socket.gaierror:
            result.error_message = f"Could not resolve hostname: {target}"
            result.status = "failed"
        except Exception as e:
            result.error_message = str(e)
            result.status = "failed"
            logger.error(f"Scan error: {e}")
        finally:
            result.scan_end_time = datetime.now()

        return result

    def _parse_ports(self, ports: Optional[List[int]], port_range: Optional[str]) -> List[int]:
        if ports:
            return ports
        if port_range:
            if is_valid_port_range(port_range):
                from traceport.utils import parse_port_range
                return parse_port_range(port_range)
            else:
                raise ValueError(f"Invalid port range: {port_range}")
        return list(self.COMMON_SERVICES.keys())

    def _scan_ports(self, host: str, ports: List[int]) -> Set[int]:
        open_ports = set()
        total = len(ports)
        completed = 0

        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = {executor.submit(self._check_port, host, port): port for port in ports}

            for future in as_completed(futures):
                if self.stop_flag:
                    executor.shutdown(wait=False)
                    break

                port = futures[future]
                try:
                    if future.result():
                        open_ports.add(port)
                except Exception as e:
                    logger.debug(f"Port {port} check error: {e}")

                completed += 1
                if self.progress_callback:
                    self.progress_callback(completed, total)

        return open_ports

    def _check_port(self, host: str, port: int) -> bool:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                result = sock.connect_ex((host, port))
                return result == 0
        except socket.timeout:
            return False
        except Exception as e:
            logger.debug(f"Error checking port {port}: {e}")
            return False

    def _grab_banners(self, host: str, ports: List[int]) -> List[ServiceInfo]:
        services = []
        with ThreadPoolExecutor(max_workers=min(10, len(ports))) as executor:
            futures = {executor.submit(self._grab_banner, host, port): port for port in ports}
            for future in as_completed(futures):
                port = futures[future]
                try:
                    service_info = future.result()
                    services.append(service_info)
                except Exception as e:
                    logger.debug(f"Banner grab error on port {port}: {e}")
                    services.append(ServiceInfo(port=port, service_name=self.COMMON_SERVICES.get(port, "unknown")))
        return sorted(services, key=lambda x: x.port)

    def _grab_banner(self, host: str, port: int) -> ServiceInfo:
        service_info = ServiceInfo(port=port, service_name=self.COMMON_SERVICES.get(port, "unknown"))
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.BANNER_TIMEOUT)
                sock.connect((host, port))
                try:
                    banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                    if banner:
                        service_info.banner = banner
                        if '/' in banner:
                            parts = banner.split('/')
                            if len(parts) > 1:
                                service_info.version = parts[1].split()[0]
                except socket.timeout:
                    pass
        except Exception as e:
            logger.debug(f"Error grabbing banner on {host}:{port}: {e}")
        return service_info

    def stop(self):
        self.stop_flag = True

    def set_progress_callback(self, callback: Callable[[int, int], None]):
        self.progress_callback = callback
