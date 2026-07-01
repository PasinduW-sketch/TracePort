"""TracePort v2 - Advanced Port Scanner Engine."""

import socket
import time
import ssl
import threading
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

from traceport.models import ScanResult, ServiceInfo


class PortScannerV2:
    """Advanced professional-grade port scanner."""

    COMMON_SERVICES = {
        22: "ssh",
        23: "telnet",
        80: "http",
        443: "https",
        445: "smb",
        3306: "mysql",
        3389: "rdp",
        8080: "http-proxy",
    }

    HIGH_RISK_PORTS = {23, 445, 3389}
    MEDIUM_RISK_PORTS = {22, 3306, 5432}
    LOW_RISK_PORTS = {80, 443, 8080}

    def __init__(self, threads=100, timeout=2, banner=True):
        self.threads = threads
        self.timeout = timeout
        self.banner = banner
        self.stop_flag = False

    # ---------------------------
    # MAIN SCAN
    # ---------------------------
    def scan(self, target, ports):
        result = ScanResult(target=target)
        result.scan_start_time = datetime.now()
        result.status = "running"

        ip = socket.gethostbyname(target)
        result.ip_address = ip
        result.hostname = target

        open_ports = self._scan_ports(ip, ports)
        result.open_ports = sorted(open_ports)

        services = []
        for port in open_ports:
            info = self._analyze_port(ip, port)
            services.append(info)

        result.services = services
        self._compute_risk(result)

        result.scan_end_time = datetime.now()
        result.status = "completed"

        return result

    # ---------------------------
    # PORT SCANNING
    # ---------------------------
    def _scan_ports(self, host, ports):
        open_ports = set()

        with ThreadPoolExecutor(max_workers=self.threads) as ex:
            futures = {ex.submit(self._check_port, host, p): p for p in ports}

            for f in as_completed(futures):
                if self.stop_flag:
                    break
                port = futures[f]
                try:
                    if f.result():
                        open_ports.add(port)
                except:
                    pass

        return open_ports

    def _check_port(self, host, port):
        try:
            with socket.socket() as s:
                s.settimeout(self.timeout)
                return s.connect_ex((host, port)) == 0
        except:
            return False

    # ---------------------------
    # INTELLIGENT ANALYSIS
    # ---------------------------
    def _analyze_port(self, host, port):
        start = time.time()

        service = ServiceInfo(
            port=port,
            service_name=self.COMMON_SERVICES.get(port, "unknown"),
        )

        banner = self._grab_banner(host, port)
        service.banner = banner

        # 🔥 HTTP detection
        if port in [80, 8080]:
            service.banner = self._http_probe(host, port)

        # 🔥 SSH detection
        if port == 22:
            service.version = self._ssh_probe(host, port)

        service.response_time_ms = (time.time() - start) * 1000

        return service

    # ---------------------------
    # BANNER GRABBING
    # ---------------------------
    def _grab_banner(self, host, port):
        try:
            with socket.socket() as s:
                s.settimeout(self.timeout)
                s.connect((host, port))
                data = s.recv(1024)
                return data.decode(errors="ignore").strip()
        except:
            return None

    # ---------------------------
    # HTTP INTELLIGENCE
    # ---------------------------
    def _http_probe(self, host, port):
        try:
            s = socket.socket()
            s.settimeout(self.timeout)
            s.connect((host, port))

            request = f"HEAD / HTTP/1.1\r\nHost: {host}\r\n\r\n"
            s.send(request.encode())

            response = s.recv(2048).decode(errors="ignore")
            s.close()
            return response.split("\r\n")[0]
        except:
            return "HTTP service detected"

    # ---------------------------
    # SSH INTELLIGENCE
    # ---------------------------
    def _ssh_probe(self, host, port):
        try:
            s = socket.socket()
            s.settimeout(self.timeout)
            s.connect((host, port))
            banner = s.recv(1024).decode(errors="ignore")
            return banner.strip()
        except:
            return "SSH detected"

    # ---------------------------
    # RISK ENGINE 🔥
    # ---------------------------
    def _compute_risk(self, result: ScanResult):
        for s in result.services:
            if s.port in self.HIGH_RISK_PORTS:
                s.risk_level = "HIGH"
                result.high_risk_ports += 1

            elif s.port in self.MEDIUM_RISK_PORTS:
                s.risk_level = "MEDIUM"
                result.medium_risk_ports += 1

            else:
                s.risk_level = "LOW"
                result.low_risk_ports += 1

    def stop(self):
        self.stop_flag = True
