"""Data models for TracePort scanner results."""

from dataclasses import dataclass, field
from typing import Optional, List
from datetime import datetime
import json


@dataclass
class ServiceInfo:
    """Information about a detected service."""
    port: int
    service_name: Optional[str] = None
    version: Optional[str] = None
    banner: Optional[str] = None
    protocol: str = "TCP"

    def to_dict(self) -> dict:
        return {
            'port': self.port,
            'service_name': self.service_name,
            'version': self.version,
            'banner': self.banner,
            'protocol': self.protocol
        }


@dataclass
class ScanResult:
    """Result of a network scan operation."""
    target: str
    hostname: Optional[str] = None
    ip_address: Optional[str] = None
    open_ports: List[int] = field(default_factory=list)
    services: List[ServiceInfo] = field(default_factory=list)
    scan_start_time: Optional[datetime] = None
    scan_end_time: Optional[datetime] = None
    total_ports_scanned: int = 0
    error_message: Optional[str] = None
    status: str = "pending"

    @property
    def scan_duration(self) -> Optional[float]:
        if self.scan_start_time and self.scan_end_time:
            return (self.scan_end_time - self.scan_start_time).total_seconds()
        return None

    @property
    def open_ports_count(self) -> int:
        return len(self.open_ports)

    def to_dict(self) -> dict:
        return {
            'target': self.target,
            'hostname': self.hostname,
            'ip_address': self.ip_address,
            'open_ports': self.open_ports,
            'services': [s.to_dict() for s in self.services],
            'scan_start_time': self.scan_start_time.isoformat() if self.scan_start_time else None,
            'scan_end_time': self.scan_end_time.isoformat() if self.scan_end_time else None,
            'total_ports_scanned': self.total_ports_scanned,
            'scan_duration': self.scan_duration,
            'open_ports_count': self.open_ports_count,
            'status': self.status,
            'error_message': self.error_message
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)

    def to_csv_row(self) -> str:
        return f"{self.target},{self.ip_address},{self.hostname},{len(self.open_ports)},{','.join(map(str, self.open_ports))},{self.scan_duration}"
