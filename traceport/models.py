"""Advanced data models for TracePort v2 - Professional Network Scanner."""

from dataclasses import dataclass, field
from typing import Optional, List, Dict
from datetime import datetime
import json


# =========================
#  SERVICE INFORMATION
# =========================

@dataclass
class ServiceInfo:
    """Detailed service detection info."""

    port: int
    service_name: str = "unknown"
    version: Optional[str] = None
    banner: Optional[str] = None
    protocol: str = "TCP"

    #  NEW: security & intelligence fields
    risk: str = "UNKNOWN"        # LOW / MEDIUM / HIGH / CRITICAL
    state: str = "open"          # open / filtered
    product: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "port": self.port,
            "service_name": self.service_name,
            "version": self.version,
            "banner": self.banner,
            "protocol": self.protocol,
            "risk": self.risk,
            "state": self.state,
            "product": self.product,
        }


# =========================
# 🔥 SCAN RESULT (MAIN)
# =========================

@dataclass
class ScanResult:
    """Complete scan result for a target host."""

    # Target info
    target: str
    hostname: Optional[str] = None
    ip_address: Optional[str] = None

    # Scan data
    open_ports: List[int] = field(default_factory=list)
    services: List[ServiceInfo] = field(default_factory=list)
    filtered_ports: List[int] = field(default_factory=list)

    # Timing
    scan_start_time: Optional[datetime] = None
    scan_end_time: Optional[datetime] = None

    # Metadata
    total_ports_scanned: int = 0
    scan_type: str = "TCP"  # TCP / SYN / UDP (future ready)
    status: str = "pending"
    error_message: Optional[str] = None

    #  NEW: security summary
    risk_score: int = 0
    risk_level: str = "UNKNOWN"  # LOW / MEDIUM / HIGH / CRITICAL

    # =========================
    #  DERIVED METRICS
    # =========================

    @property
    def scan_duration(self) -> Optional[float]:
        if self.scan_start_time and self.scan_end_time:
            return (self.scan_end_time - self.scan_start_time).total_seconds()
        return None

    @property
    def open_ports_count(self) -> int:
        return len(self.open_ports)

    @property
    def high_risk_ports(self) -> List[int]:
        return [s.port for s in self.services if s.risk in ["HIGH", "CRITICAL"]]

    # =========================
    # 📦 EXPORT METHODS
    # =========================

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "hostname": self.hostname,
            "ip_address": self.ip_address,

            "open_ports": self.open_ports,
            "filtered_ports": self.filtered_ports,

            "services": [s.to_dict() for s in self.services],

            "scan_start_time": self.scan_start_time.isoformat() if self.scan_start_time else None,
            "scan_end_time": self.scan_end_time.isoformat() if self.scan_end_time else None,
            "scan_duration": self.scan_duration,

            "total_ports_scanned": self.total_ports_scanned,
            "scan_type": self.scan_type,
            "status": self.status,
            "error_message": self.error_message,

            # 🔥 security summary
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "high_risk_ports": self.high_risk_ports,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)

    def to_csv_row(self) -> str:
        return (
            f"{self.target},"
            f"{self.ip_address},"
            f"{self.hostname},"
            f"{self.open_ports_count},"
            f"{'|'.join(map(str, self.open_ports))},"
            f"{self.scan_duration},"
            f"{self.risk_level}"
        )


# =========================
# 🔥 SECURITY SUMMARY MODEL
# =========================

@dataclass
class SecuritySummary:
    """High-level security overview for reports."""

    target: str
    risk_score: int
    risk_level: str
    total_open_ports: int
    high_risk_services: int
    recommendations: List[str] = field(default_factory=list)

    def to_dict(self):
        return {
            "target": self.target,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "total_open_ports": self.total_open_ports,
            "high_risk_services": self.high_risk_services,
            "recommendations": self.recommendations,
        }
