"""TracePort - High-performance Network Port Scanner

A Python-based network port scanner with multi-threading support,
banner grabbing, and dual GUI/CLI interfaces.
"""

__version__ = "1.0.0"
__author__ = "PasinduW-sketch"
__description__ = "High-performance Network Port Scanner with GUI and CLI"

from traceport.scanner import PortScanner
from traceport.models import ScanResult, ServiceInfo

__all__ = ["PortScanner", "ScanResult", "ServiceInfo"]
