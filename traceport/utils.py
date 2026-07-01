"""Utility functions for TracePort."""

import socket
import re
from typing import Optional
import logging

logger = logging.getLogger(__name__)

def validate_ip(address: str) -> Optional[str]:
    ipv4_pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
    if re.match(ipv4_pattern, address):
        return address
    return None

def resolve_hostname(ip_address: str) -> Optional[str]:
    try:
        hostname, _, _ = socket.gethostbyaddr(ip_address)
        return hostname
    except (socket.herror, socket.timeout):
        return None

def get_service_name(port: int) -> str:
    try:
        return socket.getservbyport(port, 'tcp')
    except OSError:
        return 'unknown'

def is_valid_port_range(port_range: str) -> bool:
    try:
        for part in port_range.split(','):
            if '-' in part:
                start, end = part.split('-')
                start_port = int(start)
                end_port = int(end)
                if not (0 < start_port <= 65535 and 0 < end_port <= 65535 and start_port <= end_port):
                    return False
            else:
                port = int(part)
                if not (0 < port <= 65535):
                    return False
        return True
    except ValueError:
        return False

def parse_port_range(port_range: str) -> list:
    ports = []
    for part in port_range.split(','):
        if '-' in part:
            start, end = part.split('-')
            ports.extend(range(int(start), int(end) + 1))
        else:
            ports.append(int(part))
    return sorted(set(ports))

def setup_logging(level=logging.INFO):
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[logging.StreamHandler()]
    )
