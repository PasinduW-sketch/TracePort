"""Risk classification module for TracePort."""

RISK_DB = {
    20: ("FTP-DATA", "LOW"),
    21: ("FTP", "LOW"),
    22: ("SSH", "MEDIUM"),
    23: ("TELNET", "HIGH"),
    25: ("SMTP", "LOW"),
    53: ("DNS", "LOW"),
    80: ("HTTP", "LOW"),
    110: ("POP3", "MEDIUM"),
    139: ("NETBIOS", "HIGH"),
    443: ("HTTPS", "LOW"),
    445: ("SMB", "HIGH"),
    3389: ("RDP", "CRITICAL"),
}

def get_risk(port: int, service: str = ""):
    service = service.upper()

    if port in RISK_DB:
        return RISK_DB[port][1]

    if "SSH" in service:
        return "MEDIUM"
    if "HTTP" in service:
        return "LOW"

    return "UNKNOWN"
