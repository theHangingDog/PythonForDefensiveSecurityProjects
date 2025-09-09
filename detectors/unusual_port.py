# detectors/unusual_port.py
# Detects if known services are running on non-standard ports

standard_ports = {
    # Web & Browsing
    "HTTP": 80,
    "HTTPS": 443,
    "HTTP Alternate": 8080,
    "HTTPS Alternate": 8443,

    # File Transfer
    "FTP Data": 20,
    "FTP Control": 21,
    "SSH": 22,
    "TFTP": 69,

    # Remote Access
    "Telnet": 23,
    "RDP": 3389,
    "VNC": 5900,

    # Email
    "SMTP": 25,
    "POP3": 110,
    "IMAP": 143,

    # DNS & Directory
    "DNS": 53,
    "mDNS": 5353,
    "LDAP": 389,
    "Kerberos": 88,
    "SMB": 445,

    # Databases
    "MySQL": 3306,
    "PostgreSQL": 5432,
    "MSSQL": 1433,

    # VPN & Tunneling
    "OpenVPN": 1194,
    "WireGuard": 51820,

    # Monitoring
    "SNMP": 161,
    "Syslog": 514,
    "NTP": 123,
    "SSDP": 1900,
}

# Reverse lookup: port → service
port_to_service = {p: s for s, p in standard_ports.items()}

# Ignore ephemeral client-side ports
EPHEMERAL_RANGE = range(49152, 65536)

# Whitelist: system/multicast ports that are noisy but legitimate
whitelist_ports = {5353, 1900, 67, 68, 123}


def detect_unusual_ports(flow):
    """Detect unusual port usage in network flow."""
    alerts = []
    src_ip = flow.get("src_ip")
    dst_ip = flow.get("dst_ip")
    src_port = flow.get("src_port")
    dst_port = flow.get("dst_port")
    proto = flow.get("protocol", "").upper()

    # Ignore ephemeral ports
    if dst_port in EPHEMERAL_RANGE or src_port in EPHEMERAL_RANGE:
        return alerts

    # Ignore whitelisted system ports
    if dst_port in whitelist_ports or src_port in whitelist_ports:
        return alerts

    # If port is known, check if service matches
    if dst_port in port_to_service:
        # Service is running on standard port → fine
        return alerts

    # Otherwise, raise anomaly: unknown service on uncommon port
    alerts.append(
        f"[Unusual Port] {proto} traffic {src_ip}:{src_port} -> {dst_ip}:{dst_port} "
        f"(no known standard service for port {dst_port})"
    )

    # Common backdoor ports
    backdoor_ports = {
        31337,       # Back Orifice
        12345, 12346,  # NetBus
        20034,       # NetBus Pro
        9999,        # Common backdoor
        4444,        # Metasploit default
        6666, 6667,   # IRC (sometimes malicious)
        1337,        # Common backdoor
        2222,        # SSH on non-standard port
        8008,        # Alternative HTTP
        7777         # Common backdoor
    }
        
    if dst_port in backdoor_ports:
        alerts.append(f"[Unusual Port] Known backdoor port detected: {dst_port}")

    return alerts
