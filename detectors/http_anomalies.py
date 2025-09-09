#detectors/http_anomalies.py
#looks for strange http behaviour and extract payload if possible

import re

suspicious_user_agent = [
    # Recon & Scanning
    "nmap",
    "masscan",
    "zmap",
    "zgrab",
    "nikto",
    "skipfish",
    "dirbuster",
    "dirb",
    "whatweb",
    "httprobe",
    "w3af",
    "arachni",
    "OpenVAS",
    "nessus",
    "acunetix",
    "netsparker",

    # Brute-force & exploitation
    "hydra",
    "medusa",
    "patator",
    "sqlmap",
    "commix",
    "XSSer",
    "wpscan",
    "joomscan",
    "fimap",

    # C2 & malware frameworks
    "Empire",
    "CobaltStrike",
    "Metasploit",
    "DarkCloud",
    "Project1",
    "Project1sqlite",
    "Arkei",
    "Lokibot",
    "Matanbuchus",
    "katz-ontop",
    "botnet",
    "bot",

    # Headless & automation
    "phantomjs",
    "selenium",
    "puppeteer",
    "headless",
    "scrapy",
    "mechanize",
    "spider",
    "crawler",
    "robot",
    "auto",
    "scan",
    "probe",

    # CLI & scripting tools
    "curl",
    "wget",
    "python-requests",
    "httpie",
    "libwww-perl",
    "lwp-trivial",
    "Go-http-client",
    "Java/",
    "Apache-HttpClient",
    "okhttp",
    "axios",
    "rest-client",
    "httpclient",
    "urllib",
    "aiohttp",
    "node-fetch",
    "undici",

    # Suspicious mobile/IoT agents
    "Dalvik",
    "Stagefright",
    "AndroidDownloadManager",
    "Mozilla/5.0 (Linux; U; Android",
    "Baiduspider",
    "YandexBot",
    "MJ12bot",
    "AhrefsBot",
    "SemrushBot",
    "DotBot",
    "PetalBot",

    # Empty or malformed
    "",
    "-",
    "null",
    "undefined",
    "unknown",
    "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)",  # often spoofed
]

def detect_http_anomalies(flow: dict) -> list:
    """Detects suspicious http behaviour"""
    alerts = []
    if flow.get("protocol") != "TCP" or flow.get("dst_port") not in (80,8080,8082,8888,8000):
        return alerts
    http_info = flow.get("http", {})

    user_agent = http_info.get("user_agent", "").lower()
    if any(ua in user_agent for ua in suspicious_user_agent):
        alerts.append(f"[HTTP] Suspicious User-Agent: {user_agent}")
    if http_info.get("method") == "POST" and http_info.get("body_length", 0) > 5000:
        alerts.append(f"[HTTP] Large POST body ({http_info['body_length']}) bytes")
    content_type = http_info.get("content_type", "").lower()

    if content_type and not any( x in content_type for x in ["json", "html", "xml", "plain", "form"]):
        alerts.append(f"[HTTP] Unusual Content-Type: {content_type}")

    uri = http_info.get("uri", "")
    base64_pattern = r"(?:[A-Za-z0-9+/]{20,}={0,2})"
    match = re.search(base64_pattern, uri)

    if match or re.search(r"(?:[a-f0-9]{32,})", uri):
        alerts.append(f"[HTTP] Obfuscated or encoded URI: {uri}")

    return alerts