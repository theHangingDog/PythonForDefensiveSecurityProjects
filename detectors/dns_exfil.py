# detectors/dns_exfil.py

import math
import re
from typing import List, Dict
from collections import Counter

def shannon_entropy(data: str) -> float:
    """Calculate Shannon entropy of a string"""
    if not data:
        return 0.0
    
    # Count character frequencies
    prob = [float(data.count(c)) / len(data) for c in set(data)]
    # Calculate entropy
    return -sum(p * math.log2(p) for p in prob if p > 0)


def detect_dns_tunneling_patterns(domain: str) -> List[str]:
    """Detect patterns common in DNS tunneling"""
    alerts = []
    
    # Check for base64-like patterns
    if re.search(r'^[A-Za-z0-9+/]{20,}={0,2}$', domain.split('.')[0]):
        alerts.append("Possible base64 encoding in subdomain")
    
    # Check for hex encoding patterns
    if re.search(r'^[0-9a-fA-F]{32,}$', domain.split('.')[0]):
        alerts.append("Possible hex encoding in subdomain")
    
    # Check for unusually long labels
    labels = domain.split('.')
    for label in labels[:-2]:  # Exclude TLD and domain
        if len(label) > 63:  # DNS label limit
            alerts.append(f"DNS label exceeds maximum length: {len(label)} chars")
        elif len(label) > 20:
            alerts.append(f"Unusually long DNS label: {len(label)} chars")
    
    # Check for high number of subdomains (subdomain chaining)
    if len(labels) > 5:
        alerts.append(f"Excessive subdomain depth: {len(labels)} levels")
    
    return alerts


def analyze_dns_behavior(dns_queries: List[Dict]) -> List[str]:
    """Analyze patterns across multiple DNS queries"""
    alerts = []
    
    if not dns_queries:
        return alerts
    
    # Extract query names
    query_names = [q.get("query_name", "") for q in dns_queries if q.get("query_name")]
    
    if not query_names:
        return alerts
    
    # Check for DGA (Domain Generation Algorithm) patterns
    subdomains = []
    for qname in query_names:
        parts = qname.split('.')
        if len(parts) > 2:
            subdomains.append(parts[0])  # Get subdomain
    
    if len(subdomains) >= 5:
        # Check if subdomains have similar length (DGA indicator)
        lengths = [len(s) for s in subdomains]
        avg_length = sum(lengths) / len(lengths)
        if all(abs(l - avg_length) < 3 for l in lengths) and avg_length > 10:
            alerts.append(f"Possible DGA pattern: {len(subdomains)} similar-length subdomains (avg {avg_length:.1f} chars)")
        
        # Check entropy consistency (DGA domains often have similar entropy)
        entropies = [shannon_entropy(s) for s in subdomains]
        if entropies:
            avg_entropy = sum(entropies) / len(entropies)
            if avg_entropy > 3.5 and all(abs(e - avg_entropy) < 0.5 for e in entropies):
                alerts.append(f"Consistent high entropy across subdomains: {avg_entropy:.2f}")
    
    # Check for data exfiltration via TXT records
    txt_records = [q for q in dns_queries if q.get("query_type") == "16"]  # Type 16 = TXT
    if len(txt_records) > 5:
        alerts.append(f"Excessive TXT record queries: {len(txt_records)} (possible data exfiltration)")
    
    # Check for uncommon query types that might indicate tunneling
    query_types = [q.get("query_type", "") for q in dns_queries]
    uncommon_types = {"10": "NULL", "16": "TXT", "33": "SRV", "99": "SPF", "255": "ANY"}
    for qtype, qname in uncommon_types.items():
        count = query_types.count(qtype)
        if count > 3:
            alerts.append(f"Multiple {qname} record queries: {count} (possible tunneling)")
    
    return alerts


def detect_dns_exfil(flow: dict) -> list:
    """Detect possible DNS exfiltration attempts"""
    alerts = []
    
    # Only analyze DNS (UDP/53 or TCP/53) traffic
    if flow.get("dst_port") != 53 and flow.get("src_port") != 53:
        return alerts
    
    # Get DNS queries from the flow
    dns_queries = flow.get("dns", [])
    
    # If no DNS data extracted, fall back to basic flow analysis
    if not dns_queries:
        # Basic flow-level checks
        if flow.get("protocol") == "TCP" and flow.get("dst_port") == 53:
            alerts.append("[DNS Exfil] DNS over TCP detected (unusual for normal queries)")
        
        if flow.get("packets", 0) > 50:
            alerts.append(f"[DNS Exfil] Excessive packets in DNS flow: {flow['packets']} packets")
        
        if flow.get("bytes", 0) > 10000:  # 10KB
            alerts.append(f"[DNS Exfil] Large DNS flow size: {flow['bytes']} bytes")
        
        return alerts
    
    # Analyze individual DNS queries
    for dns_entry in dns_queries:
        if not dns_entry.get("is_response", True):  # Only analyze queries, not responses
            query_name = dns_entry.get("query_name", "")
            
            if not query_name:
                continue
            
            # Remove trailing dot if present
            query_name = query_name.rstrip('.')
            
            # Basic checks
            if len(query_name) > 100:
                alerts.append(f"[DNS Exfil] Unusually long domain: {len(query_name)} chars - {query_name[:50]}...")
            
            # Calculate entropy of the full domain
            entropy = shannon_entropy(query_name)
            if entropy > 4.5:
                alerts.append(f"[DNS Exfil] High-entropy domain (possible encoded data): {entropy:.2f} - {query_name[:50]}...")
            
            # Check for suspicious patterns
            tunnel_patterns = detect_dns_tunneling_patterns(query_name)
            for pattern in tunnel_patterns:
                alerts.append(f"[DNS Exfil] {pattern}: {query_name[:50]}...")
            
            # Check for non-ASCII characters (uncommon in legitimate domains)
            if not all(ord(c) < 128 for c in query_name):
                alerts.append(f"[DNS Exfil] Non-ASCII characters in domain: {query_name[:50]}...")
            
            # Check for numeric-heavy domains (except IP addresses)
            if not re.match(r'^\d+\.\d+\.\d+\.\d+', query_name):  # Not an IP
                digit_ratio = sum(c.isdigit() for c in query_name) / len(query_name)
                if digit_ratio > 0.5:
                    alerts.append(f"[DNS Exfil] Numeric-heavy domain ({digit_ratio:.0%} digits): {query_name[:50]}...")
    
    # Behavioral analysis across all queries
    behavioral_alerts = analyze_dns_behavior(dns_queries)
    for alert in behavioral_alerts:
        alerts.append(f"[DNS Exfil] {alert}")
    
    # Check query frequency
    if len(dns_queries) > 20:
        unique_queries = len(set(q.get("query_name", "") for q in dns_queries))
        if unique_queries > 15:
            alerts.append(f"[DNS Exfil] High unique query count: {unique_queries} different domains in single flow")
    
    return alerts
