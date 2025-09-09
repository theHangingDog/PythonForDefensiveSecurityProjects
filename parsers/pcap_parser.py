# parsers/pcap_parser.py
import hashlib
from dataclasses import dataclass, field
from typing import Dict, List
import pyshark
from tqdm import tqdm


@dataclass
class Flow:
    flow_id: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    proto: str                 
    packets: int = 0
    bytes: int = 0
    timestamps: List[float] = field(default_factory=list)
    http: List[dict] = field(default_factory=list)
    dns: List[dict] = field(default_factory=list)



class PcapParser:
    def __init__(self, pcap_file: str):
        self.pcap_file = pcap_file

    def _make_flow_id(self, src_ip, dst_ip, src_port, dst_port, proto) -> str:
        """Generate a unique ID for a flow using md5 hash."""
        key = f"{src_ip}-{dst_ip}-{src_port}-{dst_port}-{proto}"
        return hashlib.md5(key.encode()).hexdigest()

    def _proto_to_name(self, proto: str) -> str:
        """Convert IP protocol number to name."""
        proto_map = {
            "6": "TCP",
            "17": "UDP", 
            "1": "ICMP",
            "2": "IGMP",
            "41": "IPv6",
            "47": "GRE",
            "50": "ESP",
            "51": "AH",
            "89": "OSPF",
            "132": "SCTP"
        }
        return proto_map.get(str(proto), f"Protocol-{proto}")

    def parse(self) -> Dict[str, Flow]:
        """Parse PCAP and return a dictionary of flows with timestamps."""
        try:
            cap = pyshark.FileCapture(self.pcap_file, keep_packets=False)
        except Exception as e:
            print(f"Error opening PCAP file: {e}")
            return {}
        
        flows: Dict[str, Flow] = {}

        for pkt in tqdm(cap, desc="Parsing packets", unit="pkt", unit_scale=True, dynamic_ncols=True):
            try:
                if not hasattr(pkt, "ip"): 
                    continue

                ip_layer = pkt.ip
                src_ip = ip_layer.src
                dst_ip = ip_layer.dst
                proto = ip_layer.proto

                # Timestamp (float seconds)
                timestamp = float(pkt.sniff_time.timestamp())

                # Extract ports
                if hasattr(pkt, "tcp"):
                    src_port = int(pkt.tcp.srcport)
                    dst_port = int(pkt.tcp.dstport)
                elif hasattr(pkt, "udp"):
                    src_port = int(pkt.udp.srcport)
                    dst_port = int(pkt.udp.dstport)
                else:
                    src_port = dst_port = 0  # non-TCP/UDP traffic

                # Flow key
                fid = self._make_flow_id(src_ip, dst_ip, src_port, dst_port, proto)

                if fid not in flows:
                    # Fixed: Removed protocol_name and timestamp from constructor
                    flows[fid] = Flow(
                        flow_id=fid,
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        src_port=src_port,
                        dst_port=dst_port,
                        proto=proto
                    )

                flow = flows[fid]

                # Update flow details
                flow.packets += 1
                flow.bytes += int(pkt.length)
                flow.timestamps.append(timestamp)

                # --- HTTP info ---
                if hasattr(pkt, "http"):
                    http_entry = {
                        "method": getattr(pkt.http, "request_method", ""),
                        "uri": getattr(pkt.http, "request_uri", ""),
                        "user_agent": getattr(pkt.http, "user_agent", ""),
                        "content_type": getattr(pkt.http, "content_type", ""),
                        "host": getattr(pkt.http, "host", ""),
                        "referer": getattr(pkt.http, "referer", ""),
                        "response_code": getattr(pkt.http, "response_code", ""),
                    }
                    
                    # Get body data if available
                    if hasattr(pkt.http, "file_data"):
                        try:
                            body = pkt.http.file_data
                            http_entry["body_length"] = len(body) if body else 0
                            # Optionally store first N bytes of body
                            http_entry["body_preview"] = body[:500] if body else ""
                        except:
                            http_entry["body_length"] = 0
                    else:
                        http_entry["body_length"] = 0
                    
                    flow.http.append(http_entry)


                # --- DNS info ---
                if hasattr(pkt, "dns"):
                    dns_entry = {}

                    # DNS Query
                    if hasattr(pkt.dns, "qry_name"):
                        dns_entry["query_name"] = str(pkt.dns.qry_name)
                        dns_entry["query_type"] = getattr(pkt.dns, "qry_type", "")
                        dns_entry["transaction_id"] = getattr(pkt.dns, "id", "")
                        dns_entry["is_response"] = False

                    # DNS Responses
                    if hasattr(pkt.dns, "resp_name"):
                        dns_entry["response_name"] = str(pkt.dns.resp_name)
                        dns_entry["answers"] = []
                        dns_entry["is_response"] = True

                        # Extracting answers
                        if hasattr(pkt.dns, "a"):
                            dns_entry["answers"].append({"type": "A", "value": str(pkt.dns.a)})
                        if hasattr(pkt.dns, "aaaa"):
                            dns_entry["answers"].append({"type": "AAAA", "value": str(pkt.dns.aaaa)})
                        if hasattr(pkt.dns, "cname"):
                            dns_entry["answers"].append({"type": "CNAME", "value": str(pkt.dns.cname)})
                        if hasattr(pkt.dns, "mx"):
                            dns_entry["answers"].append({"type": "MX", "value": str(pkt.dns.mx)})
                        if hasattr(pkt.dns, "txt"):
                            dns_entry["answers"].append({"type": "TXT", "value": str(pkt.dns.txt)})
                    
                    if dns_entry:
                        flow.dns.append(dns_entry)



            except AttributeError as e:
                # Log the error for debugging if needed
                continue
            except Exception as e:
                # Catch any other exceptions
                continue

        try:
            cap.close()
        except:
            pass
        return flows