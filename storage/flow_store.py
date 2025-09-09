# storage/flow_store.py
from typing import Dict, List
from parsers.pcap_parser import Flow


class FlowStore:
    def __init__(self):
        self.flows: Dict[str, Flow] = {}

    def add_flows(self, new_flows: Dict[str, Flow]):
        """Add multiple flows from a parsed PCAP."""
        for fid, flow in new_flows.items():
            if fid in self.flows:
                # Update existing flow stats
                existing = self.flows[fid]
                existing.packets += flow.packets
                existing.bytes += flow.bytes
                existing.timestamps.extend(flow.timestamps)

                # Merge DNS, HTTP, TLS if available
                if hasattr(flow, "dns") and flow.dns:
                    existing.dns.extend(flow.dns)
                if hasattr(flow, "http") and flow.http:
                    existing.http.extend(flow.http)
                if hasattr(flow, "tls") and flow.tls:
                    existing.tls.extend(flow.tls)

            else:
                self.flows[fid] = flow

    def get_flow(self, fid: str) -> Flow:
        """Retrieve a flow by ID."""
        return self.flows.get(fid)

    def list_flows(self) -> List[Flow]:
        """Return all flows as a list."""
        return list(self.flows.values())

    def stats(self) -> Dict[str, int]:
        """Basic statistics about the flows."""
        return {
            "total_flows": len(self.flows),
            "total_packets": sum(f.packets for f in self.flows.values()),
            "total_bytes": sum(f.bytes for f in self.flows.values()),
        }
