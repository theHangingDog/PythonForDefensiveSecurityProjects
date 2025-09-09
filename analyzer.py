# network_analyzer/main.py
import argparse
import progressbar
from parsers.pcap_parser import PcapParser
from storage.flow_store import FlowStore
from detectors.unusual_port import detect_unusual_ports
from detectors.beaconing import detect_beaconing
from detectors.dns_exfil import detect_dns_exfil
from detectors.http_anomalies import detect_http_anomalies
from reports.reporter import save_json_report

# Map IP protocol numbers to names
PROTO_MAP = {"6": "TCP", "17": "UDP", "1": "ICMP"}

def flow_to_dict(f):
    """Convert Flow dataclass to dict format detectors expect."""
    proto = str(f.proto)
    # Convert protocol number to name
    protocol_name = PROTO_MAP.get(proto, f"Protocol-{proto}")

    return {
        "flow_id": f.flow_id,
        "src_ip": f.src_ip,
        "dst_ip": f.dst_ip,
        "src_port": f.src_port,
        "dst_port": f.dst_port,
        "protocol": protocol_name,
        "packets": f.packets,
        "bytes": f.bytes,
        "timestamps": getattr(f, "timestamps", []),
        "http": getattr(f, "http", []),
        "tls": getattr(f, "tls", []),
        "dns": getattr(f, "dns", [])
    }

def main():
    ap = argparse.ArgumentParser(description="Python Network Traffic Analyzer")
    ap.add_argument("--pcap", required=True, help="Path to the PCAP file")
    ap.add_argument("--outdir", default="reports", help="Directory to save reports")
    ap.add_argument("--outfile", default=None, help="Optional report filename")
    ap.add_argument("--verbose", action="store_true", help="Verbose console output")
    args = ap.parse_args()

    # Parse PCAP -> flows
    parser = PcapParser(args.pcap)
    flows_dict = parser.parse()
    store = FlowStore()
    store.add_flows(flows_dict)

    if args.verbose:
        print("[*] Stats:", store.stats())

    results = {
        "pcap": args.pcap,
        "summary": store.stats(),
        "alerts": [],
    }

    flows = store.list_flows()
    total_flows = len(flows)

    print(f"[*] Analyzing {total_flows} flows...")

    # Create progress bar for flow analysis
    widgets = ['Analyzing flows: ', progressbar.Percentage(), ' ', 
               progressbar.Bar(marker='█', left='[', right=']'), ' ', 
               progressbar.ETA(), ' ', progressbar.Counter(), f'/{total_flows}']

    pbar = progressbar.ProgressBar(widgets=widgets, maxval=total_flows).start()

    for i, f in enumerate(flows):
        try:
            fd = flow_to_dict(f)

            alerts = []

            # Run detectors with error handling
            try:
                alerts.extend(detect_unusual_ports(fd))
            except Exception as e:
                if args.verbose:
                    print(f"Error in unusual_ports detector: {e}")

            try:
                alerts.extend(detect_dns_exfil(fd))
            except Exception as e:
                if args.verbose:
                    print(f"Error in dns_exfil detector: {e}")

            try:
                for http_entry in fd["http"]:
                    temp_flow = {
                    "protocol": fd["protocol"],
                    "dst_port": fd["dst_port"],
                    "http": http_entry
                    }
                    alerts.extend(detect_http_anomalies(temp_flow))
            except Exception as e:
                if args.verbose:
                    print(f"Error in http_anomalies detector: {e}")

            try:
                alerts.extend(detect_beaconing(fd))
            except Exception as e:
                if args.verbose:
                    print(f"Error in beaconing detector: {e}")

            if alerts:
                results["alerts"].append({
                    "flow": {
                        "flow_id": fd["flow_id"],
                        "src_ip": fd["src_ip"],
                        "dst_ip": fd["dst_ip"],
                        "src_port": fd["src_port"],
                        "dst_port": fd["dst_port"],
                        "protocol": fd["protocol"],
                        "packets": fd["packets"],
                        "bytes": fd["bytes"],
                    },
                    "alerts": alerts
                })
            if args.verbose and alerts:
                print(f"Flow {fd['flow_id'][:8]}...: {len(alerts)} alerts")

        except Exception as e:
            if args.verbose:
                print(f"Error processing flow: {e}")
        finally:
            pbar.update(i + 1)

    pbar.finish()

    save_json_report(results, output_dir=args.outdir, filename=args.outfile)
    print("[+] Analysis complete")

if __name__ == "__main__":
    main()