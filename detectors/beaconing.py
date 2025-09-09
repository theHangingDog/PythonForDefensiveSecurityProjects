
from collections import defaultdict
from statistics import stdev, mean

# Global connection history for tracking patterns across flows
connection_history = defaultdict(list)

def detect_beaconing(flow: dict, timestamp: float = None) -> list:
    """Detect potential beaconing behavior based on timing patterns"""
    alerts = []
    
    # Method 1: Analyze timing patterns within a single flow
    timestamps = flow.get("timestamps", [])
    if len(timestamps) >= 5:  # Need enough data points
        # Calculate time intervals between packets
        intervals = []
        for i in range(1, len(timestamps)):
            interval = timestamps[i] - timestamps[i-1]
            intervals.append(interval)
        
        if intervals:
            # Calculate statistics
            avg_interval = mean(intervals)
            
            # Check for regular intervals (beaconing)
            if len(intervals) >= 5:
                try:
                    std_dev = stdev(intervals)
                    
                    # Low standard deviation relative to mean suggests regular intervals
                    if avg_interval > 0 and (std_dev / avg_interval) < 0.2:
                        alerts.append(f"[Beaconing] Regular interval pattern detected: ~{avg_interval:.2f}s between packets")
                    
                    # Check for specific beacon intervals
                    common_beacon_intervals = [
                        (30, "30 seconds"),
                        (60, "1 minute"),
                        (300, "5 minutes"),
                        (600, "10 minutes"),
                        (900, "15 minutes"),
                        (1800, "30 minutes"),
                        (3600, "1 hour"),
                    ]
                    
                    for interval_sec, interval_name in common_beacon_intervals:
                        if abs(avg_interval - interval_sec) < 5:  # Within 5 seconds
                            alerts.append(f"[Beaconing] Common C2 beacon interval detected: {interval_name}")
                            break
                except:
                    pass  # Not enough variation to calculate stdev
    
    # Method 2: Cross-flow pattern analysis using global history
    if timestamp:
        key = (flow["src_ip"], flow["dst_ip"], flow["dst_port"])
        connection_history[key].append(timestamp)
        
        if len(connection_history[key]) >= 3:
            # Check connection regularity across multiple flows
            intervals = [connection_history[key][i+1] - connection_history[key][i] 
                        for i in range(len(connection_history[key]) - 1)]
            avg_interval = sum(intervals) / len(intervals)
            
            # Check if all intervals are similar (regular beaconing)
            if all(abs(interval - avg_interval) < 2 for interval in intervals):
                alerts.append(f"[Beaconing] Cross-flow regular pattern: {flow['src_ip']} -> {flow['dst_ip']}:{flow['dst_port']} every ~{avg_interval:.1f}s")
    
    # Check for long-duration flows (persistence)
    if timestamps:
        duration = timestamps[-1] - timestamps[0]
        if duration > 3600:  # More than 1 hour
            hours = duration / 3600
            alerts.append(f"[Beaconing] Long-duration flow: {hours:.2f} hours")
    
    # Check packet count patterns
    packets = flow.get("packets", 0)
    if packets > 100 and len(set(intervals[:20] if 'intervals' in locals() else [])) < 5:
        alerts.append(f"[Beaconing] High packet count ({packets}) with repetitive timing")
    
    return alerts
