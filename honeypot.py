"""Honeypot and darknet telemetry (Section 6.7.2)."""
from collections import defaultdict, Counter

def honeypot_summary(events):
    c = Counter((e["proto"], e["technique"]) for e in events); return dict(c)

def detect_darknet_scans(records, min_ports=8, window_s=60.0):
    """records: (ts, src, dst_port). Flag sources hitting >= min_ports distinct ports within a window."""
    by = defaultdict(list)
    for ts, src, port in sorted(records): by[src].append((ts, port))
    flagged = {}
    for src, ev in by.items():
        j = 0
        for i in range(len(ev)):
            while ev[i][0] - ev[j][0] > window_s: j += 1
            ports = {p for _, p in ev[j: i + 1]}
            if len(ports) >= min_ports: flagged[src] = len(ports); break
    return flagged
