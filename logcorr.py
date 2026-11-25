"""Internal log correlation and feedback loop (Section 6.8; Table 28 'Internal Logs', Syslog/CEF, continuous).

parse_cef reads ArcSight CEF lines. correlate() groups events per source inside a time window and emits
feedback labels (source, label, evidence) that can be appended to the federated training set.
"""
import re
from collections import defaultdict

_CEF = re.compile(r"CEF:\d+\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|(\d+)\|(.*)")

def parse_cef(line):
    m = _CEF.search(line)
    if not m: return None
    vendor, product, ver, sig, name, sev, ext = m.groups(); kv = dict(re.findall(r"(\w+)=([^ ]+)", ext))
    return dict(vendor=vendor, product=product, signature=sig, name=name, severity=int(sev), src=kv.get("src"), dst=kv.get("dst"), ts=float(kv.get("rt", 0)), proto=kv.get("proto", "?"))

def correlate(events, window_s=60.0, min_events=3, min_distinct_sigs=2):
    by = defaultdict(list)
    for e in events:
        if e and e.get("src"): by[e["src"]].append(e)
    out = []
    for src, ev in by.items():
        ev.sort(key=lambda e: e["ts"]); j = 0
        for i in range(len(ev)):
            while ev[i]["ts"] - ev[j]["ts"] > window_s: j += 1
            win = ev[j: i + 1]
            if len(win) >= min_events and len({e["signature"] for e in win}) >= min_distinct_sigs:
                out.append(dict(src=src, label="suspicious", evidence=sorted({e["signature"] for e in win}), n=len(win), max_severity=max(e["severity"] for e in win))); break
    return out
