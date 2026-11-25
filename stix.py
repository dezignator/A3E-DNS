"""STIX 2.1 and vendor-feed ingestion (Section 6.7.1).

Only the indicator subset needed for DNS is parsed: patterns of the form
[domain-name:value = 'x'] and [ipv4-addr:value = 'x'].
"""
import json, re
from collections import defaultdict

_PAT = re.compile(r"\[\s*(domain-name|ipv4-addr|ipv6-addr):value\s*=\s*'([^']+)'\s*\]")

def parse_stix_bundle(text):
    b = json.loads(text); out = []
    for o in b.get("objects", []):
        if o.get("type") != "indicator": continue
        m = _PAT.search(o.get("pattern", ""))
        if m: out.append(dict(kind=m.group(1), value=m.group(2).lower(), confidence=o.get("confidence", 50) / 100.0,
                              valid_from=o.get("valid_from"), source=o.get("created_by_ref", "stix")))
    return out

def normalize_vendor_feed(rows, source, weight=1.0):
    return [dict(kind=r.get("kind", "domain-name"), value=r["value"].lower().strip("."),
                 confidence=float(r.get("score", 50)) / 100.0, valid_from=r.get("seen"), source=source, w=weight) for r in rows]

def fuse_indicators(*feeds, reputation=None):
    """Reputation-weighted fusion. fused = 1 - prod(1 - w_s * conf_s) (noisy-OR)."""
    reputation = reputation or {}; acc = defaultdict(lambda: [1.0, set()])
    for feed in feeds:
        for i in feed:
            w = reputation.get(i["source"], i.get("w", 1.0)); a = acc[(i["kind"], i["value"])]
            a[0] *= 1 - min(max(w * i["confidence"], 0), 0.999); a[1].add(i["source"])
    return {k: dict(score=1 - v[0], sources=sorted(v[1])) for k, v in acc.items()}
