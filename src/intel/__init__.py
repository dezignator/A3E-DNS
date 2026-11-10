"""Threat-intelligence subpackage for the A3E-DNS artifact (Chapter 6).

The five sources of Table 28 are implemented as independent adapters
that share a common ``IntelRecord`` output type:

    stix_parser              — CERT alerts (STIX 2.1 / TAXII 2.1)      94.2 %
    honeypot_correlation     — Honeypot telemetry (JSON, 5 min)        96.8 %
    darknet_monitor          — Darknet monitoring (PCAP, hourly)       89.5 %
    vendor_feed_normalizer   — Vendor feeds (CSV / JSON, daily)        92.1 %
    internal_log_correlator  — Internal logs (syslog / CEF, continuous) 97.3 %

The percentages are the measured fraction of blocked / detected /
prevented / protected / identified events attributable to each source
during the evaluation period (Table 28, §6.7). They are not claimed as
general properties of the sources.

The contribution of this subpackage is the **operational integration**
into the A³E-DNS pipeline (§6.7), not the constituent standards. STIX,
TAXII, honeypot telemetry, darknet monitoring and vendor-feed
normalisation are all published methods.
"""

from __future__ import annotations

__all__ = [
    "stix_parser",
    "taxii_client",
    "honeypot_correlation",
    "darknet_monitor",
    "vendor_feed_normalizer",
    "internal_log_correlator",
]
