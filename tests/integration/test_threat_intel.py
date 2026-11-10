"""Integration tests for the threat-intel pipeline (§6.7, Table 28).

Covers:
    * STIX 2.1 bundle parsing (CERT alerts),
    * honeypot log correlation,
    * darknet scan detection,
    * vendor feed normalisation,
    * internal-log correlation.

The tests use the committed fixtures in ``data/threat_feeds/``. They
do not require network access.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from src.intel.darknet_monitor import DarknetMonitor
from src.intel.honeypot_correlation import HoneypotCorrelator
from src.intel.internal_log_correlator import (
    InternalLogCorrelator,
    parse_cef_line,
    parse_syslog_line,
)
from src.intel.stix_parser import (
    CERT_EFFECTIVENESS_PCT,
    RULES_PER_MINUTE,
    STIXParser,
    parse_stix_file,
)
from src.intel.vendor_feed_normalizer import (
    VENDOR_EFFECTIVENESS_PCT,
    VendorFeedNormalizer,
)


# ---------------------------------------------------------------- STIX
def test_stix_parser_parses_sample(sample_stix_bundle: Path):
    if not sample_stix_bundle.exists():
        pytest.skip(f"{sample_stix_bundle} not present")
    records = parse_stix_file(sample_stix_bundle)
    assert len(records) >= 3
    for r in records:
        assert r.source == "cert"
        assert r.indicator_type
        assert r.indicator_value


def test_stix_parser_extracts_domains(sample_stix_bundle: Path):
    if not sample_stix_bundle.exists():
        pytest.skip(f"{sample_stix_bundle} not present")
    records = parse_stix_file(sample_stix_bundle)
    domains = [r for r in records if r.indicator_type == "domain-name"]
    assert any("tunnel.example.com" in r.indicator_value for r in domains)


def test_stix_parser_extracts_ips(sample_stix_bundle: Path):
    if not sample_stix_bundle.exists():
        pytest.skip(f"{sample_stix_bundle} not present")
    records = parse_stix_file(sample_stix_bundle)
    ips = [r for r in records if r.indicator_type == "ipv4-addr"]
    assert any("192.0.2.42" in r.indicator_value for r in ips)


def test_stix_effectiveness_matches_thesis():
    assert CERT_EFFECTIVENESS_PCT == pytest.approx(94.2)
    assert RULES_PER_MINUTE == 15


# ---------------------------------------------------------------- honeypot
def test_honeypot_parse_sample(sample_honeypot_logs: Path):
    if not sample_honeypot_logs.exists():
        pytest.skip(f"{sample_honeypot_logs} not present")
    correlator = HoneypotCorrelator()
    records = correlator.parse_file(sample_honeypot_logs)
    assert len(records) >= 4


def test_honeypot_correlates_with_dns():
    honeypot = [
        {"timestamp": 1762732800.0, "src_ip": "203.0.113.17", "port": 53},
    ]
    dns = [
        {"timestamp": 1762732810.0, "src_ip": "203.0.113.17", "port": 53},
    ]
    correlator = HoneypotCorrelator()
    results = correlator.correlate(honeypot, dns)
    assert len(results) == 1
    assert results[0].confidence > 0.5


def test_honeypot_rejects_out_of_window():
    honeypot = [{"timestamp": 1762732800.0, "src_ip": "203.0.113.17"}]
    dns = [{"timestamp": 1762736000.0, "src_ip": "203.0.113.17"}]  # ~1h later
    correlator = HoneypotCorrelator()
    assert correlator.correlate(honeypot, dns) == []


# ---------------------------------------------------------------- darknet
def test_darknet_parse_sample(sample_darknet_metadata: Path):
    if not sample_darknet_metadata.exists():
        pytest.skip(f"{sample_darknet_metadata} not present")
    monitor = DarknetMonitor()
    packets = monitor.parse_file(sample_darknet_metadata)
    assert len(packets) > 0


def test_darknet_detects_scan(sample_darknet_metadata: Path):
    if not sample_darknet_metadata.exists():
        pytest.skip(f"{sample_darknet_metadata} not present")
    monitor = DarknetMonitor()
    packets = monitor.parse_file(sample_darknet_metadata)
    scans = monitor.detect_scans(packets)
    assert len(scans) >= 1
    assert scans[0].unique_destinations >= 32


def test_darknet_to_intel_records(sample_darknet_metadata: Path):
    if not sample_darknet_metadata.exists():
        pytest.skip(f"{sample_darknet_metadata} not present")
    monitor = DarknetMonitor()
    packets = monitor.parse_file(sample_darknet_metadata)
    scans = monitor.detect_scans(packets)
    records = monitor.to_intel_records(scans)
    assert len(records) == len(scans)
    for r in records:
        assert r.source == "darknet"


# ---------------------------------------------------------------- vendor
def test_vendor_parse_sample(sample_vendor_feed: Path):
    if not sample_vendor_feed.exists():
        pytest.skip(f"{sample_vendor_feed} not present")
    normalizer = VendorFeedNormalizer()
    records = normalizer.parse_file(sample_vendor_feed)
    assert len(records) >= 3


def test_vendor_reputation_updates():
    normalizer = VendorFeedNormalizer()
    initial = normalizer.reputation_of("vendor_a")
    updated = normalizer.update_reputation("vendor_a", observed_accuracy=0.9)
    assert updated > initial
    assert normalizer.reputation_of("vendor_a") == updated


def test_vendor_effectiveness_matches_thesis():
    assert VENDOR_EFFECTIVENESS_PCT == pytest.approx(92.1)


# ---------------------------------------------------------------- internal logs
def test_parse_syslog_line():
    line = '<134>2026-11-10T00:00:00Z host app: hello world'
    parsed = parse_syslog_line(line)
    assert parsed is not None
    assert parsed["host"] == "host"
    assert parsed["app"] == "app"
    assert parsed["msg"] == "hello world"


def test_parse_cef_line():
    line = "CEF:0|Vendor|Product|1.0|100|Test|5|src=1.2.3.4 dst=5.6.7.8"
    parsed = parse_cef_line(line)
    assert parsed is not None
    assert parsed["format"] == "cef"
    assert parsed["signature_id"] == "100"


def test_internal_log_correlator_emits_feedback():
    correlator = InternalLogCorrelator()
    correlator.ingest_decision(
        {"timestamp": 0.0, "flow_key": "example", "flagged": True, "score": 0.9}
    )
    # No external indicators -> one signal
    from src.intel.stix_parser import IntelRecord
    records = [
        IntelRecord(source="vendor", indicator_type="domain-name", indicator_value="example")
    ]
    signals = correlator.correlate(records)
    assert len(signals) >= 1
