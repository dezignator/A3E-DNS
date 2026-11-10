"""A3E-DNS — Next-Generation Secure and Adaptive Evolutionary Encryption
for DNS-over-HTTPS, DNS-over-TLS and DNS-over-QUIC.

Thesis artifact (Chapter 6). No new cryptographic primitive is proposed;
every cryptographic component is an existing, standardized, or published
scheme. A full factorial ablation of the integration was not performed
(§7.3.1).

The public package is organized as:

    src.utils            — SE(3), metrics, CDS, config, seeding, logging
    src.protocols        — DoH / DoT / DoQ adapters + unified pipeline
    src.models           — AEE, QHE, FL, AMPS, anomaly detector
    src.intel            — STIX/TAXII, honeypot, darknet, vendor, internal
    src.dataplane        — P4 3-stage, eBPF, Mininet
    src.attacks          — S1–S5 + DoH/DoT/DoQ specific
    src.hardware_simulation — A100, entropy, perf model
    src.compliance       — 5 checkers (NIST CSF, GDPR, ISO 27001, PCI DSS, FISMA)
"""

from __future__ import annotations

__title__ = "a3e-dns"
__description__ = (
    "Next-Generation Secure and Adaptive Evolutionary Encryption for "
    "DNS-over-HTTPS, DNS-over-TLS and DNS-over-QUIC — thesis artifact (Chapter 6)"
)
__version__ = "1.0.0"
__author__ = "A3E-DNS Thesis Authors"
__license__ = "MIT"
__url__ = "https://github.com/dezignator/A3E-DNS"
__python_requires__ = ">=3.11,<3.12"
__thesis_chapter__ = "Chapter 6"
__thesis_framework__ = "A3E-DNS"

# Public subpackages intentionally NOT imported here to keep `import src`
# cheap and free of heavy optional dependencies. Import them explicitly,
# e.g. `from src.utils.se3_lie_group import exp_map`.

__all__ = [
    "__title__",
    "__description__",
    "__version__",
    "__author__",
    "__license__",
    "__url__",
    "__python_requires__",
    "__thesis_chapter__",
    "__thesis_framework__",
]


def get_version() -> str:
    """Return the package version string (also used by setup.py)."""
    return __version__


def thesis_reference() -> dict[str, str]:
    """Return the thesis metadata that every table/figure script must cite."""
    return {
        "chapter": __thesis_chapter__,
        "framework": __thesis_framework__,
        "artifact_version": __version__,
    }
