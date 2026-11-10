"""Attack suite for the A3E-DNS artifact (Chapter 6).

The suite mirrors Table 32 (S1–S5) and the six attack classes of
Table 30. Each scenario is a self-contained module that:

    * defines the attack parameters and the command that would be run
      in a live testbed (reproduced verbatim from the thesis),
    * defines the expected detection threshold and the reported
      success rate / FNR (from Table 32),
    * exposes a ``run(...)`` function that either drives the live
      testbed (when the tools are installed) or produces a
      deterministic simulation that the test suite can assert on.

Modules:

    s1_timing        — S1-Timing     (tshark + custom)
    s2_tunnel        — S2-Tunnel     (dnscat2)
    s3_poison        — S3-Poison     (fl-attack / poison.py)
    s4_quantum       — S4-Quantum    (liboqs / openssl kyber1024)
    s5_evasion       — S5-Evasion    (ART)
    doh_attacks      — DoH-specific  (HTTP/2 / HTTP/3)
    dot_attacks      — DoT-specific  (TLS 1.3)
    doq_attacks      — DoQ-specific  (QUIC v1)
    attack_runner    — orchestration

Table 32 authoritative values
------------------------------

    S1-Timing   98.7 % success, 1.3 % FNR, 0.4 ms response
    S2-Tunnel   99.2 % success, 0.8 % FNR, 1.2 ms response
    S3-Poison   96.5 % success, 3.5 % FNR, 2.5 ms response
    S4-Quantum 100.0 % success, 0.0 % FNR, 1.8 ms response
    S5-Evasion  97.8 % success, 2.2 % FNR, 0.9 ms response
"""

from __future__ import annotations

__all__ = [
    "s1_timing",
    "s2_tunnel",
    "s3_poison",
    "s4_quantum",
    "s5_evasion",
    "doh_attacks",
    "dot_attacks",
    "doq_attacks",
    "attack_runner",
]
