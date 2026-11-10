> ⚠️ **These are deployment guides, NOT the thesis artifact.**
>
> - The thesis artifact is `README.md` at the repository root and the
>   165 files it references. It is **reproducible on a stock CPU** using
>   the emulators described in `docs/HARDWARE_EMULATION.md`.
> - The files under `deployment/` describe a **real, paid-hardware**
>   deployment path that **DIFFERS** from the thesis's reproducibility
>   tiers. It is **not** verified by
>   `expected_outputs/verification_script.py`, and the numbers you
>   will see on real hardware will **differ** from the thesis's
>   reported figures.
> - If your goal is **to reproduce the thesis**, stop reading and use
>   the tier-A/B/C/D path in `REPRODUCIBILITY_CHECKLIST.md`.
> - If your goal is **to deploy A³E-DNS on real hardware**, continue.

# A³E-DNS Deployment Guide

This directory documents how to deploy the A³E-DNS framework on **real
paid hardware** — servers, an NVIDIA A100, an Intel Loihi 2, and a P4
switch — using real software (OpenFHE, SEAL, liboqs, the P4 toolchain,
a real Kubernetes cluster). It is written for a deployment engineer,
not for a thesis reviewer.

The framework itself is unchanged: the code in `src/` is the same code
that runs in the emulated tier. Only the **execution substrate** is
different. Concretely:

| Layer | Thesis artifact | This deployment |
|---|---|---|
| A100 | Emulated (`a100_emulation.py`) | Real NVIDIA A100 40 GB or 80 GB PCIe |
| Loihi | Emulated (`loihi_mock.py`) | Real Intel Loihi 2 (via INRC membership) |
| P4 | BMv2 (software switch) | Real Tofino-1 or BMv2-on-real-NIC |
| Testbed | Docker + Minikube | Real 4-node cluster + kubeadm Kubernetes |
| HE library | In-process simulator (`_RingLWESimulator`) | OpenFHE + Microsoft SEAL |
| Post-quantum KEM | SHA-256 KDF over raw bytes | liboqs (ML-KEM / Kyber) |
| DNSSEC trust anchor | Self-signed in testbed | Real trust anchor |
| Observability | Prometheus + Grafana in docker-compose | Real Prometheus + Grafana HA |

The framework's **architectural** and **empirical** contributions are the
same. The **absolute figures** will differ from the thesis because
they are properties of the real hardware, not of the emulators
(§7.3.4 of the thesis; `docs/HARDWARE_EMULATION.md` §6 of the artifact).

---

## 1. Decision tree
