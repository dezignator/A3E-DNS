# ARCHITECTURE — A³E-DNS Integrated Framework

**Thesis Chapter 6 · §6.3.1 (three planes), §6.3.3 (pipeline Eq. 117)**

This document describes the architecture of the A³E-DNS framework as
specified in Chapter 6 of the thesis, and maps each architectural
element to the module in this repository that implements it.

---

## 1. The three planes (§6.3.1)

The framework is organized into **three planes** with strictly defined
interfaces and loosely coupled responsibilities. The decomposition
mirrors the "data / control / management" separation that is standard
in SDN architectures and is used here to keep the security-critical
path (data plane) independent of the slower decision path (control
plane) and the administrative path (management plane).

### 1.1 Data plane

Responsible for packet processing, feature extraction and cryptographic
transformation. It runs on the critical path of DNS resolution, so every
component in this plane must meet the per-query latency budget.

| Component | Module | Reference |
|---|---|---|
| Kernel-level packet capture (eBPF / XDP) | `src/dataplane/ebpf_loader.py`, `src/dataplane/ebpf_capture.c` | §6.11.2, §6.12 |
| P4 3-stage metadata extraction | `src/dataplane/p4_telemetry.py`, `src/dataplane/p4_pipeline/*.p4` | §6.12.1–§6.12.3 |
| Mininet + BMv2 topology | `src/dataplane/mininet_topology.py` | §6.12 |
| Adaptive Evolutionary Encryption (AEE) | `src/models/aee_engine.py`, `src/models/aee_neural_controller.py` | §6.4, Eqs. 119–122 |
| Quantum-Safe Homomorphic Encryption (QHE) | `src/models/qhe_engine.py`, `src/models/qhe_ntt.py`, `src/models/qhe_ziggurat.py` | §6.5, Eqs. 123–125 |
| Hardware entropy integration | `src/hardware_simulation/entropy.py` | §6.4.3 |

### 1.2 Control plane

Responsible for distributed intelligence and threat detection. It runs
asynchronously with respect to the data plane; its outputs are
consumed by the data plane via a closed feedback loop.

| Component | Module | Reference |
|---|---|---|
| Federated Learning coordinator | `src/models/fl_coordinator.py` | §6.6 |
| Spatio-temporal Transformer | `src/models/fl_transformer.py` | §6.6.1–§6.6.2 |
| Byzantine-robust aggregation | `src/models/fl_geometric_median.py` | §6.6.4, Eq. 127 |
| DP-SGD (ε = 0.68) | `src/models/fl_dp_sgd.py` | §6.6.5, Eq. 129 |
| Transformer-based anomaly detector | `src/models/anomaly_detector.py` | §6.6.1, Table 27 |
| Threat Intelligence integration | `src/intel/*` | §6.7, Table 28 |
| Adaptive Multi-Protocol Sandbox | `src/models/am_sandbox.py` | §6.3.2, §6.17.3 |

### 1.3 Management plane

Responsible for administration, observability and compliance.

| Component | Module | Reference |
|---|---|---|
| Human-in-the-loop policy configuration | `configs/*.yaml` | §6.11.2 |
| Monitoring (Prometheus + Grafana) | `docker-compose.yml` (`prometheus`, `grafana` services) | §6.11.2 |
| Compliance checkers | `src/compliance/__init__.py` | §6.9, Table 29 |
| Failover and recovery | per-module `failover` block in `configs/*.yaml` | Table 27 |

---

## 2. The processing pipeline (§6.3.3, Eq. 117)

Formally, the multi-protocol processing pipeline is the composition of
four operators, applied in a fixed order:
