# TESTBED — 4-node Containerised Environment

**Thesis Chapter 6 · §6.11.1 (hardware), §6.11.2 (software)**

This document describes the testbed that produced the empirical results
reported in Chapter 6. It is the reference for the figures in
`README.md` and for the throughput statement (22.5 M QPS) that
accompanies the proposed framework.

**The testbed is a containerised 4-node environment, not a production
DNS deployment.** See §7.3.7 (`docs/LIMITATIONS.md` §7) for the
external-validity limits.

---

## 1. Hardware (§6.11.1)

| Property | Value |
|---|---|
| **Nodes** | 4 |
| **CPUs** | Intel Xeon Silver + AMD EPYC |
| **Cores per node** | 16 (Xeon Silver) / 32 (EPYC) |
| **Memory** | 128 GB DDR4 per node |
| **OS** | Ubuntu Server 22.04 LTS |
| **Container runtime** | Docker |
| **Orchestrator** | Kubernetes (Minikube) |

### 1.1 Node roles

Each node runs one of the four A3E-DNS roles:

| Node | CPU profile | Role | gRPC | Metrics |
|---|---|---|---|---|
| node-1 | Intel Xeon Silver (16 cores) | FL coordinator | 50051 | 8001 |
| node-2 | AMD EPYC (32 cores) | QHE service | 50052 | 8002 |
| node-3 | AMD EPYC (32 cores) | Anomaly detector + AMPS sandbox | 50053 / 50054 | 8003 |
| node-4 | Intel Xeon Silver (16 cores) | Threat intel + P4/eBPF data plane | 50055 | 8004 |

The `docker-compose.yml` at the repository root encodes these roles and
their resource limits. The `cpus` and `mem_limit` fields in each service
block match the table above.

### 1.2 Networking (§6.11.2)

The network is a **software-defined, fully virtualised** environment:

- Docker networks and Linux network namespaces.
- Virtual bridge interfaces.
- Open vSwitch for programmable forwarding policies.
- Wireshark, tcpdump, and Scapy for packet-level inspection.
- tcpreplay for replaying captured traffic.

This means the testbed **does not use a physical DNS resolver**, and
the throughput and latency figures are properties of this virtualised
environment, not of a physical DNS deployment.

---

## 2. Software stack (§6.11.2)

| Category | Software |
|---|---|
| **Language** | Python 3.11 |
| **Container runtime** | Docker, Docker Compose |
| **Orchestrator** | Kubernetes (Minikube) |
| **ML frameworks** | PyTorch, TensorFlow |
| **Crypto libraries** | OpenFHE, Microsoft SEAL, OpenSSL |
| **Observability** | Prometheus, Grafana |
| **Network tools** | Wireshark, tcpdump, Scapy, Open vSwitch |
| **RPC** | gRPC |
| **Data** | Dask |

Every one of these is a standard, published tool. The contribution of
this repository is the **specific configuration and orchestration** of
these tools for the A³E-DNS pipeline, not the tools themselves.

---

## 3. What the testbed exercises

The testbed exercises:

- The **full pipeline** of Eq. 117 (§6.3.3):
  `S_eBPF ∘ F_QHE ∘ A_FL ∘ M_sandbox`.
- The **4-node role decomposition** described in §1.1.
- The **threat-intel integration** of Table 28 (CERT alerts, honeypot,
  darknet, vendor feeds, internal logs).
- The **attack scenarios** S1–S5 of Table 32 and the protocol-specific
  scenarios of §6.15.2–§6.15.4.
- The **compliance checkers** of Table 29.

The testbed does **not** exercise:

- A production DNS resolver's traffic.
- A physical A100, Loihi 2, or P4 switch (these are emulated in the
  default Tier B path; see `docs/HARDWARE_EMULATION.md`).
- A production deployment at scale (the testbed is a 4-node
  containerised environment).

---

## 4. The 22.5 M QPS figure

The throughput figure of **22.5 M QPS** reported for the proposed
framework (Table 33) is a property of the testbed described in §1. It
was measured on the 4-node cluster under the conditions described in
§6.16.2, with the emulators in place for the A100 and BMv2 components.

**The figure is not extrapolated to a production DNS deployment.** It
is a property of the testbed, and the thesis states this explicitly in
§6.17.1 and §7.3.7.

A reader who wants to estimate the production throughput should:

1. Multiply the figure by the ratio of the target cluster's CPU cores
   to the testbed's CPU cores (for the CPU-bound parts).
2. Multiply by the ratio of the target cluster's GPU resources to the
   A100 (for the QHE-bound parts).
3. Adjust for the target network bandwidth.
4. Accept that the estimate is at best an order-of-magnitude estimate,
   because production traffic distributions differ from the testbed's.

The artifact does not provide a general scaling law; §5.7.3 of the
thesis provides a scaling-law model, but it was not validated on a
production deployment.

---

## 5. Reproducing the testbed

The testbed is described in `docker-compose.yml` at the repository root.
To bring it up locally:

```bash
docker compose -f docker-compose.yml up -d --build
docker compose -f docker-compose.yml logs -f node-1
