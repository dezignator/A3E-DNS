# HARDWARE_BOM — Bill of Materials

**Part numbers and quantities for a real A³E-DNS deployment.**
**Prices are indicative for early 2026 and will vary by vendor and region.**

---

## 1. The three deployment profiles

| Profile | Use case | Capex | What you buy |
|---|---|---|---|
| **A. Full purchase** | Research lab, permanent setup | ~$58 K–$71 K | All hardware, on-prem |
| **B. Hybrid** | Academic group, most common | ~$25 K–$40 K | 4-node cluster on-prem + rent A100 / Loihi in cloud |
| **C. Cloud-only** | Fast to start, no capex | $0 | Rent everything (AWS / GCP / Azure) |

`COST_ESTIMATE.md` gives the TCO for each. This document gives the
parts list for profile A, plus the "what you rent instead of buy" for
profile B, and the cloud-SKU list for profile C.

---

## 2. Profile A — Full purchase BOM

### 2.1 Four servers (the 4-node testbed of §6.11.1)

| Qty | Item | Part number | Unit | Line total |
|---|---|---|---|---|
| 2 | Intel Xeon Silver 4314 (16C/32T, 2.4 GHz, 135 W) | `CD8068904659502` | $1,150 | $2,300 |
| 2 | AMD EPYC 7543 (32C/64T, 2.8 GHz, 225 W) | `100-100000321WOF` | $2,300 | $4,600 |
| 4 | Supermicro MBD-H12SSL-i (EPYC) or MBD-X12SPi-TF (Xeon) motherboard | depends on CPU | $700 | $2,800 |
| 4 | 4× 32 GB DDR4-3200 ECC RDIMM (128 GB total per server) | `MTA18ASF4G72PDZ-3G2E2` | $500 | $2,000 |
| 4 | 2 TB NVMe SSD (Samsung 990 PRO or enterprise equiv.) | `MZ-V9P2T0BW` | $200 | $800 |
| 4 | 2U rackmount chassis + 800 W PSU + 6 fans | `CSE-825TQC-R802LPB` | $850 | $3,400 |
| 4 | Rack rails | (bundled) | $0 | $0 |
| **Servers subtotal** | | | | **$15,900** |

The 4 servers map to §6.11.1's node roles: `node-1` and `node-4` are
Xeon Silver (16 cores), `node-2` and `node-3` are EPYC (32 cores).
If you buy only **profile B** (hybrid), you still buy all 4 servers —
they are the testbed. Only the accelerators are rented.

### 2.2 Accelerators

| Qty | Item | Part number | Unit | Line total |
|---|---|---|---|---|
| 1 | NVIDIA A100 80 GB PCIe Gen4 | `900-21001-0020-000` | $17,000 | $17,000 |
| 1 | Intel Loihi 2 development system | via INRC (free, approval required) | $0 | $0 |
| 1 | Intel Tofino-1 programmable switch | `Wedge 100BF-32X` (Edgecore) | $22,000 | $22,000 |
| **Accelerators subtotal** | | | | **$39,000** |

**Substitutions and alternatives:**

- **A100 40 GB PCIe** (`900-21001-0000-000`) is **~$10,000** but is
  being deprecated; buy the 80 GB if you can. **A100 80 GB SXM5**
  (`900-21001-0040-000`) is **~$25,000** and requires an HGX baseboard
  (only worth it for 8-GPU configurations).
- **H100 80 GB PCIe** (`900-21010-0020-000`) is **~$30,000** and is a
  drop-in replacement for A100 with better throughput; the code is
  CUDA-compatible, no changes needed. It is overkill unless you
  intend to train larger models than the thesis uses.
- **Loihi 2** is **not for sale**; it is available only via the
  **Intel Neuromorphic Research Community (INRC)**. See
  `PREREQUISITES.md` §3. If you skip Loihi, use the emulator
  (`loihi_mock.py`); the artifact supports it.
- **Tofino-1** is being superseded by **Tofino-2** (`Tofino2-based
  switch`, ~$35,000). The P4 pipeline in `src/dataplane/p4_pipeline/`
  is written for `v1model` and runs on both. If you skip the
  hardware switch, use BMv2-on-real-NIC (`05_P4_SETUP.md` §4);
  performance will be ~10× lower but functionally identical.

### 2.3 Networking

| Qty | Item | Part number | Unit | Line total |
|---|---|---|---|---|
| 4 | Mellanox ConnectX-6 Dx 25 GbE dual-port NIC | `MCX623106AN-CDAT` | $800 | $3,200 |
| 1 | 32-port 25/100 GbE aggregation switch | `SN2410` (Mellanox/NVIDIA) | $5,000 | $5,000 |
| 8 | 25 GbE SFP28 DAC cables (1 m) | `MCP2M00-A001` | $60 | $480 |
| 4 | 100 GbE QSFP28 DAC cables (3 m, uplink) | `MCP1600-E003E26` | $200 | $800 |
| **Networking subtotal** | | | | **$9,480** |

### 2.4 Power, cooling, and mechanical

| Qty | Item | Unit | Line total |
|---|---|---|---|
| 1 | 12U wall-mount or 24U floor rack | $800 | $800 |
| 1 | Rack PDU (30 A, 208 V, 8 outlets) | $500 | $500 |
| 1 | UPS (3 kVA, 15 min runtime) | $1,200 | $1,200 |
| 1 | KVM switch + 17" LCD | $600 | $600 |
| — | Cabling, labels, misc. | $200 | $200 |
| **Facilities subtotal** | | | **$3,300** |

### 2.5 Grand total — profile A

| Category | Subtotal |
|---|---|
| Servers | $15,900 |
| Accelerators | $39,000 |
| Networking | $9,480 |
| Facilities | $3,300 |
| **Hardware total** | **$67,680** |
| Contingency (10%) | $6,768 |
| **Grand total** | **$74,448** |

Add ~$55,000/year for licences and support; see
`COST_ESTIMATE.md` §2.

---

## 3. Profile B — Hybrid BOM

The 4-node testbed is on-prem (as profile A, §2.1 + §2.3 + §2.4 =
$15,900 + $9,480 + $3,300 = **$28,680**). The accelerators are
**rented**:

| Resource | Provider | SKU | Hourly | Monthly (730 h) |
|---|---|---|---|---|
| 1× A100 80 GB | AWS | `p4d.24xlarge` (8 GPUs; 1/8 share ≈ 1 GPU) | $32.77 | $23,922 |
| 1× A100 80 GB | GCP | `a2-ultragpu-1g` | $4.10 | $2,993 |
| 1× A100 80 GB | Azure | `ND96asr_v4` (8 GPUs; 1/8 share ≈ 1 GPU) | $27.20 | $19,856 |
| 1× Loihi 2 | Intel INRC | (remote access via INRC cloud) | free | free |
| 1× Tofino | BMv2-on-NIC | (local) | free | free |

**Recommended hybrid:** own the 4-node testbed, rent **one A100 on
GCP `a2-ultragpu-1g`** (~$3,000/month) when running benchmarks, use
the **BMv2-on-NIC** path for P4, and use the **Loihi emulator** (or
INRC cloud if approved). Total capex ~**$28,680**, opex ~**$36,000–
$50,000/year** depending on how much time the A100 is rented.

---

## 4. Profile C — Cloud-only BOM

No hardware purchase. Everything is rented.

| Resource | Provider | SKU | Hourly | Monthly |
|---|---|---|---|---|
| 4× nodes (32 vCPU, 128 GB) | AWS | 4× `c6i.8xlarge` | 4 × $1.36 = $5.44 | $3,971 |
| 1× A100 80 GB | AWS | `p4d.24xlarge` (1 GPU share) | $32.77 | $23,922 |
| 1× A100 80 GB (alternative) | GCP | `a2-ultragpu-1g` | $4.10 | $2,993 |
| 1× A100 80 GB (alternative) | Azure | `ND96asr_v4` (1 GPU share) | $27.20 | $19,856 |
| Loihi 2 | INRC cloud | (free) | $0 | $0 |
| P4 / BMv2 | (local) | $0 | $0 | $0 |
| Networking (egress) | AWS | ~$0.09/GB × 200 GB/mo | — | ~$18 |
| **Total (AWS, on-demand)** | | | | **~$27,900/mo** |
| **Total (GCP, 1× A100)** | | | | **~$6,964/mo** |
| **Total (Azure, 1× A100)** | | | | **~$23,827/mo** |

**Cost optimization for profile C:**

- Use **spot / preemptible instances** for the A100: 60–70% discount
  (GCP `a2-ultragpu-1g` spot ≈ $1.20/hour → ~$876/month).
- Use **reserved instances** for the 4 CPU nodes: ~40% discount
  (3-year commitment, `c6i.8xlarge` ≈ $0.82/hour → ~$2,395/month).
- Use **AWS Savings Plans** for the A100: 30–50% discount.
- **Do not run the A100 24/7.** Shut it down between benchmarks. Real
  usage is typically 200–400 hours/month, which brings the A100 cost
  down to $820–$1,640/month.

Realistic cloud-only monthly cost with optimization: **$3,000–$6,000**.

---

## 5. What is NOT in the BOM

The following are needed but not listed as hardware, because they are
either software (see `08_CRYPTO_SETUP.md`, `09_ML_SETUP.md`) or
organizational:

- **INRC membership** (Loihi 2) — free, approval required
- **NVIDIA AI Enterprise licence** — $4,500/year per GPU (optional;
  only needed if you want vendor support)
- **Tofino SDE licence** — ~$50,000/year, NDA required (only if you
  buy the Tofino switch; BMv2-on-NIC does not need it)
- **Microsoft SEAL** — free
- **OpenFHE** — free
- **liboqs** — free
- **Ubuntu Server 22.04 LTS** — free
- **Kubernetes** — free (upstream) or $5,000–$15,000/year (Red Hat
  OpenShift)
- **Grafana Enterprise** — $15,000/year (only if you need enterprise
  support; OSS Grafana is free)
- **DDoS protection** — $3,000–$50,000/month (Cloudflare / Akamai;
  only if the deployment is internet-facing)
- **Security audit** — $20,000–$100,000 (one-time; see
  `15_PRODUCTION_CHECKLIST.md`)

Full opex is in `COST_ESTIMATE.md` §2.

---

## 6. Order of purchase

If you are buying profile A, order in this sequence to minimize the
critical path:

1. **Week 0:** INRC membership application (Loihi 2). This is the
   long pole — 6–12 weeks for approval.
2. **Week 0:** Servers, NICs, networking, rack, power. These have the
   shortest lead times (1–2 weeks).
3. **Week 0:** A100 (if buying). Lead time is 4–8 weeks depending on
   vendor and region.
4. **Week 1:** Tofino switch (if buying). Lead time is 4–6 weeks.
5. **Week 1:** Tofino SDE license (if using Tofino hardware). NDA is
   2–4 weeks.
6. **Week 6:** Loihi 2 arrives (if approved at week 0).

The critical path is **A100 lead time (4–8 weeks)**, followed by
**Tofino SDE NDA (2–4 weeks)**, followed by **Loihi 2 approval (6–12
weeks)**. Start all three on day 0.

If any of these threaten your schedule, switch to profile B (rent the
accelerators) or profile C (rent everything).

---

## 7. Warranty and support

- **Servers:** 3-year on-site warranty from Supermicro / Dell /
  HPE. Do not skip; a failed server in the middle of a benchmark is
  expensive.
- **A100:** 3-year NVIDIA warranty. The card is a line item on the
  server warranty if you buy it bundled with the server.
- **Tofino switch:** 3-year Edgecore warranty; the SDE licence is
  separate and renews annually.
- **Loihi 2:** no commercial warranty; it is a research device
  provided under the INRC membership terms.
- **Networking:** 3-year Mellanox / NVIDIA warranty.

Annual support (NVIDIA AI Enterprise + Tofino SDE + OpenShift +
Grafana Enterprise) is **~$55,000** if you take all four. You can
drop OpenShift and Grafana Enterprise to reduce this to **~$55,000 –
$5,000 – $15,000 = $35,000**, at the cost of running the OSS versions
yourself.

---

## 8. What profile to choose

| If... | Choose |
|---|---|
| You are a research lab with a 3-year horizon and a $75 K budget | **Profile A** |
| You are an academic group with $30 K and an AWS/GCP account | **Profile B** |
| You are a startup that wants to validate the approach in 2 weeks | **Profile C** |
| You are reproducing the thesis | **None of these.** Use the thesis artifact. |

The most common choice in the field is **profile B**, because it
avoids the Tofino SDE NDA, avoids the Loihi 2 wait, and keeps the
4-node testbed (which is what most of the thesis's empirical results
depend on) on-prem.
