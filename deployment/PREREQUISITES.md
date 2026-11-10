# PREREQUISITES — Accounts, Approvals, and Waits

**Before you order anything, complete every item on this checklist.**
**The critical path of the deployment is here, not in the installation.**

---

## 1. The 8 prerequisites, in dependency order

| # | Prerequisite | Blocked by | Typical wait |
|---|---|---|---|
| 1 | Procurement approval (PO, budget) | Finance | 1–4 weeks |
| 2 | Data Protection Impact Assessment (DS-1/2/3) | Legal / DPO | 1–3 weeks |
| 3 | **INRC membership (Loihi 2)** | Intel review | **6–12 weeks** ← critical path |
| 4 | NVIDIA Developer Program | None | 1 day |
| 5 | NVIDIA AI Enterprise licence (optional) | Procurement | 1–2 weeks |
| 6 | Tofino SDE NDA + licence (only if buying Tofino) | Intel + Legal | 2–6 weeks |
| 7 | Cloud accounts (AWS / GCP / Azure) | Procurement | 1–3 days |
| 8 | Firewall / proxy approval | Network team | 1–2 weeks |

**Start items 1, 2, 3, 7 on day 0.** Everything else follows.

If you are skipping Loihi (using the emulator), you save 6–12 weeks
of critical path. This is the most consequential single decision in
the deployment.

---

## 2. Procurement

### 2.1 What procurement needs from you

- A signed **Statement of Work (SOW)** with the vendor.
- A **Purchase Order (PO)** with the exact part numbers from
  `HARDWARE_BOM.md`.
- A **cost centre** to charge the capex and opex to.
- A **fixed asset tag** (most organisations require this before
  delivery).
- A **shipping address** that can receive freight (servers and
  switches ship on pallets; a P.O. box will not work).

### 2.2 What procurement needs to tell you

- The **approval threshold** for your department. If the PO is above
  it, expect a longer review.
- The **preferred vendors** (Supermicro, Dell, HPE, Edgecore). Using
  a preferred vendor can cut the lead time by weeks.
- The **payment terms**. Net-30 is standard; some vendors require
  prepayment for first orders.
- The **warranty registration process**. Do this on delivery, not
  later.

### 2.3 Order-of-magnitude numbers

See `HARDWARE_BOM.md` §2.5 and `COST_ESTIMATE.md` §2. Most research
groups are in profile B (~$30 K capex). A typical approval takes
1–2 weeks; a large capex (>$50 K) takes 3–4 weeks.

---

## 3. INRC membership (the critical path)

### 3.1 What the INRC is

The **Intel Neuromorphic Research Community (INRC)** is the only way
to get an Intel Loihi 2 chip. There is no commercial purchase path.
Membership is **free for academic and non-profit researchers**;
industry membership is available on request.

### 3.2 How to apply

1. Go to <https://intel-ncl.atlassian.net/servicedesk/customer/portal/3/group/5/create/38>.
2. Fill in the **INRC membership request** form. You will need:
   - Your institutional email address (not a personal one).
   - A **1-page research proposal** describing what you intend to do
     with the chip. For A³E-DNS, describe the SNN-based anomaly
     detector (§6.6.1) and reference the thesis.
   - A **signed research agreement** from your institution's legal
     team. This is not an NDA; it is a research collaboration
     agreement. Most university technology-transfer offices have a
     template.
   - A **shipping address** and a **primary investigator** (PI) name
     and email.
3. Submit and wait. **Typical review time is 6–12 weeks.** There is
   no way to expedite it.
4. When approved, you receive:
   - A **Loihi 2 development system** (either a physical board or
     cloud access — the review committee decides).
   - Access to the **INRC cloud** (a shared Loihi 2 cluster you can
     reach from your institution's network).
   - Credentials for the **NxSDK** and **Lava** downloads.

### 3.3 If you are not approved

You have three fallbacks:

1. **Use the emulator.** The A³E-DNS artifact ships `loihi_mock.py`
   (see `docs/HARDWARE_EMULATION.md` §3). It reproduces the
   reported Loihi figures exactly, because the emulator is a fixed
   model. For reproduction of the thesis, this is sufficient.
2. **Use the INRC cloud.** Even if you do not receive a physical
   board, INRC members usually receive cloud access. This is the
   fastest path if the physical board does not arrive in time.
3. **Drop Loihi from the deployment.** The A³E-DNS pipeline does
   not require Loihi for its main functions; Loihi is used only in
   the PAFA-DoH chapter (Chapter 4) for the SNN anomaly detector.
   Chapter 6 (the integrated A³E-DNS) does not depend on it.

**Recommendation:** if you are deploying Chapter 6 (the integrated
framework) rather than Chapter 4 (PAFA-DoH), **skip Loihi**. The
integrated pipeline uses the transformer-based detector, not the SNN.
Loihi only matters if you specifically want to reproduce the
neuromorphic inference numbers in §4.25.

### 3.4 What you must NOT do

- Do **not** buy a Loihi 2 from a third-party reseller. There are no
  legitimate resellers. Any Loihi 2 for sale on eBay or Alibaba is
  either a stolen INRC board or a counterfeit.
- Do **not** share your NxSDK / Lava credentials. They are
  per-institution.
- Do **not** attempt to reverse-engineer the chip. That violates
  the INRC research agreement.

---

## 4. NVIDIA Developer Program

### 4.1 What you need it for

- **CUDA Toolkit downloads** (free, but requires an account).
- **cuDNN downloads** (free, but requires an account).
- **NCCL downloads** (free, but requires an account).
- **NVIDIA AI Enterprise** (paid; optional but recommended for
  production support).

### 4.2 How to register

1. Go to <https://developer.nvidia.com/login>.
2. Create a **free account** with your institutional email.
3. Join the **NVIDIA Developer Program** (free).
4. Confirm your email.

### 4.3 NVIDIA AI Enterprise (paid)

- **Cost:** ~$4,500/year per GPU.
- **What you get:** enterprise support, certified containers, NVIDIA
  Fleet Command, long-term driver branches.
- **Is it required?** No. The artifact runs on free drivers and CUDA.
  It is **recommended** for a production deployment because you get
  a support contract, and it eliminates weeks of "which driver
  version works with which CUDA" debugging.
- **How to buy:** through an NVIDIA reseller (e.g. CDW, Insight).
  Procurement handles it; see §2.

### 4.4 A100 driver prerequisites

- **A100 PCIe** requires **driver ≥ 450.80.02** (CUDA 11.0+).
- For CUDA 12.4 (what the artifact pins), use **driver ≥ 550.54.14**.
- On Ubuntu 22.04 LTS, the `nvidia-driver-550` package is what you
  want. See `03_NVIDIA_A100_SETUP.md` §2.

---

## 5. Tofino SDE (only if buying Tofino hardware)

### 5.1 What the Tofino SDE is

The **Intel Tofino Software Development Environment (SDE)** is the
compiler, driver, and runtime for the Tofino programmable switch. It
is **required** to program a Tofino ASIC.

### 5.2 The NDA

The SDE is distributed under NDA. To get it:

1. Contact your **Intel account manager** or reseller.
2. Sign the **Intel Tofino NDA** (a mutual NDA, not a one-way NDA).
3. Pay the **licence fee** (~$50,000/year).
4. Receive the SDE tarball via a secure download link.

**Timeline:** 2–6 weeks (NDA negotiation is the long pole). If your
legal team has not seen a Tofino NDA before, expect the longer end.

### 5.3 If you are not buying Tofino

You have three options:

1. **BMv2-on-real-NIC** (free). Install `p4c`, `simple_switch_grpc`,
   and the `xdp` backend. The P4 pipeline runs on the host's NIC
   using XDP. Performance is ~10× lower than a Tofino ASIC, but
   functionally identical. See `05_P4_SETUP.md` §4.
2. **Software simulation** (free). BMv2 with `simple_switch` on a
   loopback interface. This is what the thesis artifact does.
3. **Skip P4 entirely.** The A³E-DNS pipeline runs without the P4
   data plane; the eBPF capture path is sufficient for functional
   correctness.

**Recommendation:** unless you specifically need Tofino throughput,
**use BMv2-on-real-NIC**. It saves $50 K/year and the NDA wait.

---

## 6. Cloud accounts (if using profile B or C)

### 6.1 What to register for

| Provider | What for | Recommended SKU | Cost (indicative) |
|---|---|---|---|
| **AWS** | Alternative A100 (`p4d.24xlarge`) | 1/8 GPU share | $32.77/h |
| **GCP** | Primary A100 (`a2-ultragpu-1g`) | 1 full GPU | $4.10/h (on-demand), $1.20/h (spot) |
| **Azure** | Alternative A100 (`ND96asr_v4`) | 1/8 GPU share | $27.20/h |
| **INRC cloud** | Loihi 2 access (via INRC) | — | free |

**Recommended primary:** GCP `a2-ultragpu-1g`. It is the cheapest
A100 80 GB option, and the spot price makes it ~3× cheaper than
on-demand. See `COST_ESTIMATE.md` §3.

### 6.2 What you need from IT / procurement

- A **cloud account** with billing enabled.
- A **project** (GCP) or **account** (AWS) with a budget cap.
- A **service account** with `compute.instances.*` permissions.
- An **SSH key** uploaded to the cloud console.
- A **VPN** or **IP allowlist** if your organisation restricts
  egress.

**Timeline:** 1–3 days for a new account; same-day if you already
have an organisational account.

### 6.3 Cost control

- **Set a budget alert** at 50% and 90% of your monthly estimate.
- **Stop the A100 instance** when you are not benchmarking. A100
  spot at $1.20/h × 730 h/mo = $876/mo if left running. That is
  $10,512/year. Set a shutdown cron if your team forgets.
- **Use preemptible / spot** for the A100 and reserved for the CPU
  nodes. See `COST_ESTIMATE.md` §4.3.

---

## 7. Data protection (DS-1/2/3)

### 7.1 What the datasets are

- **DS-1** Zenodo 5957677: 32 GB PCAP + JSON, public research data.
- **DS-2** DoH Real-World 2022: ~5 GB PCAP + JSON, public research
  data.
- **DS-3** Kosekmi 2022 DoQ: ~2 GB PCAP + JSON, public research
  data.

All three are **public** datasets. They do not contain personal
data, and they do not contain live production DNS queries. The
original papers document their collection ethics.

### 7.2 What you still need to do

Even for public data:

1. **Register the download in your organisation's data inventory.**
   Most organisations require this even for open data.
2. **Confirm the licence.** DS-1 is CC BY 4.0. DS-2 and DS-3 have
   their own licences (check the original record before
   redistribution). Do **not** redistribute the raw PCAPs without
   checking.
3. **If you stage the data in a cloud provider:** confirm the
   provider's data residency policy. DS-1 contains EU traffic; if
   you are outside the EU, staging it in a US cloud region may
   trigger a transfer impact assessment.
4. **Do not combine DS-1/2/3 with any live production data** without
   a separate DPIA. The thesis only evaluated the public datasets.

### 7.3 If you are using your **own** data

This guide does **not** cover the data protection assessment for
your own data. Before deploying on real traffic:

- Do a **DPIA** (Data Protection Impact Assessment) if EU data is
  involved.
- Get **network team sign-off** for capturing live traffic.
- Get **user consent** if the traffic is not anonymous.
- Get **legal sign-off** for the retention period.

The thesis does **not** claim compliance with any of these; see
`docs/LIMITATIONS.md` §7.

---

## 8. Firewall and proxy

### 8.1 Required egress

The deployment needs egress to:

| Destination | Port | Purpose |
|---|---|---|
| `nvcr.io` | 443 | NVIDIA containers |
| `developer.download.nvidia.com` | 443 | CUDA, cuDNN |
| `github.com` | 443 | Source and tools |
| `pypi.org` | 443 | Python packages |
| `zenodo.org` | 443 | DS-1 |
| `storage.googleapis.com` | 443 | GCP A100 access |
| `*.amazonaws.com` | 443 | AWS access |
| `*.intel-ncl.atlassian.net` | 443 | INRC |
| `packages.openfhe.org` | 443 | OpenFHE |
| `github.com/open-quantum-safe` | 443 | liboqs |

### 8.2 Required ingress (if you expose the deployment)

For a **production** deployment:

| Service | Port | Notes |
|---|---|---|
| DoH resolver | 443/tcp | Behind TLS 1.3 |
| DoT resolver | 853/tcp | Behind TLS 1.3 |
| DoQ resolver | 853/udp | Behind QUIC + TLS 1.3 |
| Kubernetes API | 6443/tcp | Only from admin VLAN |
| Prometheus | 9090/tcp | Only from admin VLAN |
| Grafana | 3000/tcp | Only from admin VLAN |

For a **development / benchmark** deployment, **close all ingress**
and use SSH tunnels.

### 8.3 What to give the network team

A one-page document with:

- The **IP ranges** the deployment will use.
- The **port matrix** above.
- The **TTL / egress policy** for each destination.
- A **contact** for incident response.

Most network teams will approve this within a week. Some will not
approve egress to `github.com` or `pypi.org`; in that case, you need
an **internal mirror**. This adds 1–2 weeks.

---

## 9. Institutional sign-offs

### 9.1 Who needs to sign off

| Sign-off | Who | When |
|---|---|---|
| Procurement | Finance / admin | Before PO |
| Data protection | DPO or Legal | Before downloading DS-1/2/3 |
| Network | Network team | Before deployment |
| Security | CISO / security team | Before deployment |
| Ethics (if human data) | IRB | Only if you use your own data |

### 9.2 What to prepare

For each sign-off, prepare a 1-page summary:

- **What** the deployment is (thesis artifact vs. production).
- **Why** it needs the approval (what data, what network access).
- **What the risk is** (the data is public, but the network exposure
  is not zero).
- **What happens if the sign-off is not granted** (we use the
  emulated path; the deployment is a research artifact, not a
  production service).
- **Who is responsible** (the PI).

---

## 10. Checklist (copy this)

- [ ] Procurement PO approved
- [ ] DPIA signed off (DS-1/2/3)
- [ ] **INRC membership submitted** (or Loihi skipped)
- [ ] NVIDIA Developer Program account created
- [ ] NVIDIA AI Enterprise licence purchased (if desired)
- [ ] Tofino NDA signed (if buying Tofino; otherwise skip)
- [ ] Tofino SDE licence purchased (if buying Tofino; otherwise skip)
- [ ] Cloud account created (GCP recommended)
- [ ] Firewall egress / ingress approved
- [ ] Network team contact identified
- [ ] Security team contact identified
- [ ] Vendor contact identified (Supermicro / Dell / HPE reseller)
- [ ] Shipping address confirmed
- [ ] Fixed asset tag prepared

**When every box is ticked, proceed to `HARDWARE_BOM.md` and
`COST_ESTIMATE.md`.**

---

## 11. What if I cannot get one of these approvals

Each prerequisite has a fallback:

| Blocked prerequisite | Fallback |
|---|---|
| Procurement PO (no budget) | Use cloud profile C; no capex |
| DPIA (no DPO) | Use the thesis artifact's toy datasets |
| **INRC (Loihi 2)** | **Use the emulator** (`loihi_mock.py`) |
| NVIDIA Enterprise | Use free drivers + CUDA |
| Tofino NDA | Use BMv2-on-NIC |
| Cloud account | Use profile A (on-prem) |
| Firewall egress | Use an internal mirror |

**None of these block the deployment itself.** They block the
specific feature that depends on them. The A³E-DNS framework runs on
the emulated path indefinitely; production deployment is optional.
