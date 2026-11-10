
---

### File 173 — `deployment/04_INTEL_LOIHI_SETUP.md`

**Upload path on GitHub:** `deployment/04_INTEL_LOIHI_SETUP.md`

```markdown
# 04_INTEL_LOIHI_SETUP — NxSDK and Lava on Loihi 2

**Prerequisite: `PREREQUISITES.md` §3 (INRC membership) is approved.**

This document installs the Intel Loihi 2 toolchain (NxSDK and Lava)
and verifies that the Loihi 2 chip is reachable and usable. It is
**only required** if you have a physical Loihi 2 board or INRC cloud
access.

If you **do not** have Loihi 2, skip this document. The A³E-DNS
artifact's `loihi_mock.py` reproduces the reported figures exactly
(see `docs/HARDWARE_EMULATION.md` §3), and the integrated A³E-DNS
pipeline does not require Loihi 2 (only the PAFA-DoH chapter does).

---

## 1. What Loihi 2 is (and what it is not)

### 1.1 What Loihi 2 is

- A **neuromorphic research chip** from Intel Labs.
- **128 neuromorphic cores**, each with 1,024 LIF neurons → 131,072
  neurons total.
- **128 million synapses**.
- Programmable in **Lava** (an open-source Python framework) and
  **NxSDK** (a lower-level C/Python SDK).
- Available **only** via the Intel Neuromorphic Research Community
  (INRC).

### 1.2 What Loihi 2 is not

- **A GPU.** It does not run CUDA. It does not accelerate dense
  matrix multiplication. It is efficient for **sparse, event-driven**
  workloads (spiking neural networks).
- **A consumer product.** There is no retail price; there is no
  purchase path.
- **A drop-in replacement** for the A100. The A³E-DNS pipeline uses
  the A100 for QHE and the transformer; Loihi is used only in
  Chapter 4 for the SNN anomaly detector.

### 1.3 If you do not have Loihi 2

You have three options:

1. **Skip.** Do not install NxSDK or Lava. The A³E-DNS artifact's
   emulator (`loihi_mock.py`) reproduces the reported figures.
2. **INRC cloud.** If you are an INRC member, use the cloud.
3. **Request membership.** See `PREREQUISITES.md` §3.

---

## 2. What the INRC provides

### 2.1 Membership benefits

When your INRC membership is approved, you receive:

- **Access to the INRC cloud** (a shared cluster of Loihi 2 chips
  you can reach over SSH from your institution).
- **Credentials for NxSDK** and **Lava** downloads.
- **A physical Loihi 2 board** (in some cases; the committee decides
  based on your proposal).
- **An Intel Labs point of contact** for technical questions.

### 2.2 Membership obligations

- **Use the chip only for research.** Commercial use requires a
  separate licence.
- **Report results.** Intel Labs may request a brief summary of
  what you did; this is usually optional but strongly encouraged.
- **Do not share credentials.** They are per-institution.
- **Do not redistribute** the chip or the SDK.
- **Acknowledge the INRC** in publications. Standard format:
  *"This research used the Intel Neuromorphic Research Community
  (INRC) Loihi 2 platform."*

---

## 3. Prerequisites

### 3.1 Hardware

- [ ] INRC membership approved (see `PREREQUISITES.md` §3)
- [ ] If you received a physical board: a host server with a
      free **PCIe x8 Gen3 or Gen4 slot** (the Loihi 2 board is a
      PCIe card)
- [ ] If you are using the INRC cloud: an SSH key registered with
      INRC (see §4.2)

### 3.2 Software

- [ ] Ubuntu 22.04 LTS (matches `02_OS_SETUP.md`)
- [ ] Kernel headers installed
- [ ] Python 3.10 or 3.11 (the NxSDK supports 3.8–3.11; the
      A³E-DNS artifact uses 3.11)
- [ ] `git`, `wget`, `curl`, `build-essential`

### 3.3 Accounts

- [ ] INRC portal account (your institutional email)
- [ ] Access to the INRC cloud (usually the same account)

---

## 4. Physical Loihi 2 setup (if you have a board)

**If you are using the INRC cloud, skip to §5.**

### 4.1 Physical installation

1. **Power off** the host server.
2. Remove the host server from the rack (or pull it out on its rails).
3. Ground yourself.
4. Locate a free **PCIe x8 Gen3 or Gen4 slot**.
5. Remove the slot cover.
6. Insert the Loihi 2 board. **Do not force it.**
7. Screw the bracket.
8. Reinstall the server.
9. Reconnect power.
10. Power on.

### 4.2 Verify detection

```bash
lspci | grep -i intel
# You should see an entry like:
# 03:00.0 Co-processor: Intel Corporation Device 0d0f (rev 01)
