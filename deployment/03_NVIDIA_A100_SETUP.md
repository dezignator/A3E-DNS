
---

### File 172 — `deployment/03_NVIDIA_A100_SETUP.md`

**Upload path on GitHub:** `deployment/03_NVIDIA_A100_SETUP.md`

```markdown
# 03_NVIDIA_A100_SETUP — Driver, CUDA 12.4, cuDNN, NCCL

**Prerequisite: `02_OS_SETUP.md` is complete on the node where you
will install the A100.**

This document installs the NVIDIA driver, CUDA 12.4, cuDNN, NCCL,
and DCGM on the A100 host. If you are using **profile B (hybrid)**,
you install this **on the rented cloud A100**, not on the on-prem
nodes.

---

## 1. Before you install the A100

### 1.1 Physical

- [ ] `01_HARDWARE_SETUP.md` §2.4 is complete (CPU, RAM, NVMe
      installed, server boots to Ubuntu).
- [ ] Above-4G decoding is enabled in BIOS.
- [ ] Resizable BAR is enabled in BIOS.
- [ ] The A100's auxiliary power is connected (8-pin PCIe EPS or
      12VHPWR, depending on the model).
- [ ] The server has ≥ 1 U of free space above the A100 for airflow.
- [ ] The server PSU has ≥ 300 W headroom over the current
      consumption.

### 1.2 Software

- [ ] `02_OS_SETUP.md` is complete.
- [ ] Kernel headers are installed (`sudo apt install linux-headers-$(uname -r)`).
- [ ] `dkms` is installed (`sudo apt install dkms`).
- [ ] Secure Boot is disabled (see `01_HARDWARE_SETUP.md` §7.4).
- [ ] `build-essential` is installed.

### 1.3 Power on

Install the A100 physically, then power on the server. The fan speed
will briefly spike; this is normal.

---

## 2. Install the NVIDIA driver

### 2.1 Add the NVIDIA repository

```bash
wget https://developer.download.nvidia.com/compute/cuda/repos/ubuntu2204/x86_64/cuda-keyring_1.1-1_all.deb
sudo dpkg -i cuda-keyring_1.1-1_all.deb
sudo apt-get update
