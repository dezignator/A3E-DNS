# 02_OS_SETUP — Ubuntu Server 22.04 LTS on All 4 Nodes

**Prerequisite: `01_HARDWARE_SETUP.md` is complete.**

This document installs Ubuntu Server 22.04 LTS on each of the 4
servers, configures the network, hardens the OS, and installs the
base toolchain. Run it on **every node** (node-1 through node-4).

---

## 1. Prepare the installer USB

### 1.1 Download

```bash
wget https://releases.ubuntu.com/22.04.4/ubuntu-22.04.4-live-server-amd64.iso
sha256sum ubuntu-22.04.4-live-server-amd64.iso
# Compare against the value on releases.ubuntu.com — do NOT skip this.
