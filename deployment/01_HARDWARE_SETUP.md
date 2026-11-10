# 01_HARDWARE_SETUP — Physical Installation

**Assumes `PREREQUISITES.md` is complete and the hardware has arrived.**

This document covers unboxing, racking, cabling, BIOS configuration,
IPMI / BMC setup, and the first power-on for the 4-node testbed and
the A100 / Tofino hardware.

---

## 1. Before you start

### 1.1 What you need

- **4 servers** (2× Xeon Silver, 2× EPYC), as per `HARDWARE_BOM.md` §2.1
- **1 A100 80 GB PCIe** (if buying; else skip)
- **1 Tofino-1 switch** (if buying; else skip)
- **4 ConnectX-6 Dx NICs** + **1 SN2410 switch** + cables
- **1 rack** (12U or 24U)
- **1 PDU** (30 A, 208 V)
- **1 UPS** (3 kVA)
- **1 KVM switch** + LCD
- **1 laptop** with Ubuntu 22.04 for the initial setup (not for
  production; just for the installer)
- **1 8 GB USB stick** (for the Ubuntu installer)
- **A second person** for lifting (a 2U server with a full sled
  weighs ~25 kg)

### 1.2 What to prepare

- [ ] Rack is secured to the floor and has ≥ 12U free
- [ ] PDU is connected to mains power and tested
- [ ] UPS is connected and charged
- [ ] Ethernet cables are labelled (both ends)
- [ ] Power cables are labelled (both ends)
- [ ] You have a printed copy of `HARDWARE_BOM.md` to check off parts
- [ ] You have a printed copy of the IP plan (see §5)

### 1.3 What **not** to do

- Do **not** install the A100 before the server boots. Install the
  server OS first, verify it works, then install the A100.
- Do **not** power on the Tofino switch before reading §7.
- Do **not** plug anything into the rack PDU before testing the PDU
  outlets.

---

## 2. Inventory and inspection

### 2.1 Unbox

Unbox each item and check against `HARDWARE_BOM.md`:

- [ ] 2× Intel Xeon Silver 4314 (or your CPU) — boxed, sealed
- [ ] 2× AMD EPYC 7543 (or your CPU) — boxed, sealed
- [ ] 4× Supermicro (or Dell / HPE) motherboards
- [ ] 4× chassis with PSU and fans
- [ ] 4× 4× 32 GB DDR4-3200 ECC RDIMM
- [ ] 4× 2 TB NVMe SSD
- [ ] 4× Mellanox ConnectX-6 Dx
- [ ] 1× A100 80 GB PCIe (if bought)
- [ ] 1× Tofino-1 switch (if bought)
- [ ] 1× SN2410 switch
- [ ] 8× 25 GbE SFP28 DAC cables
- [ ] 4× 100 GbE QSFP28 DAC cables
- [ ] Rack, PDU, UPS, KVM, LCD
- [ ] All manuals and warranty cards

### 2.2 Inspect

For each server:

- [ ] Chassis has no dents or cracks
- [ ] All fans are present (typically 6 per 2U chassis)
- [ ] All PSUs are present (typically 2 per chassis)
- [ ] NVMe slot is accessible
- [ ] PCIe slots are empty and undamaged
- [ ] Front panel LEDs are intact

For the A100:

- [ ] Anti-static bag is sealed
- [ ] Card has no bent pins
- [ ] Bracket is intact
- [ ] Serial number recorded (for warranty)

For the Tofino switch:

- [ ] Front panel ports are intact
- [ ] Console port is accessible
- [ ] All PSUs are present

**If anything is damaged, stop and call the vendor before
proceeding.** Do not install damaged hardware.

---

## 3. Rack installation

### 3.1 Rack layout

A 12U rack layout (bottom to top):

| U | Equipment |
|---|---|
| 1–2 | Server 1 (node-1) |
| 3–4 | Server 2 (node-2) |
| 5–6 | Server 3 (node-3) |
| 7–8 | Server 4 (node-4) |
| 9 | Tofino switch (if bought) |
| 10 | SN2410 switch |
| 11 | KVM + LCD |
| 12 | Cable management / free |

If you bought a 24U rack, use the lower 12U for equipment and the
upper 12U for cable management. Do **not** install servers above
head height.

### 3.2 Mount the rails

For each server:

1. Attach the inner rails to the server chassis (usually 4 screws
   per rail).
2. Attach the outer rails to the rack (usually 2 screws per rail,
   front and rear).
3. Slide the server onto the rails.

**Do not fully push the server in until cabling is done.**

### 3.3 Mount the switches

1. Attach the rack-mount ears to the switches.
2. Screw the switches to the rack.
3. Leave 1U of space above each switch for airflow.

### 3.4 Connect power

**Order matters.** Do this in sequence:

1. **PDU** → wall outlet. Verify PDU shows voltage.
2. **UPS** → PDU. Verify UPS shows "on battery" briefly, then
   "online".
3. **Server PSU** (both PSUs per server) → UPS.
4. **Switch PSU** → UPS.
5. **KVM** → UPS.

Do **not** connect to wall power during a thunderstorm. Do **not**
daisy-chain PDUs.

### 3.5 Connect management network

1. **IPMI / BMC** port on each server → management switch (or
   SN2410 if you have no separate management switch).
2. **Console** port on each switch → KVM or your laptop.
3. **KVM** keyboard / mouse / LCD → first server (you will swap
   cables for each server).

---

## 4. Install CPUs, RAM, and NVMe

### 4.1 CPU installation

For each server:

1. Ground yourself (anti-static wrist strap to bare metal).
2. Remove the CPU socket cover.
3. Align the CPU notch with the socket notch. **Do not force it.**
4. Close the retention bracket.
5. Apply thermal paste (a pea-sized dot in the centre).
6. Install the heatsink. Tighten screws in a diagonal pattern
   (1-3-2-4).

### 4.2 RAM installation

For a Xeon Silver server (4-channel):

1. Install 1 DIMM per channel, starting with slot A1, B1, C1, D1.
2. Then A2, B2, C2, D2 (if you have 8 DIMMs).

For an EPYC server (8-channel):

1. Install 1 DIMM per channel, starting with A1, B1, C1, D1, E1,
   F1, G1, H1.
2. Then the second slot in each channel.

**Do not mix DIMM sizes or speeds.** All DIMMs must be identical.

### 4.3 NVMe installation

1. Locate the M.2 or U.2 slot.
2. Insert the NVMe at a 30-degree angle.
3. Press down and secure with the retention screw.

### 4.4 A100 installation (only if bought)

Do **not** install the A100 yet. Install the OS first (see
`02_OS_SETUP.md`), verify the server boots, then install the A100.

---

## 5. IP plan

Before the first power-on, decide the IP addresses. A typical plan:

| Node | Hostname | Mgmt IP | Data IP | Role |
|---|---|---|---|---|
| Server 1 | node-1 | 10.0.1.11 | 10.0.2.11 | FL coordinator |
| Server 2 | node-2 | 10.0.1.12 | 10.0.2.12 | QHE service |
| Server 3 | node-3 | 10.0.1.13 | 10.0.2.13 | Anomaly + AMPS |
| Server 4 | node-4 | 10.0.1.14 | 10.0.2.14 | Threat intel + P4 |
| SN2410 | switch | 10.0.1.2 | — | Aggregation |
| Tofino | tofino | 10.0.1.3 | — | P4 switch |
| Gateway | gw | 10.0.1.1 | 10.0.2.1 | Default route |

**Do not use DHCP.** Static IPs are required for Kubernetes (the
control plane needs stable addresses).

---

## 6. First power-on

### 6.1 Power on the SN2410 switch

1. Press the power button.
2. Wait 2 minutes for the switch to boot.
3. Connect via console (9600-8-N-1) using the KVM.
4. Assign the management IP (10.0.1.2) and default gateway
   (10.0.1.1). See the SN2410 quick-start guide.
5. Verify: `ping 10.0.1.2` from your laptop (plugged into a
   management port).

### 6.2 Power on each server

1. Connect a keyboard, mouse, and LCD to the first server (via
   KVM).
2. Press the power button.
3. Enter BIOS (Del or F2 on Supermicro; F9 on Dell; F10 on HPE).
4. Configure BIOS per §7.
5. Save and reboot.

### 6.3 Power on the Tofino switch (if bought)

**Do not power on the Tofino yet.** See §9.

---

## 7. BIOS configuration

For each server, set:

### 7.1 Boot order

1. USB (for the Ubuntu installer)
2. NVMe (for the OS)
3. Network (PXE, disabled if you do not use PXE)

### 7.2 Virtualisation

- **Intel VT-x**: Enabled
- **Intel VT-d**: Enabled
- **AMD-V**: Enabled (EPYC)
- **AMD IOMMU**: Enabled (EPYC)
- **SR-IOV**: Enabled

### 7.3 Performance

- **Power profile**: Maximum Performance
- **C-states**: Disabled (or C1 only)
- **Turbo Boost**: Enabled
- **NUMA**: Enabled
- **Memory interleaving**: NUMA-aware (not channel-interleaved)

### 7.4 Security

- **Secure Boot**: Disabled (the A100 and Mellanox drivers are not
  all signed)
- **TPM**: Enabled (if present)
- **Boot password**: Set a BIOS password (for unattended reboot
  protection)
- **UEFI**: Enabled (not Legacy)

### 7.5 Hardware

- **SATA mode**: AHCI (if using SATA SSDs)
- **NVMe**: Enabled
- **PCIe**: Gen4 (or the highest the CPU supports)
- **Above 4G decoding**: Enabled (required for A100)
- **Resizable BAR**: Enabled (required for A100)

### 7.6 IPMI / BMC

- **BMC IP**: static, per §5
- **BMC user**: `ADMIN` / strong password
- **IPMI over LAN**: Enabled
- **Serial over LAN**: Enabled

---

## 8. IPMI / BMC setup

The BMC is a separate network interface on each server. It lets you
manage the server even when it is powered off.

### 8.1 Configure the BMC

1. From the BIOS, note the BMC IP (usually DHCP by default; set it
   static).
2. From your laptop, open `https://<bmc-ip>` in a browser.
3. Log in with the default credentials (usually `ADMIN` /
   `ADMIN` — change this immediately).
4. Set the BMC password to something strong.
5. Configure the BMC IP, netmask, and gateway per §5.
6. Enable **IPMI over LAN**.
7. Test: `ipmitool -I lanplus -H <bmc-ip> -U ADMIN -P <password>
   power status`.

### 8.2 What IPMI is used for

- **Remote power** (`power on`, `power off`, `power cycle`).
- **Serial console** (for when SSH is broken).
- **Sensor readings** (temperature, fan speed, PSU status).
- **Event log** (hardware errors).

### 8.3 What IPMI is **not** used for

- **OS-level management.** That is SSH.
- **Application deployment.** That is Kubernetes.
- **Observability.** That is Prometheus.

---

## 9. Tofino switch setup (only if bought)

### 9.1 Power-on

1. Connect the **console** cable (RJ-45 to DB-9 or USB).
2. Open a serial terminal (115200-8-N-1).
3. Power on the switch.
4. Wait 3–5 minutes for the ONIE installer to boot.

### 9.2 Install the NOS

The Tofino switch ships with **ONIE** (Open Network Install
Environment) and no NOS. You need to install one of:

- **Stratum** (open source, from the Open Networking Foundation).
- **SONiC** (Microsoft, open source).
- **Intel Tofino SDE reference NOS** (requires the SDE; see
  `PREREQUISITES.md` §5).

**Recommendation:** use Stratum. It supports P4Runtime, which is
what the A³E-DNS P4 pipeline uses.

**Details:** see `05_P4_SETUP.md` §3. Do **not** attempt to install
Stratum during hardware setup; do it after the OS is set up.

### 9.3 Cable

1. **Management** port → SN2410 (or your management switch).
2. **Data** ports → SN2410.
3. **Console** port → KVM.

---

## 10. Cable everything

### 10.1 Cable the servers

For each server:

1. **IPMI / BMC** port → SN2410 (port 1–4).
2. **ConnectX-6 Dx port 0** → SN2410 (port 5–12).
3. **ConnectX-6 Dx port 1** → SN2410 (port 13–20, optional for
   redundancy).
4. **Onboard 1 GbE** → SN2410 (management, port 21–24).

### 10.2 Cable the switches

1. **SN2410 port 25** → **Tofino port 1** (100 GbE QSFP28).
2. **Tofino port 2** → **SN2410 port 26** (100 GbE, optional).

### 10.3 Label everything

- Both ends of every cable.
- Naming convention: `<node>-<interface>-<purpose>`.
- Examples: `node-1-bmc-mgmt`, `node-1-cx6-p0-data`,
  `node-4-onboard-mgmt`.

### 10.4 Verify

- [ ] All servers can reach the SN2410
- [ ] All BMCs are reachable
- [ ] All switches are reachable via console
- [ ] No link errors on the switch ports

---

## 11. First boot checklist

- [ ] All 4 servers power on
- [ ] All 4 servers pass POST
- [ ] All 4 BMCs are reachable
- [ ] All 4 servers have correct BIOS settings
- [ ] All 4 servers can reach the SN2410 via IPMI
- [ ] The SN2410 is reachable
- [ ] The Tofino is reachable (if bought)
- [ ] All cables are labelled
- [ ] The UPS is on
- [ ] The PDU is on
- [ ] Ambient temperature is < 25 °C
- [ ] Fan noise is uniform (any loud fan = problem)

**If any of the above fails, stop and diagnose.** Do not proceed to
`02_OS_SETUP.md` until all 12 items are green.

---

## 12. Common problems

| Symptom | Likely cause | Fix |
|---|---|---|
| Server will not POST | RAM not seated | Reseat RAM, one DIMM at a time |
| Server beeps twice | CPU not seated | Reseat CPU |
| Server beeps three times | RAM error | Try one DIMM, then pairs |
| BMC unreachable | DHCP not configured | Boot to BIOS, set BMC static |
| Fan loud after 30 s | Thermal trip | Check heatsink, thermal paste |
| Switch will not boot | Bad PSU | Swap PSU |
| Tofino will not boot | No NOS | See `05_P4_SETUP.md` §3 |
| A100 not detected | Above-4G not enabled | Enable BIOS setting |
| Link down on SN2410 | Bad cable | Swap cable |
| Link up but no traffic | VLAN mismatch | Check switch config |

See `14_TROUBLESHOOTING.md` for more.

---

## 13. Sign-off

Do not proceed to `02_OS_SETUP.md` until:

- [ ] All 12 items in §11 are green
- [ ] All cabling is labelled
- [ ] All BMCs are reachable
- [ ] The rack is closed and secured
- [ ] The temperature is stable
- [ ] The UPS runtime has been tested (pull the plug for 30 s)
- [ ] The rack is documented in your organisation's asset register
