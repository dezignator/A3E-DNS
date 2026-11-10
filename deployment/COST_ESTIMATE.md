# COST_ESTIMATE — Total Cost of Ownership

**The three profiles (purchase, hybrid, cloud-only) compared over a
3-year horizon.**

All numbers are indicative for early 2026, in USD, and exclude tax.
Prices will vary by vendor, region, and negotiation.

---

## 1. Summary

| Profile | Year-0 capex | Year-1 opex | 3-year TCO |
|---|---|---|---|
| **A. Full purchase** | $74,448 | $55,000 | **$239,448** |
| **B. Hybrid** | $28,680 | $40,000 | **$148,680** |
| **C. Cloud-only (unoptimized)** | $0 | $335,000 | **$1,005,000** |
| **C. Cloud-only (optimized)** | $0 | $54,000 | **$162,000** |

**Interpretation:**

- **Profile C unoptimized** is the trap: it is the most expensive over
  3 years because the A100 runs 24/7 at on-demand rates.
- **Profile C optimized** is competitive with **profile B** over 3
  years ($162 K vs $149 K) but has **zero capex** and **zero vendor
  management**. This is the right choice for a 1–3 year project.
- **Profile A** is the most expensive over 3 years ($239 K) but you
  own the hardware after year 3. If you plan to keep the hardware
  past year 3, profile A wins after ~year 4.
- **Profile B** is the cheapest over 3 years ($149 K) because it
  combines owned compute with rented accelerators.

The decision hinges on **how long you will use the hardware**:

| Horizon | Best profile |
|---|---|
| < 1 year | Profile C (optimized) |
| 1–3 years | Profile B |
| > 4 years | Profile A |

---

## 2. Profile A — Full purchase

### 2.1 Year-0 capex

| Category | Amount | Source |
|---|---|---|
| Servers (4) | $15,900 | `HARDWARE_BOM.md` §2.1 |
| Accelerators (A100 + Tofino; Loihi is free) | $39,000 | `HARDWARE_BOM.md` §2.2 |
| Networking | $9,480 | `HARDWARE_BOM.md` §2.3 |
| Facilities | $3,300 | `HARDWARE_BOM.md` §2.4 |
| **Subtotal** | **$67,680** | |
| Contingency (10%) | $6,768 | |
| **Year-0 capex** | **$74,448** | |

### 2.2 Year-1 opex

| Item | Amount | Notes |
|---|---|---|
| NVIDIA AI Enterprise licence | $4,500 | 1 GPU; optional but recommended |
| Tofino SDE licence | $50,000 | Required for Tofino hardware; drop if using BMv2-on-NIC |
| **Subtotal** | **$54,500** | |
| Electricity (4 servers + A100 + switch, 3.2 kW avg) | $0 | Included in facilities in some labs; add $3,400/year if you pay for power |
| **Year-1 opex** | **$54,500–$57,900** | |

### 2.3 Year-2 and year-3 opex

Same as year-1: **$54,500–$57,900/year**.

### 2.4 3-year TCO — profile A
