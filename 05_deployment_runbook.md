# 05. Deployment runbook (testbed of Section 6.11)

All files referenced here are in `deployment/v2/`. The XDP, P4, Mininet and Compose files were written for this package and have not been built or started in the environment that produced it; the verification column says what to check when you do.

## 5.1 Hardware and operating system (Section 6.11.1)

Four nodes with Intel Xeon Silver or AMD EPYC processors (16 or 32 cores) and 128 GB DDR4, Ubuntu Server 22.04 LTS. One node carries an NVIDIA A100 (6,912 CUDA cores, 40 GB) for the GPU path of Section 6.5.4.

## 5.2 Roles

| node | role | software |
|---|---|---|
| n1 | resolver front end (DoH, DoT, DoQ) | dnsdist with TLS, DoH and DoQ listeners (`dnsdist_v2.conf`) |
| n2 | QHE analyzer and sandbox host | `experiments_v2/qhe_analyzer_v2.py`, container runtime |
| n3 | FL coordinator | `experiments_v2/fl_coordinator_v2.py` |
| n4 | clients and load generators | Mininet topology or physical clients |

## 5.3 Bring-up order

| step | action | command | verify |
|---|---|---|---|
| 1 | system packages | `sudo apt install clang llvm libbpf-dev linux-tools-common bpftool mininet openvswitch-switch python3-venv` | `clang --version`, `bpftool version` |
| 2 | Python environment | `python3 -m venv .venv && . .venv/bin/activate && pip install -r requirements-v2.txt` | `make -f Makefile.v2 test` passes (42 tests) |
| 3 | XDP collector | `clang -O2 -g -target bpf -c deployment/v2/ebpf/dns_meta_v2.bpf.c -o dns_meta_v2.bpf.o` | object file builds |
| 4 | attach XDP | `sudo ip link set dev <if> xdp obj dns_meta_v2.bpf.o sec xdp` | `bpftool prog show`, `bpftool map dump name flows` |
| 5 | P4 program | `p4c-bm2-ss deployment/v2/p4/a3e_meta_v2.p4 -o a3e_meta_v2.json` | JSON produced |
| 6 | BMv2 switch | `simple_switch -i 1@veth0 -i 2@veth2 a3e_meta_v2.json` then `simple_switch_CLI < deployment/v2/p4/table_entries_v2.txt` | `table_dump classify` shows three entries |
| 7 | topology | `sudo python3 deployment/v2/scripts/mininet_topology_v2.py --profile wan_jitter --clients 8` | `pingall` succeeds |
| 8 | netem on a real interface | `sudo deployment/v2/scripts/netem_profiles_v2.sh eth1 wan` | `tc qdisc show dev eth1` |
| 9 | dataset | `python deployment/v2/scripts/dask_preprocess_v2.py --input <csv> --dask` | `split_manifest.json` written |
| 10 | services | `docker compose -f deployment/v2/docker-compose.v2.yml up --build` | logs show listeners and coordinator rounds |

## 5.4 Runtime parameters (Table 27)

| component | setting | value |
|---|---|---|
| AEE | key rotation / entropy threshold | 10 s / 0.95 |
| QHE | noise / failover level | N(0, 1.58) / 512 |
| FL | rounds, clients, bandwidth | 100, 100, about 1.2 MB per round |
| detector | layers, heads, window | 8, 12, 512 |
| sandbox | memory, timeout, replication | 2 GB, 30 s, 3 |

## 5.5 Failure modes

| symptom | likely cause | action |
|---|---|---|
| decryption returns wrong counts | summed more ciphertexts than the noise budget allows, or counts reached the plaintext modulus | check E4a for the parameter set; keep reporters x window below t |
| FL accuracy collapses with the mean aggregator | malicious share too high | switch to `mad_geomed` |
| F1 drops sharply after enabling DP | noise multiplier too large for the model size | review E3 grid, use sub-sampling accounting |
| XDP load fails | verifier rejects a loop or map access | rebuild with `-O2`, check kernel version |
| P4 compile error on `hash` or `register` | different v1model include path | adjust `-I` for your p4c installation |
| no DoQ listener | dnsdist build without QUIC | use a build that provides DoQ |

## 5.6 Safety

Run attack replays only on an isolated network that you own or are authorised to test. The package ships no launcher for live attack tools; Table 31 and Table 32 list the tools that Chapter 6 used.
