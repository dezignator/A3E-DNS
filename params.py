"""Parameter registry for Chapter 6 (A3E-DNS).

Each entry records the value stated in the thesis, the section it comes
from, and a status flag. Rows flagged "conflict" are places where two
statements in the chapter disagree; docs/v2/08_consistency_audit.md
discusses each one.
"""
from dataclasses import dataclass, asdict
import csv, io

@dataclass(frozen=True)
class Param:
    key: str
    value: str
    section: str
    component: str
    status: str = "stated"   # stated | conflict | derived
    note: str = ""

REGISTRY = [
 # --- AEE (6.4)
 Param("aee.window_packets","1000","6.4.1","AEE"),
 Param("aee.state_group","SE(3)^n","6.4.2","AEE"),
 Param("aee.session_key_bits","256","6.4.2","AEE"),
 Param("aee.controller_layers","2 x 64 (feed-forward)","6.4.5","AEE"),
 Param("aee.controller_training","reinforcement learning","6.4.5","AEE"),
 Param("aee.sigma_min_positive","true (0 < sigma_min <= sigma_max)","6.4.4","AEE"),
 Param("aee.key_rotation_interval_s","10","Table 27","AEE"),
 Param("aee.entropy_threshold","0.95","Table 27","AEE"),
 Param("aee.entropy_source","RDRAND/RDSEED + system entropy, whitened","6.4.3","AEE","conflict",
       "Table 27 command uses /dev/urandom"),
 Param("aee.failover","chacha20","Table 27","AEE"),
 Param("aee.latency_increase_ms","0.2","Table 27","AEE","conflict",
       "6.17.2 reports 0.8 ms for the whole security layer"),
 Param("aee.param_update_us_max","45","Section 6.1 text; Table 26 row","AEE"),
 # --- QHE (6.5)
 Param("qhe.ring_dimension_n","256","Table 34a","QHE","conflict","Table 27 lists lattice dimension 1024"),
 Param("qhe.modulus_q","4096","Table 34a","QHE","conflict","Table 27 lists modulus 3329"),
 Param("qhe.error_sigma","1.58","Table 27","QHE"),
 Param("qhe.simd_slots","1024","6.5.1","QHE","conflict","n=256 gives at most 256 coefficient slots"),
 Param("qhe.speedup_vs_reference","28x","6.5.1","QHE"),
 Param("qhe.ziggurat_latency_gain","47%","6.5.2","QHE"),
 Param("qhe.selective_op_reduction","8x","6.5.3","QHE"),
 Param("qhe.compression_ratio","8:1","6.5.5","QHE"),
 Param("qhe.pipeline_depth","3","6.5.5","QHE"),
 Param("qhe.cpu_cores","16","6.5.5","QHE"),
 Param("qhe.core_utilization","92%","6.5.5","QHE"),
 Param("qhe.gpu","NVIDIA A100, 6912 CUDA cores, 40 GB","6.5.4","QHE"),
 Param("qhe.gpu_lattice_tops","2.5","6.5.4","QHE"),
 Param("qhe.cpu_overhead","+12% CPU, +256 MB","Table 27","QHE"),
 Param("qhe.kem","ML-KEM-1024 and Classic McEliece (hybrid KEM)","Table 29","QHE"),
 # --- FL (6.6)
 Param("fl.rounds","100","Table 27","FL"),
 Param("fl.clients","100","Table 27","FL"),
 Param("fl.dp_epsilon","0.68","6.6.5","FL","conflict","Table 27 and Table 30 use 0.7"),
 Param("fl.dp_noise_mechanism","Gaussian (RDP accountant)","6.6.5","FL","conflict",
       "Table 27 lists Lap(0.1/0.7)"),
 Param("fl.transformer_layers","8","Table 27","FL"),
 Param("fl.transformer_heads","12","Table 27","FL"),
 Param("fl.attention_window","512","Table 27","FL"),
 Param("fl.pgd_epsilon","0.3","Table 30","FL"),
 Param("fl.adversarial_epochs","50","Table 30","FL"),
 Param("fl.byzantine_bound","f < N/2","6.2.3","FL"),
 Param("fl.learning_rate_base","6.5%","6.9.3 (Eq. 133)","FL"),
 Param("fl.dp_accuracy_cost_pp","0.4","6.17.2","FL"),
 Param("fl.bandwidth_per_round_MB","1.2","Table 27","FL"),
 # --- Sandbox / intel / data plane
 Param("sandbox.memory","2GB","Table 27","Sandbox"),
 Param("sandbox.timeout_s","30","Table 27","Sandbox"),
 Param("sandbox.replication_factor","3","Table 27","Sandbox"),
 Param("sandbox.overhead","15%","Table 27","Sandbox"),
 Param("intel.stix_latency_ms_max","100","6.7.1","Intel"),
 Param("intel.cert_rules_per_min","15","Table 28","Intel"),
 Param("intel.effectiveness_pct","CERT 94.2, honeypot 96.8, darknet 89.5, vendor 92.1, internal logs 97.3","Table 28","Intel"),
 Param("intel.ingestion","CERT real-time push; honeypot 5 min; darknet hourly PCAP; vendor daily; logs continuous","Table 28","Intel"),
 Param("anomaly.inference_latency_ms","0.08 per DNS query","Table 27","FL"),
 Param("fl.isolate_threshold","3 sigma","Table 27","FL"),
 Param("qhe.degrade_level","512 (failover)","Table 27","QHE"),
 Param("qhe.parallel","8","Table 27","QHE"),
 Param("qhe.noise","N(0, 1.58)","Table 27","QHE"),
 Param("data.dataset","Gen-C-DDD-2022 (32+ GB)","6.13.1","Data"),
 Param("data.preprocess_hours","~2","6.13","Data"),
 Param("testbed.nodes","4 (Xeon Silver / EPYC, 16 or 32 cores, 128 GB DDR4)","6.11.1","Testbed"),
 Param("testbed.os","Ubuntu Server 22.04 LTS","6.11.1","Testbed"),
 # --- Reported results
 Param("res.accuracy_pct","99.94","Table 33","Results"),
 Param("fl.fl_poison_clients","7 (Table 32 S3) vs 5 (Table 31)","Tables 31, 32","FL","conflict","number of malicious clients differs between the two tables"),
 Param("fl.evasion_epsilon","0.15 (Table 32 S5) vs 0.3 (Table 30)","Tables 30, 32","FL","conflict","attack epsilon in S5 differs from the PGD defence epsilon; may be intentional"),
 Param("fl.side_channel_noise","Laplace Lap(0.1/eps) (Table 30) vs Gaussian N(0, 0.5) (Table 31)","Tables 30, 31","FL","conflict","two different timing-noise mechanisms are named"),
 Param("res.fpr_pct","0.17","Table 33","Results"),
 Param("res.p99_ms","1.42","Table 33","Results"),
 Param("res.qps_M","22.5","Table 33","Results","conflict","the Section 6.15.1 introduction mentions a 30 M QPS load"),
 Param("res.adv_robustness_pct","96.5","Table 33","Results"),
 Param("res.dp_epsilon","0.68","Table 33","Results"),
]

def as_rows():
    return [asdict(p) for p in REGISTRY]

def to_csv() -> str:
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=list(asdict(REGISTRY[0]).keys()))
    w.writeheader(); w.writerows(as_rows())
    return buf.getvalue()

def conflicts():
    return [p for p in REGISTRY if p.status == "conflict"]
