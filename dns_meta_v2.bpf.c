// SPDX-License-Identifier: GPL-2.0
// A3E-DNS v2: XDP metadata collector for encrypted-DNS flows (Section 6.5.5, 6.14.3).
// Counts packets/bytes per source, keeps a coarse inter-arrival histogram, and
// classifies the transport (DoH/DoT on TCP, DoQ on UDP). It never inspects payloads.
// NOT COMPILED IN THE ENVIRONMENT THAT PRODUCED THIS FILE. Build: see docs/v2/05_deployment_runbook.md
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define IAT_BINS 8
enum proto { P_OTHER = 0, P_DOH = 1, P_DOT = 2, P_DOQ = 3 };

struct flow_stat {
    __u64 pkts;
    __u64 bytes;
    __u64 last_ns;
    __u32 proto;
    __u32 iat_hist[IAT_BINS];   // log2 bins of inter-arrival time in microseconds
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1 << 20);
    __type(key, __u32);          // IPv4 source address
    __type(value, struct flow_stat);
} flows SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 4);
    __type(key, __u32);
    __type(value, __u64);
} proto_pkts SEC(".maps");

static __always_inline __u32 bin_of(__u64 us)
{
    __u32 b = 0;
    #pragma unroll
    for (int i = 0; i < IAT_BINS - 1; i++) {
        if (us >= (1ULL << (i + 3))) b = i + 1;
    }
    return b;
}

SEC("xdp")
int a3e_dns_meta(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data, *end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > end) return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP)) return XDP_PASS;
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > end) return XDP_PASS;

    __u32 proto = P_OTHER;
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *t = (void *)ip + ip->ihl * 4;
        if ((void *)(t + 1) > end) return XDP_PASS;
        if (t->dest == bpf_htons(443)) proto = P_DOH;
        else if (t->dest == bpf_htons(853)) proto = P_DOT;
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *u = (void *)ip + ip->ihl * 4;
        if ((void *)(u + 1) > end) return XDP_PASS;
        if (u->dest == bpf_htons(853)) proto = P_DOQ;
    }
    if (proto == P_OTHER) return XDP_PASS;

    __u64 now = bpf_ktime_get_ns();
    __u32 key = ip->saddr, pk = proto;
    __u64 *pc = bpf_map_lookup_elem(&proto_pkts, &pk);
    if (pc) (*pc)++;

    struct flow_stat *fs = bpf_map_lookup_elem(&flows, &key);
    if (!fs) {
        struct flow_stat n = { .pkts = 1, .bytes = (__u64)(end - data), .last_ns = now, .proto = proto };
        bpf_map_update_elem(&flows, &key, &n, BPF_ANY);
        return XDP_PASS;
    }
    __u64 us = (now - fs->last_ns) / 1000;
    __u32 b = bin_of(us);
    if (b < IAT_BINS) __sync_fetch_and_add(&fs->iat_hist[b], 1);
    __sync_fetch_and_add(&fs->pkts, 1);
    __sync_fetch_and_add(&fs->bytes, (__u64)(end - data));
    fs->last_ns = now; fs->proto = proto;
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
