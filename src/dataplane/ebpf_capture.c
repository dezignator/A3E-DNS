/* ============================================================
 * A3E-DNS — eBPF / XDP packet capture for encrypted-DNS metadata
 * Thesis §6.11.2, §6.12
 * ============================================================
 *
 * Attaches at the XDP hook (driver level, before the kernel network
 * stack) so that encrypted-DNS traffic is captured at line rate with
 * minimal CPU overhead. The filter accepts only the resolver ports
 * defined in §6.11.2:
 *
 *     tcp port 443     DoH
 *     tcp port 853     DoT
 *     udp port 853     DoQ
 *
 * For accepted packets, the program records the 5-tuple, timestamp
 * and packet length in a per-CPU ring buffer that userspace reads via
 * bcc or xdp-loader. No payload is copied; only metadata.
 *
 * Compile:
 *     clang -O2 -target bpf -c ebpf_capture.c -o ebpf_capture.o
 *
 * Load:
 *     xdp-loader load -m skb <iface> ebpf_capture.o
 *     # or via src/dataplane/ebpf_loader.py
 * ============================================================ */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>

/* ---------- Configuration ---------- */
#define PORT_DOH 443
#define PORT_DOT 853
#define PORT_DOQ 853
#define MAX_RECORDS 4096

/* ---------- Metadata record emitted to userspace ---------- */
struct pkt_meta {
    __u64 timestamp_ns;
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u16 payload_length;
    __u8  ip_proto;       /* 6 = TCP, 17 = UDP */
    __u8  protocol_id;    /* 1 = DoH, 2 = DoT, 3 = DoQ */
    __u8  pad[2];
};

/* ---------- BPF ring buffer (or perf buffer fallback) ---------- */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, MAX_RECORDS * sizeof(struct pkt_meta));
} meta_ringbuf SEC(".maps");

/* ---------- Per-CPU counters for observability ---------- */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 4);
    __type(key, __u32);
    __type(value, __u64);
} counters SEC(".maps");

static __always_inline void bump(__u32 idx) {
    __u64 *val = bpf_map_lookup_elem(&counters, &idx);
    if (val) {
        __sync_fetch_and_add(val, 1);
    }
}

SEC("xdp")
int xdp_capture(struct xdp_md *ctx)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    /* Ethernet header */
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        return XDP_PASS;
    }
    if (eth->h_proto != __constant_htons(ETH_P_IP)) {
        return XDP_PASS;
    }

    /* IPv4 header */
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) {
        return XDP_PASS;
    }

    struct pkt_meta *rec = bpf_ringbuf_reserve(&meta_ringbuf, sizeof(struct pkt_meta), 0);
    if (!rec) {
        bump(3);  /* drop */
        return XDP_PASS;
    }

    rec->timestamp_ns = bpf_ktime_get_ns();
    rec->src_ip       = ip->saddr;
    rec->dst_ip       = ip->daddr;
    rec->ip_proto     = ip->protocol;
    rec->protocol_id  = 0;

    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
        if ((void *)(tcp + 1) > data_end) {
            bpf_ringbuf_discard(rec, 0);
            return XDP_PASS;
        }
        __u16 sport = __builtin_bswap16(tcp->source);
        __u16 dport = __builtin_bswap16(tcp->dest);
        __u16 tot_len = __builtin_bswap16(ip->tot_len);
        rec->src_port       = sport;
        rec->dst_port       = dport;
        rec->payload_length = (tot_len > ip->ihl * 4) ? (tot_len - ip->ihl * 4) : 0;

        if (sport == PORT_DOH || dport == PORT_DOH) {
            rec->protocol_id = 1;  /* DoH */
            bump(0);
        } else if (sport == PORT_DOT || dport == PORT_DOT) {
            rec->protocol_id = 2;  /* DoT */
            bump(1);
        } else {
            bpf_ringbuf_discard(rec, 0);
            return XDP_PASS;
        }
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)ip + (ip->ihl * 4);
        if ((void *)(udp + 1) > data_end) {
            bpf_ringbuf_discard(rec, 0);
            return XDP_PASS;
        }
        __u16 sport = __builtin_bswap16(udp->source);
        __u16 dport = __builtin_bswap16(udp->dest);
        __u16 len   = __builtin_bswap16(udp->len);
        rec->src_port       = sport;
        rec->dst_port       = dport;
        rec->payload_length = (len > 8) ? (len - 8) : 0;

        if (sport == PORT_DOQ || dport == PORT_DOQ) {
            rec->protocol_id = 3;  /* DoQ */
            bump(2);
        } else {
            bpf_ringbuf_discard(rec, 0);
            return XDP_PASS;
        }
    } else {
        bpf_ringbuf_discard(rec, 0);
        return XDP_PASS;
    }

    bpf_ringbuf_submit(rec, 0);
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
