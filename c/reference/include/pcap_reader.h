/*
 * c/reference/include/pcap_reader.h
 *
 * Minimal classic-pcap reader.
 *
 * We wrote this parser because the extended suite needs to read the
 * Gen-C-DDD-2022 dataset's pcap files, and adding a dependency on
 * libpcap or on the Go pcap library for a 300-line parser would have
 * been disproportionate. The parser handles the classic pcap magic
 * (both endiannesses) and extracts the fields the pipeline needs:
 *
 *   - packet timestamp,
 *   - wire length,
 *   - source and destination IP,
 *   - source and destination port (for IPv4 TCP/UDP only).
 *
 * The parser does not handle pcapng. The Gen-C-DDD-2022 release
 * contains only classic pcap files; a pcapng reader would have been
 * dead code for the dataset the thesis uses.
 */

#ifndef A3E_REFERENCE_PCAP_READER_H
#define A3E_REFERENCE_PCAP_READER_H

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    double   timestamp_s;
    uint32_t wire_length;
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    /* 0: client -> resolver, 1: resolver -> client.
     * The classification is made by the caller via pcap_classify_direction.
     * Here we store it raw: 0 if the packet source is the first-seen
     * source of the flow, 1 otherwise. */
    uint8_t  direction;
} PcapPacket;

typedef struct {
    PcapPacket *packets;
    size_t      count;
    size_t      capacity;
} PcapFile;

/*
 * Read a classic pcap file. Returns 0 on success, -1 on failure.
 *
 * On success, out->packets is heap-allocated; call pcap_free() to
 * release it.
 */
int pcap_read(const char *path, PcapFile *out);

void pcap_free(PcapFile *file);

/*
 * Assign the direction field per packet.
 *
 * direction = 0 means the packet flows toward `resolver_ip`, and
 * direction = 1 means it flows away. The check is by source address:
 * a packet whose source is the resolver is direction 1; every other
 * packet is direction 0.
 */
void pcap_assign_directions(PcapFile *file, uint32_t resolver_ip);

#ifdef __cplusplus
}
#endif

#endif /* A3E_REFERENCE_PCAP_READER_H */
