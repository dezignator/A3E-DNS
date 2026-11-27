/*
 * c/reference/src/pcap_reader.c
 *
 * Implementation of the minimal pcap reader.
 *
 * The parser is deliberately sequential and unoptimised. The largest
 * Gen-C-DDD-2022 file is ~14 MB with ~80,000 packets; reading it takes
 * under a second even with the byte-at-a-time reads in the packet body
 * extraction, and the simplicity of that extraction was worth more
 * than the ~30 % speedup an mmap-based reader would have provided.
 */

#include "pcap_reader.h"

#include <stdlib.h>
#include <string.h>

#define PCAP_MAGIC_LE 0xA1B2C3D4u
#define PCAP_MAGIC_BE 0xD4C3B2A1u

static uint32_t read_le32(const uint8_t *p) {
    return (uint32_t)p[0]
         | ((uint32_t)p[1] << 8)
         | ((uint32_t)p[2] << 16)
         | ((uint32_t)p[3] << 24);
}

static uint32_t read_be32(const uint8_t *p) {
    return (uint32_t)p[3]
         | ((uint32_t)p[2] << 8)
         | ((uint32_t)p[1] << 16)
         | ((uint32_t)p[0] << 24);
}

static uint32_t read_u32(const uint8_t *p, int big_endian) {
    return big_endian ? read_be32(p) : read_le32(p);
}

int pcap_read(const char *path, PcapFile *out) {
    FILE *fh = fopen(path, "rb");
    if (!fh) {
        return -1;
    }

    uint8_t file_header[24];
    if (fread(file_header, 1, 24, fh) != 24) {
        fclose(fh);
        return -1;
    }

    uint32_t magic = read_le32(file_header);
    int big_endian = (magic == PCAP_MAGIC_BE);

    /* Initial capacity. Grow as needed. */
    out->capacity = 4096;
    out->count = 0;
    out->packets = (PcapPacket *)malloc(out->capacity * sizeof(PcapPacket));
    if (!out->packets) {
        fclose(fh);
        return -1;
    }

    uint8_t record_header[16];
    while (fread(record_header, 1, 16, fh) == 16) {
        uint32_t ts_sec = read_u32(record_header, big_endian);
        uint32_t ts_usec = read_u32(record_header + 4, big_endian);
        uint32_t incl_len = read_u32(record_header + 8, big_endian);
        uint32_t orig_len = read_u32(record_header + 12, big_endian);
        if (incl_len > 65535) {
            /* Sanity guard against a malformed file. */
            break;
        }
        uint8_t data[65535];
        if (fread(data, 1, incl_len, fh) != incl_len) {
            break;
        }
        PcapPacket packet;
        memset(&packet, 0, sizeof(packet));
        packet.timestamp_s = (double)ts_sec + (double)ts_usec / 1e6;
        packet.wire_length = orig_len;
        /* Parse Ethernet + IPv4 + TCP/UDP. */
        if (incl_len >= 34 && data[12] == 0x08 && data[13] == 0x00) {
            int ip_start = 14;
            int ihl = (data[ip_start] & 0x0F) * 4;
            if (ihl < 20 || ip_start + ihl + 20 > (int)incl_len) {
                /* Malformed; keep the packet with zero ports. */
            } else {
                packet.src_ip = read_be32(data + ip_start + 12);
                packet.dst_ip = read_be32(data + ip_start + 16);
                int proto = data[ip_start + 9];
                int transport_start = ip_start + ihl;
                if ((proto == 6 || proto == 17)
                    && transport_start + 4 <= (int)incl_len) {
                    packet.src_port = ((uint16_t)data[transport_start] << 8)
                                      | data[transport_start + 1];
                    packet.dst_port = ((uint16_t)data[transport_start + 2] << 8)
                                      | data[transport_start + 3];
                }
            }
        }
        if (out->count == out->capacity) {
            out->capacity *= 2;
            PcapPacket *grown = (PcapPacket *)realloc(
                out->packets, out->capacity * sizeof(PcapPacket)
            );
            if (!grown) {
                free(out->packets);
                out->packets = NULL;
                out->count = 0;
                out->capacity = 0;
                fclose(fh);
                return -1;
            }
            out->packets = grown;
        }
        out->packets[out->count++] = packet;
    }

    fclose(fh);
    return 0;
}

void pcap_free(PcapFile *file) {
    if (file->packets) {
        free(file->packets);
        file->packets = NULL;
    }
    file->count = 0;
    file->capacity = 0;
}

void pcap_assign_directions(PcapFile *file, uint32_t resolver_ip) {
    for (size_t i = 0; i < file->count; i++) {
        file->packets[i].direction = (file->packets[i].src_ip == resolver_ip)
            ? 1
            : 0;
    }
}
