#ifndef _PACKET_H
#define _PACKET_H

#include <stdio.h>
#include <stdbool.h>
#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_byteorder.h>
#include "hash.h"

/* Error types */
#define READ_ERROR_UNSUPPORTED_PROTOCOL 1

/* Five tuple struct */
struct ftuple {
    rte_be32_t src_ip;
    rte_be32_t dst_ip;
    rte_be16_t src_port;
    rte_be16_t dst_port;
    uint8_t ip_proto;
};

/* Returns an IP address from "a"."b"."c"."d" */
static inline rte_be32_t
get_ip_address(uint8_t a, uint8_t b, uint8_t c, uint8_t d)
{
#if __BYTE_ORDER == __BIG_ENDIAN
    return a | b << 8 | c << 16 | d << 24;
#else
    return rte_cpu_to_be_32(a << 24 | b << 16 | c << 8 | d);
#endif
}

/* Returns a port number in network endianness */
static inline rte_be16_t
get_port(uint16_t port)
{
    return rte_cpu_to_be_16(port);
}

/* Fills "mbuf" with a single IPV4 packet of "size" bytes with
 * "ftuple" 5-tuple header info */
void packet_generate_ftuple(struct rte_mbuf *mbuf,
                            struct rte_ether_addr *src_mac,
                            struct rte_ether_addr *dst_mac,
                            int size,
                            struct ftuple *ftuple,
                            bool print_packet);

/* Fills "mbuf" with raw packet bytes from "bytes" with size "size" */
void packet_generate_raw(struct rte_mbuf *mbuf, const char *bytes, size_t size);

/* Extracts the 5-tuple "ftuple" from the packet in "mbuf". "bytes" holds
 * a pointer to the packet payload, and "size" the payload size. */
int packet_read_ftuple(struct rte_mbuf *mbuf,
                       struct ftuple *ftuple,
                       char **bytes,
                       int *size);

/* Extract a timestamp from a packet payload */
uint64_t packet_parse_timestamp(char *bytes, int size);

/* Parses "str" into the 5-tuple "ftuple". Returns 0 on success.
 * "str" format: IP_PROTO,SRC-IP,DST-IP,SRC-PORT,DST-PORT
 * (delimiter can also be ' ' or '\t')
 */
int ftuple_parse(struct ftuple *ftuple, const char *str);

/* Print 5-tuple to file */
void ftuple_print(FILE *f, struct ftuple *ftuple);

static inline uint32_t
ftuple_hash(struct ftuple *ftuple)
{
    return hash_bytes(ftuple, sizeof(*ftuple), 0);
}

/* Returns true iff "a" == "b" */
static inline bool
ftuple_compare(struct ftuple *a, struct ftuple *b)
{
    return a->src_ip == b->src_ip &&
           a->dst_ip == b->dst_ip &&
           a->src_port == b->src_port &&
           a->dst_port == b->dst_port &&
           a->ip_proto == b->ip_proto;
}

#endif
