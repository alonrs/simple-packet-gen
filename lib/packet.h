#ifndef _PACKET_H
#define _PACKET_H

#include <stdio.h>
#include <stdbool.h>
#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_byteorder.h>

/* Error types */
#define READ_ERROR_UNSUPPORTED_PROTOCOL 1
#define READ_ERROR_HASH 2

/* Five tuple struct */
struct ftuple {
    uint8_t ip_proto;
    rte_be32_t src_ip;
    rte_be32_t dst_ip;
    rte_be16_t src_port;
    rte_be16_t dst_port;
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
void generate_ftuple_packet(struct rte_mbuf *mbuf,
                            struct rte_ether_addr *src_mac,
                            struct rte_ether_addr *dst_mac,
                            int size,
                            struct ftuple *ftuple,
                            bool print_packet);

/* Reads a single packet from "mbuf", returns its timestamp into "timestamp".
 * Returns 0 on valid packet. */
int read_packet(struct rte_mbuf *mbuf, uint64_t *timestamp);

/* Parses "str" into the 5-tuple "ftuple". Returns 0 on success.
 * "str" format: IP_PROTO,SRC-IP,DST-IP,SRC-PORT,DST-PORT
 * (delimiter can also be ' ' or '\t')
 */
int ftuple_parse(struct ftuple *ftuple, const char *str);

/* Print 5-tuple to file */
void ftuple_print(FILE *f, struct ftuple *ftuple);

#endif
