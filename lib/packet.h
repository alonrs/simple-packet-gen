#ifndef _PACKET_H
#define _PACKET_H

#include <rte_mbuf.h>
#include <rte_byteorder.h>

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
    return rte_cpu_to_be_32(a << 24 | b << 16 | c << 8 | d);
}

static inline rte_be16_t
get_port(uint16_t port)
{
    return rte_cpu_to_be_16(port);
}

/* Fills "mbuf" with a single IPV4 packet of "size" bytes with
 * "ftuple" 5-tuple header info */
void generate_packet(struct rte_mbuf *mbuf,
                     int size,
                     struct ftuple *ftuple);

#endif
