#include <stdint.h>
#include <rte_byteorder.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <rte_icmp.h>
#include <netinet/in.h>

#include "config.h"
#include "common.h"
#include "packet.h"
#include "hash.h"

#define IPVERSION 4

/* How to compute checksums in here:
 * https://gist.github.com/david-hoze/0c7021434796997a4ca42d7731a7073a */
static uint16_t compute_checksum(uint16_t *addr, uint32_t count);
static void compute_ip_checksum(struct rte_ipv4_hdr *ipv4_hdr);
static void compute_tcp_checksum(struct rte_ipv4_hdr *ipv4_hdr);
static void compute_udp_checksum(struct rte_ipv4_hdr *ipv4_hdr);
static void compute_icmp_checksum(struct rte_ipv4_hdr *ipv4_hdr);

/* Fills "mbuf" with a single IPV4 packet of "size" bytes with
 * "ftuple" 5-tuple header info */
void
generate_ftuple_packet(struct rte_mbuf *mbuf,
                       struct rte_ether_addr *src_mac,
                       struct rte_ether_addr *dst_mac,
                       int size,
                       struct ftuple *ftuple)
{
    struct rte_ether_hdr *ether_hdr;
    struct rte_ipv4_hdr *ipv4_hdr;
    char *payload;
    int header_size;
    int payload_size;

    ether_hdr = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr*);
    ipv4_hdr = rte_pktmbuf_mtod_offset(mbuf,
                                       struct rte_ipv4_hdr *,
                                       sizeof(*ether_hdr));
    header_size = sizeof(*ether_hdr) + sizeof(*ipv4_hdr);

    /* Ethernet src & dst, type is IPv4 */
    memcpy(&ether_hdr->s_addr, src_mac, sizeof(*src_mac));
    memcpy(&ether_hdr->d_addr, dst_mac, sizeof(*dst_mac));
    ether_hdr->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);

    /* Do we work with TCP? */
    if (ftuple->ip_proto == IPPROTO_TCP) {
        struct rte_tcp_hdr *tcp_hdr;
        tcp_hdr = rte_pktmbuf_mtod_offset(mbuf,
                                          struct rte_tcp_hdr *,
                                          sizeof(*ether_hdr) +
                                          sizeof(*ipv4_hdr));
        header_size += sizeof(*tcp_hdr);
        mbuf->l4_len = sizeof(*tcp_hdr);
        tcp_hdr->src_port = ftuple->src_port;
        tcp_hdr->dst_port = ftuple->dst_port;
        tcp_hdr->sent_seq = 0; /* No sequence number */
        tcp_hdr->recv_ack = 0; /* No ack number */
        tcp_hdr->data_off = sizeof(*tcp_hdr) / 4; /* 20 Bytes header size */
        tcp_hdr->tcp_flags = RTE_TCP_SYN_FLAG; /* Flag is always SYN */
        tcp_hdr->rx_win = rte_cpu_to_be_16(PACKET_TCP_WINSIZE);/* Window size */
        tcp_hdr->cksum = 0; /* Will be calculated next */
        tcp_hdr->tcp_urp = 0; /* No urgent number */
    } else if (ftuple->ip_proto == IPPROTO_UDP) {
        struct rte_udp_hdr *udp_hdr;
        udp_hdr = rte_pktmbuf_mtod_offset(mbuf,
                                          struct rte_udp_hdr *,
                                          sizeof(*ether_hdr) +
                                          sizeof(*ipv4_hdr));
        header_size += sizeof(*udp_hdr);
        mbuf->l4_len = sizeof(*udp_hdr);
        udp_hdr->src_port = ftuple->src_port;
        udp_hdr->dst_port = ftuple->dst_port;
        udp_hdr->dgram_len = rte_cpu_to_be_16(size - header_size +
                                              sizeof(*udp_hdr));
        udp_hdr->dgram_cksum = 0; /* Will be calculated next */
    } else if (ftuple->ip_proto == IPPROTO_ICMP) {
        struct rte_icmp_hdr *icmp_hdr;
        icmp_hdr = rte_pktmbuf_mtod_offset(mbuf,
                                          struct rte_icmp_hdr *,
                                          sizeof(*ether_hdr) +
                                          sizeof(*ipv4_hdr));
        header_size += sizeof(*icmp_hdr);
        mbuf->l4_len = sizeof(*icmp_hdr);
        icmp_hdr->icmp_type = 8;  /* Echo (ping) */
        icmp_hdr->icmp_code = 0;  /* N/A */
        icmp_hdr->icmp_cksum = 0; /* Calculated later */
        icmp_hdr->icmp_ident = 0;
        icmp_hdr->icmp_seq_nb = 0;
    } else {
        printf("Error: generate_packet does not support protocol %d\n",
               ftuple->ip_proto);
    }

    /* Set IPv4 header */
    ipv4_hdr->version_ihl = IPVERSION << 4 |
                           sizeof(*ipv4_hdr) / RTE_IPV4_IHL_MULTIPLIER;
    ipv4_hdr->type_of_service = 0;  /* DSCP:0(best effort),
                                     * ECN:0(not using ECN) */
    ipv4_hdr->total_length = rte_cpu_to_be_16(size - sizeof(*ether_hdr));
    ipv4_hdr->packet_id = rte_cpu_to_be_16(1); /* Packet is not fragmented;
                                     * ID has no meaningful value
                                     * (RFC6864, sec 4.1) */
    ipv4_hdr->fragment_offset = 0;  /* Flags: don't fragment.
                                     * Always first packet in flow. */
    ipv4_hdr->time_to_live = PACKET_TTL;
    ipv4_hdr->next_proto_id = ftuple->ip_proto;
    ipv4_hdr->hdr_checksum = 0;     /* Will be calculated next */
    ipv4_hdr->src_addr = ftuple->src_ip;
    ipv4_hdr->dst_addr = ftuple->dst_ip;

    compute_ip_checksum(ipv4_hdr);

    /* Set the payload (8 bytes of timestamp + 2 bytes hash) */
    payload = rte_pktmbuf_mtod_offset(mbuf,
                                      char *,
                                      header_size);
    payload_size = size - header_size;
    if (payload_size - sizeof(uint64_t) - sizeof(uint16_t) < 0) {
        printf("Error: generate_packet of size %d does not have enough "
               "space for payload data. \n", size);
    } else {
        uint64_t timestamp = get_time_ns();
        uint16_t hash = hash_uint64(timestamp) & 0xFFFF;
        memcpy(payload, (char*)&timestamp, sizeof(uint64_t));
        payload+=sizeof(uint64_t);
        payload_size-=sizeof(uint64_t);
        memcpy(payload, (char*)&hash, sizeof(uint16_t));
        payload+=sizeof(uint16_t);
        payload_size-=sizeof(uint16_t);
        /* Pad the rest of the payload with zeros */
        memset(payload, 0, payload_size);
    }

    /* Calculate checksums */
    if (ftuple->ip_proto == IPPROTO_TCP) {
        compute_tcp_checksum(ipv4_hdr);
    } else if (ftuple->ip_proto == IPPROTO_UDP) {
        compute_udp_checksum(ipv4_hdr);
    } else if (ftuple->ip_proto == IPPROTO_ICMP) {
        compute_icmp_checksum(ipv4_hdr);
    }

    mbuf->l2_len = sizeof(*ether_hdr);
    mbuf->l3_len = sizeof(*ipv4_hdr);
    mbuf->data_len = size;
    mbuf->pkt_len = size;
}

/* Reads a single packet from "mbuf", returns its timestamp into "timestamp".
 * Returns 0 on valid packet. */
int
read_packet(struct rte_mbuf *mbuf, uint64_t *timestamp)
{
    struct rte_ipv4_hdr *ipv4_hdr;
    int header_size;
    char *payload;

    header_size = sizeof(struct rte_ether_hdr);
    ipv4_hdr = rte_pktmbuf_mtod_offset(mbuf,
                                       struct rte_ipv4_hdr *,
                                       header_size);
    header_size += sizeof(struct rte_ipv4_hdr);

    /* Read L4 header */
    if (ipv4_hdr->next_proto_id == IPPROTO_TCP) {
        header_size += sizeof(struct rte_tcp_hdr);
    } else if (ipv4_hdr->next_proto_id == IPPROTO_UDP) {
        header_size += sizeof(struct rte_udp_hdr);
    } else if (ipv4_hdr->next_proto_id == IPPROTO_ICMP) {
        header_size += sizeof(struct rte_icmp_hdr);
    } else {
        /* Cannot read - unknown IP protocol */
        return READ_ERROR_UNSUPPORTED_PROTOCOL;
    }

    payload = rte_pktmbuf_mtod_offset(mbuf, char*, header_size);

    /* Read timestamp and hash */
    uint64_t ts = *(uint64_t*)payload;
    payload += sizeof(uint64_t);
    uint16_t hash = *(uint16_t*)payload;
    uint16_t check = hash_uint64(ts) & 0xFFFF;

    /* Check hash correcentss */
    if (hash != check) {
        /* Invalid packet! */
        return READ_ERROR_HASH;
    }

    if (timestamp) {
        *timestamp = ts;
    }

    return 0;
}

/* Compute checksum for count bytes starting at addr,
 * using one's complement of one's complement sum */
static uint16_t
compute_checksum(uint16_t *addr, uint32_t count)
{
    register unsigned long sum = 0;
    while (count > 1) {
        sum += * addr++;
        count -= 2;
    }
    /* if any bytes left, pad the bytes and add */
    if(count > 0) {
        sum += ((*addr)&rte_cpu_to_be_16(0xFF00));
    }
    /* Fold sum to 16 bits: add carrier to result */
    while (sum>>16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    /* one's complement */
    sum = ~sum;
    return ((uint16_t)sum);
}

/* Set ip checksum of a given ip header*/
static void
compute_ip_checksum(struct rte_ipv4_hdr *ipv4_hdr)
{
    ipv4_hdr->hdr_checksum = 0;
    ipv4_hdr->hdr_checksum = compute_checksum((uint16_t*)ipv4_hdr,
                             sizeof(*ipv4_hdr) / RTE_IPV4_IHL_MULTIPLIER);
}

/* Set tcp checksum: given IP header */
static void
compute_tcp_checksum(struct rte_ipv4_hdr *ipv4_hdr)
{
    uint16_t *ip_payload;
    register unsigned long sum;
    uint16_t tcp_size;
    struct rte_tcp_hdr *tcp_hdr;

    ip_payload = (uint16_t*)ipv4_hdr + sizeof(*ipv4_hdr);
    sum = 0;
    tcp_size = rte_be_to_cpu_16(ipv4_hdr->total_length) -
               sizeof(*ipv4_hdr) / RTE_IPV4_IHL_MULTIPLIER;
    tcp_hdr = (struct rte_tcp_hdr*)ip_payload;

    /* add the pseudo header  */
    /* the source ip */
    sum += (ipv4_hdr->src_addr>>16)&0xFFFF;
    sum += (ipv4_hdr->src_addr)&0xFFFF;
    /* the dest ip */
    sum += (ipv4_hdr->dst_addr>>16)&0xFFFF;
    sum += (ipv4_hdr->dst_addr)&0xFFFF;
    /* protocol and reserved: 6 */
    sum += rte_cpu_to_be_16(IPPROTO_TCP);
    /* the length */
    sum += rte_cpu_to_be_16(tcp_size);

    /* add the IP payload */
    /* initialize checksum to 0 */
    tcp_hdr->cksum = 0;
    while (tcp_size > 1) {
        sum += * ip_payload++;
        tcp_size -= 2;
    }
    /* if any bytes left, pad the bytes and add */
    if(tcp_size > 0) {
        /* printf("+++++++++++padding, %dn", tcp_size); */
        sum += ((*ip_payload)&rte_cpu_to_be_16(0xFF00));
    }
      /* Fold 32-bit sum to 16 bits: add carrier to result */
      while (sum>>16) {
          sum = (sum & 0xffff) + (sum >> 16);
      }
      sum = ~sum;
    /* set computation result */
    tcp_hdr->cksum = (uint16_t)sum;
}

/* set tcp checksum: given IP header */
static void
compute_udp_checksum(struct rte_ipv4_hdr *ipv4_hdr)
{
    register unsigned long sum;
    struct rte_udp_hdr *udp_hdr;
    uint16_t udp_size;
    uint16_t *ip_payload;

    ip_payload = (uint16_t*)ipv4_hdr + sizeof(*ipv4_hdr);
    udp_hdr = (struct rte_udp_hdr*)(ip_payload);
    udp_size = rte_cpu_to_be_16(udp_hdr->dgram_len);
    sum = 0;

    sum += (ipv4_hdr->src_addr>>16)&0xFFFF;
    sum += (ipv4_hdr->src_addr)&0xFFFF;
    sum += (ipv4_hdr->dst_addr>>16)&0xFFFF;
    sum += (ipv4_hdr->dst_addr)&0xFFFF;
    sum += rte_cpu_to_be_16(IPPROTO_UDP);
    sum += udp_hdr->dgram_len;

    udp_hdr->dgram_cksum = 0;
    while (udp_size > 1) {
        sum += * ip_payload++;
        udp_size -= 2;
    }
    /* if any bytes left, pad the bytes and add */
    if(udp_size > 0) {
        sum += ((*ip_payload)&rte_cpu_to_be_16(0xFF00));
    }
    /* Fold sum to 16 bits: add carrier to result */
    while (sum>>16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum = ~sum;
    /* set computation result */
    udp_hdr->dgram_cksum = ((uint16_t)sum == 0x0000) ? 0xFFFF
                           : (uint16_t)sum;
}

static void
compute_icmp_checksum(struct rte_ipv4_hdr *ipv4_hdr)
{
    uint16_t *ip_payload;
    register unsigned long sum;
    struct rte_icmp_hdr *icmp_hdr;
    uint16_t len;

    ip_payload = (uint16_t*)ipv4_hdr + sizeof(*ipv4_hdr);
    icmp_hdr = (struct rte_icmp_hdr*)(ip_payload);
    len = rte_be_to_cpu_16(ipv4_hdr->total_length) -
          sizeof(*ipv4_hdr) / RTE_IPV4_IHL_MULTIPLIER;
    sum = 0;

    /* Initiate to 0 */
    icmp_hdr->icmp_cksum = 0;
    while (len > 1) {
      sum += * ip_payload++;
      len -= 2;
    }

    /* if any bytes left, pad the bytes and add */
    if(len > 0) {
        sum += ((*ip_payload)&rte_cpu_to_be_16(0xFF00));
    }
    /* Fold 32-bit sum to 16 bits: add carrier to result */
    while (sum>>16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum = ~sum;
    /* set computation result */
    icmp_hdr->icmp_cksum = (uint16_t)sum;
}
