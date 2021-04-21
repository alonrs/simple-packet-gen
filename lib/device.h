#ifndef _DEVICE_H_
#define _DEVICE_H_

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#include <rte_mbuf.h>
#include <rte_ether.h>

/* A single port configuration */
struct port_settings {
    struct rte_mempool **rte_mempools;
    struct rte_ether_addr mac_addr;
    uint16_t port_id;
    uint16_t rx_queues;
    uint16_t tx_queues;
    uint16_t rx_descs;
    uint16_t tx_descs;
    uint32_t socket;
};

int port_init(struct port_settings *settings);

void port_get_status(uint16_t port_id);
void port_xstats_clear(uint16_t port_id);
void port_xstats_display(uint16_t port_id, bool hide_zeros);

/* Create a mempool of "size" bytes on "socket" */
struct rte_mempool* create_mempool(int socket, int size);

#endif
