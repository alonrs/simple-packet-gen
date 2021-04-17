#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <inttypes.h>
#include <signal.h>

#include <rte_byteorder.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_tcp.h>

#include "config.h"
#include "common.h"
#include "device.h"

static const struct rte_eth_conf port_conf_default = {
    .link_speeds = ETH_LINK_SPEED_AUTONEG,
    .rxmode = {
        .max_rx_pkt_len = RTE_ETHER_MAX_LEN
    }
};

/* Create a mempool of "size" bytes on "socket" */
struct rte_mempool*
create_mempool(int socket, int size) {
    static volatile int counter = 0;
    struct rte_mempool *rte_mempool;
    char pool_name[32];

    sprintf(pool_name, "mempool-%d", __sync_fetch_and_add(&counter, 1));
    rte_mempool = rte_pktmbuf_pool_create(pool_name,
                                          DEVICE_MEMPOOL_RX_ELEMENTS,
                                          DEVICE_MEMPOOL_CACHE_SIZE,
                                          0,
                                          size + RTE_PKTMBUF_HEADROOM,
                                          socket);
    if (rte_mempool  == NULL) {
        rte_exit(EXIT_FAILURE, "Cannot create mbuf pool %s\n", pool_name);
    }
    return rte_mempool;
}

/* Creates a mempool for each RX queue */
static struct rte_mempool**
create_mempools(int rx_queues, int socket)
{
    struct rte_mempool **rte_mempools;

    rte_mempools = malloc(sizeof(*rte_mempools) * rx_queues);
    if (!rte_mempools) {
        rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");
    }
    for (int i=0; i<rx_queues; i++) {
        rte_mempools[i] = create_mempool(socket, RTE_MBUF_DEFAULT_DATAROOM);
    }
    return rte_mempools;
}

/* Initialize port based on "port_config" */
int
port_init(struct port_settings *settings)
{
    struct rte_eth_dev_info dev_info;
    struct rte_eth_conf port_conf;
    int retval;
    uint16_t q;

    port_conf = port_conf_default;
    struct rte_eth_txconf txconf;

    if (!rte_eth_dev_is_valid_port(settings->port_id)) {
        return -1;
    }

    retval = rte_eth_dev_info_get(settings->port_id, &dev_info);
    if (retval != 0) {
        printf("Error during getting device (port %u) info: %s\n",
                settings->port_id, strerror(-retval));
        return retval;
    }

    if (dev_info.tx_offload_capa & DEV_TX_OFFLOAD_MBUF_FAST_FREE) {
        port_conf.txmode.offloads |= DEV_TX_OFFLOAD_MBUF_FAST_FREE;
    }

    settings->socket = rte_eth_dev_socket_id(settings->port_id);

    /* Configure the Ethernet device. */
    retval = rte_eth_dev_configure(settings->port_id,
                                   settings->rx_queues,
                                   settings->tx_queues,
                                   &port_conf);
    if (retval != 0) {
        return retval;
    }

    retval = rte_eth_dev_adjust_nb_rx_tx_desc(settings->port_id,
                                              &settings->rx_descs,
                                              &settings->tx_descs);
    if (retval != 0) {
        return retval;
    }

    /* Allocate memory pools per RX queue */
    if (settings->rx_queues) {
        settings->rte_mempools = create_mempools(settings->rx_queues,
                                                 settings->socket);
    }

    /* Allocate and set up RX queues */
    for (q = 0; q < settings->rx_queues; q++) {
        retval = rte_eth_rx_queue_setup(settings->port_id,
                                        q,
                                        settings->rx_descs,
                                        settings->socket,
                                        NULL,
                                        settings->rte_mempools[q]);
        if (retval < 0) {
            return retval;
        }
    }

    txconf = dev_info.default_txconf;
    txconf.offloads = port_conf.txmode.offloads;

    /* Allocate and set up TX queues */
    for (q = 0; q < settings->tx_queues; q++) {
        retval = rte_eth_tx_queue_setup(settings->port_id,
                                        q,
                                        settings->tx_descs,
                                        settings->socket,
                                        &txconf);
        if (retval < 0) {
            return retval;
        }
    }

    /* Start the Ethernet port. */
    retval = rte_eth_dev_start(settings->port_id);
    if (retval < 0) {
        return retval;
    }

    /* Enable RX in promiscuous mode for the Ethernet device. */
    retval = rte_eth_promiscuous_enable(settings->port_id);
    if (retval != 0) {
        return retval;
    }

    /* Display port PCI and socket */
    printf("Port %hu with %hu RX queues (%hu descs) and %hu TX "
           "queus (%hu descs) initialized on socket %d \n",
           settings->port_id, settings->rx_queues, settings->rx_descs,
           settings->tx_queues, settings->tx_descs, settings->socket);

    return 0;
}
