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

/* Create a mempool of "size" bytes on "socket" */
struct rte_mempool*
create_mempool(int socket, int size, int num_elements) {
    static volatile int counter = 0;
    struct rte_mempool *rte_mempool;
    char pool_name[32];
    uint32_t cache_size;

    cache_size = DEVICE_MEMPOOL_CACHE_SIZE;
    num_elements = MAX(num_elements, 2048);

    sprintf(pool_name, "mempool%d", __sync_fetch_and_add(&counter, 1));
    rte_mempool = rte_pktmbuf_pool_create(pool_name,
                                          num_elements-1,
                                          cache_size,
                                          0,
                                          size + RTE_PKTMBUF_HEADROOM,
                                          socket);
    if (rte_mempool  == NULL) {
        rte_exit(EXIT_FAILURE,
                 "Cannot create mbuf pool %s with %d elements of "
                 "%d bytes (%u elements in core cache) on socket %d. \n",
                 pool_name,
                 num_elements,
                 size,
                 cache_size,
                 socket);
    } else {
        printf("Created %s with %d elements each of %d bytes "
               "on socket %d. \n",
               pool_name, num_elements, size, socket);
    }
    return rte_mempool;
}

/* Creates a mempool for each RX queue */
static struct rte_mempool**
create_mempools(int rx_queues, int socket, int size, int descs)
{
    struct rte_mempool **rte_mempools;

    rte_mempools = malloc(sizeof(*rte_mempools) * rx_queues);
    if (!rte_mempools) {
        rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");
    }
    for (int i=0; i<rx_queues; i++) {
        rte_mempools[i] = create_mempool(socket, size, descs*2);
    }
    return rte_mempools;
}

/* Initialize port based on "port_config" */
int
port_init(struct port_settings *settings)
{
    struct rte_eth_dev_info dev_info;
    int retval;
    uint16_t q;

    if (!rte_eth_dev_is_valid_port(settings->port_id)) {
        return -1;
    }

    retval = rte_eth_dev_info_get(settings->port_id, &dev_info);
    if (retval != 0) {
        printf("Error during getting device (port %u) info: %s\n",
                settings->port_id, strerror(-retval));
        return retval;
    }

    settings->socket = rte_eth_dev_socket_id(settings->port_id);

    /* Set port configuration */
    struct rte_eth_conf port_conf = {
        .link_speeds = ETH_LINK_SPEED_AUTONEG,
        .rxmode = {
            .max_rx_pkt_len = RTE_ETHER_MAX_LEN,
            .offloads = DEV_RX_OFFLOAD_CHECKSUM
        },
    };

    if (dev_info.tx_offload_capa & DEV_TX_OFFLOAD_MBUF_FAST_FREE) {
        port_conf.txmode.offloads |= DEV_TX_OFFLOAD_MBUF_FAST_FREE;
    }

    struct rte_eth_txconf tx_conf = dev_info.default_txconf;
    tx_conf.offloads = port_conf.txmode.offloads;

    struct rte_eth_rxconf rx_conf = dev_info.default_rxconf;
    rx_conf.offloads = port_conf.rxmode.offloads;

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

    /* Allocate and set up TX queues */
    for (q = 0; q < settings->tx_queues; q++) {
        retval = rte_eth_tx_queue_setup(settings->port_id,
                                        q,
                                        settings->tx_descs,
                                        settings->socket,
                                        &tx_conf);
        if (retval < 0) {
            return retval;
        }
    }

    /* Allocate memory pools per RX queue */
    if (settings->rx_queues) {
        settings->rte_mempools = create_mempools(settings->rx_queues,
                                                 settings->socket,
                                                 DEVICE_MEMPOOL_DEF_SIZE,
                                                 settings->rx_descs*2);
    }

    /* Allocate and set up RX queues */
    for (q = 0; q < settings->rx_queues; q++) {
        retval = rte_eth_rx_queue_setup(settings->port_id,
                                        q,
                                        settings->rx_descs,
                                        settings->socket,
                                        &rx_conf,
                                        settings->rte_mempools[q]);
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

    /* Set MAC address */
    retval = rte_eth_macaddr_get(settings->port_id, &settings->mac_addr);
    if (retval < 0) {
        return retval;
    }

    /* Display port PCI and socket */
    printf("Port %hu with %hu RX queues (%hu descs) and %hu TX "
           "queus (%hu descs) initialized on socket %d \n",
           settings->port_id, settings->rx_queues, settings->rx_descs,
           settings->tx_queues, settings->tx_descs, settings->socket);

    port_get_status(settings->port_id);
    port_xstats_clear(settings->port_id);

    return 0;
}

void
port_get_status(uint16_t port_id)
{
    struct rte_eth_link link;
    int retval;

    printf("Getting port %hu status... ", port_id);
    retval = rte_eth_link_get(port_id, &link);

    if (retval) {
        printf("error \n");
        return;
    }

    const char *dp = (link.link_duplex == ETH_LINK_FULL_DUPLEX) ?
                     "full-duplex" : "half-duplex";

    printf("link %s, speed %u Mpps - %s\n",
           link.link_status ? "up" : "down",
           link.link_speed,
           dp);
}

/* Taken from testpmd - show xstats */
void
port_xstats_display(uint16_t port_id, bool hide_zeros)
{
    struct rte_eth_xstat *xstats;
    int cnt_xstats, idx_xstat;
    struct rte_eth_xstat_name *xstats_names;

    printf("###### NIC extended statistics for port %-2d\n", port_id);
    if (!rte_eth_dev_is_valid_port(port_id)) {
        printf("Error: Invalid port number %i\n", port_id);
        return;
    }

    /* Get count */
    cnt_xstats = rte_eth_xstats_get_names(port_id, NULL, 0);
    if (cnt_xstats  < 0) {
        printf("Error: Cannot get count of xstats\n");
        return;
    }

    /* Get id-name lookup table */
    xstats_names = malloc(sizeof(struct rte_eth_xstat_name) * cnt_xstats);
    if (xstats_names == NULL) {
        printf("Cannot allocate memory for xstats lookup\n");
        return;
    }
    if (cnt_xstats != rte_eth_xstats_get_names(
            port_id, xstats_names, cnt_xstats)) {
        printf("Error: Cannot get xstats lookup\n");
        free(xstats_names);
        return;
    }

    /* Get stats themselves */
    xstats = malloc(sizeof(struct rte_eth_xstat) * cnt_xstats);
    if (xstats == NULL) {
        printf("Cannot allocate memory for xstats\n");
        free(xstats_names);
        return;
    }
    if (cnt_xstats != rte_eth_xstats_get(port_id, xstats, cnt_xstats)) {
        printf("Error: Unable to get xstats\n");
        free(xstats_names);
        free(xstats);
        return;
    }

    /* Display xstats */
    for (idx_xstat = 0; idx_xstat < cnt_xstats; idx_xstat++) {
        if (hide_zeros && !xstats[idx_xstat].value)
            continue;
        printf("%s: %"PRIu64"\n",
            xstats_names[idx_xstat].name,
            xstats[idx_xstat].value);
    }
    free(xstats_names);
    free(xstats);
}

void
port_xstats_clear(uint16_t port_id)
{
	int ret;

	ret = rte_eth_xstats_reset(port_id);
	if (ret != 0) {
		printf("%s: Error: failed to reset xstats (port %u): %s",
		       __func__, port_id, strerror(-ret));
		return;
	}
}

