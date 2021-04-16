#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <string.h>
#include <signal.h>
#include <netinet/in.h>

#include <rte_ethdev.h>

#include "config.h"
#include "common.h"
#include "packet.h"
#include "device.h"

typedef __uint8_t uint8_t;
typedef __uint16_t uint16_t;
typedef __uint32_t uint32_t;
typedef __uint64_t uint64_t;

static int lcore_tx_worker(void *arg);
static int lcore_rx_worker(void *arg);

/* Common data that is shared among the cores, one cache line */
volatile static union {
    char b[64];
    struct {
        bool running;
        long tx_counter;
        long rx_counter;
    } data;
} CACHE_ALIGNED common;

struct port_settings tx_settings;
struct port_settings rx_settings;

/* Force quit on SIGINT or SIGTERM */
static void
signal_handler(int signum)
{
    if (signum == SIGINT || signum == SIGTERM) {
        printf("Signal %d received, preparing to exit...\n", signum);
        common.data.running = false;
    }
}

int
main(int argc, char *argv[])
{
    uint32_t nb_ports;
    uint32_t lcore_id;
    uint32_t socket;
    uint16_t portid;
    uint16_t tx_workers;
    uint16_t rx_workers;
    uint16_t *arg;
    int i;

    /* Initialize the Environment Abstraction Layer (EAL). */
    int ret = rte_eal_init(argc, argv);
    if (ret < 0) {
        rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");
    }

    argc -= ret;
    argv += ret;

    /* Initialize signal handler */
    common.data.running = true;
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    /* Initialize counters */
    atomic_init(&common.data.tx_counter, 0);
    atomic_init(&common.data.rx_counter, 0);

    /* Check that there is an even number of ports to send/receive on. */
    nb_ports = rte_eth_dev_count_avail();
    if (nb_ports < 2) {
        rte_exit(EXIT_FAILURE, "Error: number of ports is not 2.\n");
    } else if (nb_ports > 2) {
        printf("Warning: got more than two ports; using first two.\n");
    }

    /* Initialize port configurations - TODO, from args*/
    memset(&tx_settings, 0, sizeof(tx_settings));
    memset(&rx_settings, 0, sizeof(rx_settings));
    tx_settings.tx_queues = 4;
    tx_settings.tx_descs = 4096;
    tx_settings.rx_queues = 1;
    tx_settings.rx_descs = 512;

    rx_settings.rx_queues = 4;
    rx_settings.rx_descs = 1024;
    rx_settings.tx_queues = 1;
    rx_settings.tx_descs = 512;

    /* Initialize first two ports. */
    i = 0;
    RTE_ETH_FOREACH_DEV(portid) {
        if (i == 0) {
            tx_settings.id = portid;
            if (port_init(&tx_settings) != 0) {
                rte_exit(EXIT_FAILURE,
                         "Cannot init port %" PRIu16 "\n",
                         portid);
            }
        } else if (i == 1) {
            rx_settings.id = portid;
            if (port_init(&rx_settings) != 0) {
                rte_exit(EXIT_FAILURE,
                         "Cannot init port %" PRIu16 "\n",
                         portid);
            }
        } else {
            break;
        }
        i++;
    }

    tx_workers=0;
    rx_workers=0;

    /* Am I TX or RX worker */
    if (rte_socket_id() == tx_settings.socket) {
        tx_workers++;
        tx_settings.lcore_leader = rte_lcore_id();
    } else {
        rx_workers++;
        rx_settings.lcore_leader = rte_lcore_id();
    }

    /* Start workers on all cores */
    RTE_LCORE_FOREACH_WORKER(lcore_id) {
        socket = rte_lcore_to_socket_id(lcore_id);
        if (socket == tx_settings.socket) {
            if (tx_workers < tx_settings.tx_queues) {
                printf ("Starting TX worker on core %d\n", lcore_id);
                arg = malloc(sizeof(*arg));
                *arg = tx_workers;
                rte_eal_remote_launch(lcore_tx_worker,
                                      arg,
                                      lcore_id);
                if (tx_workers == 0) {
                    tx_settings.lcore_leader = lcore_id;
                }
                tx_workers++;
            }
        } else if (socket == rx_settings.socket) {
            if (rx_workers < rx_settings.rx_queues) {
                printf ("Starting RX worker on core %d\n", lcore_id);
                arg = malloc(sizeof(*arg));
                *arg = rx_workers;
                rte_eal_remote_launch(lcore_rx_worker,
                                      arg,
                                      lcore_id);
                if (rx_workers == 0) {
                    rx_settings.lcore_leader = lcore_id;
                }
                rx_workers++;
            }
        } else {
            printf ("Core %d is niether in RX or TX sockets \n", lcore_id);
        }
    }

    /* Am I TX or RX worker */
    
    arg = malloc(sizeof(*arg));
    *arg = 0;

    if (rte_socket_id() == tx_settings.socket) {
        printf ("Starting TX worker on core %d\n", rte_lcore_id());
        lcore_tx_worker(arg);
    } else {
        printf ("Starting RX worker on core %d\n", rte_lcore_id());
        lcore_rx_worker(arg);
    }

    return 0;
}

/* Main TX worker */
static int
lcore_tx_worker(void *arg)
{
    struct rte_mempool *rte_mempool;
    struct rte_mbuf *rte_mbufs[PACKET_BATCH];
    struct ftuple ftuple;
//    uint32_t tx_counter;
    uint16_t queue_id;
    uint16_t retval;
    long last_ns, diff_ns;
    int socket, core;

    queue_id = *(uint16_t*)arg;
    free(arg);
    socket = rte_socket_id();
    core = rte_lcore_id();

    /* Allocate memory */
    rte_mempool = create_mempool(socket, DEVICE_MEMPOOL_TX_ELEMENTS);
    retval = rte_pktmbuf_alloc_bulk(rte_mempool, rte_mbufs, PACKET_BATCH);
    if (retval) {
        rte_exit(EXIT_FAILURE, "Failed to allocate mbuf \n");
    }

    /* Dummy 5-tuple */
    ftuple.ip_proto = IPPROTO_TCP;
    ftuple.src_ip = get_ip_address(192,168,0,1);
    ftuple.dst_ip = get_ip_address(192,168,0,10);
    ftuple.src_port = get_port(100);
    ftuple.dst_port = get_port(80);

//    tx_counter = 0;
    last_ns = get_time_ns();

    while(common.data.running) {

        /* Generate packet batch based on the 5-tuple */
        for (int i=0; i<PACKET_BATCH; i++) {
            generate_packet(rte_mbufs[i], PACKET_SIZE, &ftuple);
        }

        /* Send packets */
        retval = rte_eth_tx_burst(tx_settings.id,
                                  queue_id,
                                  rte_mbufs,
                                  PACKET_BATCH);

        /* Update counter */
        atomic_fetch_add(&common.data.tx_counter, retval);

        /* Leader prints to screen */
        if (core == tx_settings.lcore_leader) {
            diff_ns = get_time_ns() - last_ns;
            if (diff_ns > 1e9) {
                long counter = atomic_exchange(&common.data.tx_counter, 0);
                double mpps = (double)counter/1e6;
                printf("TX %.3lf Mpps\n", mpps);
                last_ns = get_time_ns();
            }
        }
    }

    return 0;
}

/* Main RX worker */
static int
lcore_rx_worker(void *arg)
{
    return 0;
}
