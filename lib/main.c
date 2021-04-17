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
#include <rte_spinlock.h>

#include "config.h"
#include "common.h"
#include "packet.h"
#include "device.h"

static int lcore_tx_worker(void *arg);
static int lcore_rx_worker(void *arg);

/* Atomic messages accross cores, each a single cache line */
MESSAGE_T(bool, running);
MESSAGE_T(long, tx_counter);
MESSAGE_T(long, rx_counter);

rte_spinlock_t latency_lock;
atomic_long latency_counter;
atomic_long latency_total;

struct port_settings tx_settings;
struct port_settings rx_settings;

/* Force quit on SIGINT or SIGTERM */
static void
signal_handler(int signum)
{
    if (signum == SIGINT || signum == SIGTERM) {
        printf("Signal %d received, preparing to exit...\n", signum);
        atomic_store(&running.val, false);
    }
}

static inline uint16_t*
alloc_arg(uint16_t value)
{
    uint16_t *arg = (uint16_t*)malloc(sizeof(uint16_t));
    *arg = value;
    return arg;
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
    int i;

    /* Initialize the Environment Abstraction Layer (EAL). */
    int ret = rte_eal_init(argc, argv);
    if (ret < 0) {
        rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");
    }

    argc -= ret;
    argv += ret;

    /* Initialize signal handler */
    atomic_init(&running.val, true);
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    /* Initialize counters, locks */
    atomic_init(&tx_counter.val, 0);
    atomic_init(&rx_counter.val, 0);
    atomic_init(&latency_counter, 0);
    atomic_init(&latency_total, 0);
    rte_spinlock_init(&latency_lock);

    /* Check that there is an even number of ports to send/receive on. */
    nb_ports = rte_eth_dev_count_avail();
    if (nb_ports < 2) {
        rte_exit(EXIT_FAILURE, "Error: number of ports is not 2. "
                 "Use the EAL -a option to filter PCI addresses.\n");
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
    rx_settings.rx_descs = 4096;
    rx_settings.tx_queues = 1;
    rx_settings.tx_descs = 512;

    /* Initialize first two ports. */
    i = 0;
    RTE_ETH_FOREACH_DEV(portid) {
        if (i == 0) {
            tx_settings.port_id = portid;
            if (port_init(&tx_settings) != 0) {
                rte_exit(EXIT_FAILURE,
                         "Cannot init port %" PRIu16 "\n",
                         portid);
            }
        } else if (i == 1) {
            rx_settings.port_id = portid;
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
        if ((socket == tx_settings.socket) &&
            (tx_workers < tx_settings.tx_queues)) {
            printf ("Starting TX worker on core %d\n", lcore_id);
            rte_eal_remote_launch(lcore_tx_worker,
                                  alloc_arg(tx_workers),
                                  lcore_id);
            if (tx_workers == 0) {
                tx_settings.lcore_leader = lcore_id;
            }
            tx_workers++;
        } else if ((socket == rx_settings.socket) &&
                   (rx_workers < rx_settings.rx_queues)) {
            printf ("Starting RX worker on core %d\n", lcore_id);
            rte_eal_remote_launch(lcore_rx_worker,
                                  alloc_arg(rx_workers),
                                  lcore_id);
            if (rx_workers == 0) {
                rx_settings.lcore_leader = lcore_id;
            }
            rx_workers++;
        }
    }

    /* Am I TX or RX worker */
    if (rte_socket_id() == tx_settings.socket) {
        printf ("Starting TX worker on core %d\n", rte_lcore_id());
        lcore_tx_worker(alloc_arg(0));
    } else {
        printf ("Starting RX worker on core %d\n", rte_lcore_id());
        lcore_rx_worker(alloc_arg(0));
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
    uint16_t queue_id;
    uint16_t retval;
    uint64_t last_ns;
    double diff_ns;
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

    last_ns = get_time_ns();

    while(running.val) {

        /* Generate packet batch based on the 5-tuple */
        for (int i=0; i<PACKET_BATCH; i++) {
            generate_packet(rte_mbufs[i], PACKET_SIZE, &ftuple);
        }

        /* Send packets */
        retval = rte_eth_tx_burst(tx_settings.port_id,
                                  queue_id,
                                  rte_mbufs,
                                  PACKET_BATCH);

        /* Update TX counter */
        if (retval > 0) {
            atomic_fetch_add(&tx_counter.val, retval);
        }

        /* Leader prints to screen */
        if (core == tx_settings.lcore_leader) {
            diff_ns = get_time_ns() - last_ns;
            if (diff_ns > 1e9) {
                long counter = atomic_exchange(&tx_counter.val, 0);
                double mpps = (double)counter/1e6/(diff_ns/1e9);
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
    struct rte_mbuf *rte_mbufs[PACKET_BATCH];
    uint16_t queue_id;
    uint16_t packets;
    uint64_t last_ns, latency_ns, diff_ns;
    uint64_t timestamp;
    long diff_counter, diff_total;
    int core;
    int retval;

    queue_id = *(uint16_t*)arg;
    free(arg);
    core = rte_lcore_id();

    last_ns = get_time_ns();

    while(running.val) {

        /* Get a batch of packets */
        packets = rte_eth_rx_burst(rx_settings.port_id,
                                   queue_id,
                                   rte_mbufs,
                                   PACKET_BATCH);

        /* Update RX counter */
        if (packets > 0) {
            atomic_fetch_add(&rx_counter.val, packets);
        }

        diff_total = 0;
        diff_counter = 0;
        latency_ns = get_time_ns();

        /* Check timestamps, update latency, free memory */
        for (uint16_t i=0; i<packets; i++) {
            retval = read_packet(rte_mbufs[i], &timestamp);
            if (!retval) {
                diff_total += (latency_ns - timestamp);
                diff_counter++;
            }
            rte_pktmbuf_free(rte_mbufs[i]);
        }

        /* Update latency counters */
        if (diff_counter > 0) {
            rte_spinlock_lock(&latency_lock);
            atomic_fetch_add(&latency_total, diff_total);
            atomic_fetch_add(&latency_counter, diff_counter);
            rte_spinlock_unlock(&latency_lock);
        }

        /* Leader prints to screen */
        if (core == rx_settings.lcore_leader) {
            diff_ns = get_time_ns() - last_ns;
            if (diff_ns > 1e9) {
                long counter = atomic_exchange(&rx_counter.val, 0);
                double mpps = (double)counter/1e6/(diff_ns/1e9);

                rte_spinlock_lock(&latency_lock);
                diff_total = atomic_load(&latency_total);
                diff_counter = atomic_load(&latency_counter);
                double avg_latency_usec = (diff_counter == 0) ? 0 :
                        (double)diff_total / diff_counter / 1e3;
                rte_spinlock_unlock(&latency_lock);

                printf("RX %.3lf Mpps, avg. latency %.1lf usec\n",
                       mpps, avg_latency_usec);
                last_ns = get_time_ns();
            }
        }
    }

    return 0;
}
