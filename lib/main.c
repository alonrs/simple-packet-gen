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
#include "arguments.h"
#include "vector.h"
#include "packet.h"
#include "device.h"
#include "generator.h"

static int lcore_tx_worker(void *arg);
static int lcore_rx_worker(void *arg);

enum { MAX_EAL_ARGS = 64 };

/* Passed to worker threads */
struct worker_settings {
    generator_policy_func_t generator; /* Packet generator */
    void *args;                        /* Generator custom arguments */
    bool collect_latency_stats;
    uint16_t tx_leader_core_id;
    uint16_t rx_leader_core_id;
    uint16_t queue_index;
    uint16_t tx_queue_num;
    uint16_t rx_queue_num;
    int time_limit;
};

/* Application arguments and help.
 * Format: name, required, is-boolean, default, help */
static struct arguments app_args[] = {
/* Name           R  B  Def     Help */
{"tx",            1, 0, "0",    "TX port number."},
{"rx" ,           1, 0, "0",    "RX port number."},
{"eal",           0, 0, "",     "DPDK EAL arguments."},
{"txq",           0, 0, "4",    "Number of TX queues."},
{"rxq",           0, 0, "4",    "Number of RX queues."},
{"tx-descs",      0, 0, "256",  "Number of TX descs."},
{"rx-descs",      0, 0, "256",  "Number of RX descs."},
{"lat-file",      0, 0, NULL,   "Out filename for latency per packet values."},
{"time-limit",    0, 0, NULL,   "Stop application after VALUE seconds"},
{"xstats",        0, 1, NULL,   "Show port xstats at the end."},
{"hide-zeros",    0, 1, NULL,   "(xstats) Hide zero values."},
{"superspreader", 0, 1, NULL,   "(Policy) Generate packets using a "
                                "superspreader policy, continuously "
                                "increaseing dst IP and dst port."},
{"nflows",        0, 0, "100",  "(Policy:superspreader) Number of unique "
                                "flows for the superspreader policy."},
{NULL,            0, 0, NULL,   "Simple DPDK client."}
};

/* Atomic messages accross cores, each a single cache line */
MESSAGE_T(bool, running);
MESSAGE_T(long, tx_counter);
MESSAGE_T(long, rx_counter);
MESSAGE_T(long, rx_err_counter);

rte_spinlock_t latency_lock;
atomic_long latency_counter;
atomic_long latency_total;
static struct vector *latency_vector;

static struct port_settings tx_settings;
static struct port_settings rx_settings;
static struct worker_settings worker_settings;

/* Force quit on SIGINT or SIGTERM */
static void
signal_handler(int signum)
{
    if (signum == SIGINT || signum == SIGTERM) {
        printf("Signal %d received, preparing to exit...\n", signum);
        atomic_store(&running.val, false);
    }
}

/* Parse application arguments */
static void
initialize_settings()
{
    /* Initialize port settings */
    memset(&tx_settings, 0, sizeof(tx_settings));
    memset(&rx_settings, 0, sizeof(rx_settings));
    tx_settings.port_id = ARG_INTEGER(app_args, "tx", 0);
    tx_settings.tx_queues = ARG_INTEGER(app_args, "txq", 4);
    tx_settings.tx_descs = ARG_INTEGER(app_args, "tx-descs", 256);
    tx_settings.rx_queues = 1;
    tx_settings.rx_descs = 64;
    rx_settings.port_id = ARG_INTEGER(app_args, "rx", 1);
    rx_settings.rx_queues = ARG_INTEGER(app_args, "rxq", 4);
    rx_settings.rx_descs = ARG_INTEGER(app_args, "rx-descs", 256);
    rx_settings.tx_queues = 1;
    rx_settings.tx_descs = 64;
    worker_settings.tx_queue_num = tx_settings.tx_queues;
    worker_settings.rx_queue_num = rx_settings.rx_queues;
    worker_settings.collect_latency_stats = ARG_BOOL(app_args, "lat-file", 0);
    worker_settings.time_limit = ARG_INTEGER(app_args, "time-limit", 0);

    /* Set generator policy */
    policy_t policy = POLICY_UNDEFINED;
    if (ARG_BOOL(app_args, "superspreader", 0)) {
        policy = POLICY_SUPERSPREADER;
    }

    if (policy == POLICY_UNDEFINED) {
        printf("Packet generation policy was not given. Using default. \n");
    }

    switch (policy) {
    case POLICY_SUPERSPREADER:
    default:
    {
        uint32_t nflows = ARG_INTEGER(app_args, "nflows", 100);
        printf("Using superspreader policy with %u flows. \n", nflows);
        worker_settings.generator = generator_policy_superspreader;
        worker_settings.args = alloc_void_arg_uint32_t(nflows);
    }}
}

/* Initialzie DPDK from EAL arguments */
static void
initialize_dpdk()
{
    const char *args;
    char *args_mod;
    char *argv[MAX_EAL_ARGS];
    char *cur;
    int argc;

    args = ARG_STRING(app_args, "eal", "");
    args_mod = xmalloc(sizeof(char)*(strlen(args)+1));

    strcpy(args_mod, args);
    argc = 1;
    argv[0] = "";
    cur = strtok(args_mod, " ");

    while (cur && argc < MAX_EAL_ARGS-1) {
        argv[argc++] = cur;
        cur = strtok(0, " ");
    }

    /* Print EAL arguments */
    printf("EAL arguments: ");
    for (int i=1; i<argc; i++) {
        printf("[%s] ", argv[i]);
    }
    printf("\n");

    /* Initialize the Environment Abstraction Layer (EAL). */
    int ret = rte_eal_init(argc, argv);
    if (ret < 0) {
        rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");
    }

    free(args_mod);
}

/* Save latency file */
static void
save_latency_file()
{
    const char *filename;
    FILE *file;

    filename = ARG_STRING(app_args, "lat-file", NULL);
    if (!filename) {
        return;
    }

    file = fopen(filename, "w");
    if (!file) {
        printf("Error: cannot open \"%s\" for writing. \n", filename);
        return;
    }

    printf("Saving %lu collected latency items in \"%s\"... \n",
           vector_size(latency_vector), filename);

    /* For each value in latency vector */
    uint64_t val;
    VECTOR_FOR_EACH(latency_vector, val, uint64_t) {
        fprintf(file, "%lu\n", val);
    }

    fclose(file);
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

    /* Parse application argumnets, initialize */
    arg_parse(argc, argv, app_args);
    initialize_settings(argc, argv);
    initialize_dpdk();

    /* Initialize signal handler */
    atomic_init(&running.val, true);
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    /* Initialize counters, locks */
    atomic_init(&tx_counter.val, 0);
    atomic_init(&rx_counter.val, 0);
    atomic_init(&rx_err_counter.val, 0);
    atomic_init(&latency_counter, 0);
    atomic_init(&latency_total, 0);
    rte_spinlock_init(&latency_lock);
    latency_vector = vector_init(sizeof(struct vector*));

    /* Check that there is an even number of ports to send/receive on. */
    nb_ports = rte_eth_dev_count_avail();
    if (nb_ports < 2) {
        rte_exit(EXIT_FAILURE, "Error: number of ports is not 2. "
                 "Use the EAL -a option to filter PCI addresses.\n");
    } else if (nb_ports > 2) {
        printf("Warning: got more than two ports; using first two.\n");
    }

    /* Initialize ports */
    if (port_init(&tx_settings)) {
        rte_exit(EXIT_FAILURE,
                 "Cannot init port %" PRIu16 "\n",
                 tx_settings.port_id);
    }
    if (port_init(&rx_settings)) {
        rte_exit(EXIT_FAILURE,
                 "Cannot init port %" PRIu16 "\n",
                 rx_settings.port_id);
    }

    tx_workers=0;
    rx_workers=0;

    /* Am I TX or RX worker */
    if (rte_socket_id() == tx_settings.socket) {
        tx_workers++;
        worker_settings.tx_leader_core_id = rte_lcore_id();
    } else {
        rx_workers++;
        worker_settings.rx_leader_core_id = rte_lcore_id();
    }

    /* Start workers on all cores */
    RTE_LCORE_FOREACH_SLAVE(lcore_id) {
        socket = rte_lcore_to_socket_id(lcore_id);
        if ((socket == tx_settings.socket) &&
            (tx_workers < tx_settings.tx_queues)) {
            printf ("Starting TX worker on core %d\n", lcore_id);
            if (tx_workers == 0) {
                worker_settings.tx_leader_core_id = lcore_id;
            }
            worker_settings.queue_index = tx_workers;
            rte_eal_remote_launch(lcore_tx_worker,
                                  alloc_void_arg_bytes(&worker_settings,
                                                       sizeof(worker_settings)),
                                  lcore_id);
            tx_workers++;
        } else if ((socket == rx_settings.socket) &&
                   (rx_workers < rx_settings.rx_queues)) {
            printf ("Starting RX worker on core %d\n", lcore_id);
            if (rx_workers == 0) {
                worker_settings.rx_leader_core_id = lcore_id;
            }
            worker_settings.queue_index = rx_workers;
            rte_eal_remote_launch(lcore_rx_worker,
                                  alloc_void_arg_bytes(&worker_settings,
                                                       sizeof(worker_settings)),
                                  lcore_id);
            rx_workers++;
        }
    }

    /* Am I TX or RX worker */
    worker_settings.queue_index = 0;
    if (rte_socket_id() == tx_settings.socket) {
        printf ("Starting TX worker on core %d\n", rte_lcore_id());
        lcore_tx_worker(alloc_void_arg_bytes(&worker_settings,
                                             sizeof(worker_settings)));
    } else {
        printf ("Starting RX worker on core %d\n", rte_lcore_id());
        lcore_rx_worker(alloc_void_arg_bytes(&worker_settings,
                                             sizeof(worker_settings)));
    }

    /* Wait for all cores. Will get here only after signal. */
    RTE_LCORE_FOREACH_SLAVE(lcore_id) {
        rte_eal_wait_lcore(lcore_id);
    }

    /* Show xstats */
    bool xstats = ARG_BOOL(app_args, "xstats", false);
    bool hide_zeros = ARG_BOOL(app_args, "hide-zeros", false);
    if (xstats) {
        port_xstats_display(tx_settings.port_id, hide_zeros);
        port_xstats_display(rx_settings.port_id, hide_zeros);
    }

    /* Save latency file */
    save_latency_file();

    return 0;
}

/* Main TX worker */
static int
lcore_tx_worker(void *arg)
{
    struct worker_settings worker_settings;
    struct rte_mempool *rte_mempool;
    struct rte_mbuf *rte_mbufs[BATCH_SIZE];
    struct ftuple ftuple;
    uint16_t retval;
    uint64_t last_ns;
    uint64_t pkt_counter;
    double diff_ns;
    int socket, core;
    int secs;

    get_void_arg_bytes(&worker_settings,
                       arg,
                       sizeof(worker_settings),
                       true);
    socket = rte_socket_id();
    core = rte_lcore_id();
    pkt_counter = 0;
    secs = 0;
    last_ns = get_time_ns();

    /* Allocate memory */
    rte_mempool = create_mempool(socket,
                                 DEVICE_MEMPOOL_DEF_SIZE,
                                 tx_settings.tx_descs*2);
    retval = rte_pktmbuf_alloc_bulk(rte_mempool, rte_mbufs, BATCH_SIZE);
    if (retval) {
        rte_exit(EXIT_FAILURE, "Failed to allocate mbuf \n");
    }

    while(running.val) {

        /* Generate packet batch based on the 5-tuple */
        for (int i=0; i<BATCH_SIZE; i++) {
            worker_settings.generator(pkt_counter,
                                      worker_settings.queue_index,
                                      worker_settings.tx_queue_num,
                                      &ftuple,
                                      worker_settings.args);
            generate_ftuple_packet(rte_mbufs[i],
                                   &tx_settings.mac_addr,
                                   &rx_settings.mac_addr,
                                   PACKET_SIZE,
                                   &ftuple,
                                   (worker_settings.queue_index==0) &&
                                   DEBUG_PRINT_PACKETS);
            pkt_counter++;
        }

        /* Send packets */
        retval = rte_eth_tx_burst(tx_settings.port_id,
                                  worker_settings.queue_index,
                                  rte_mbufs,
                                  BATCH_SIZE);

        /* Update TX counter */
        if (retval > 0) {
            atomic_fetch_add(&tx_counter.val, retval);
        }

        /* Leader prints to screen */
        if (core == worker_settings.tx_leader_core_id) {
            diff_ns = get_time_ns() - last_ns;
            if (diff_ns > 1e9) {
                long counter = atomic_exchange(&tx_counter.val, 0);
                double mpps = (double)counter/1e6/(diff_ns/1e9);
                printf("TX %.4lf Mpps\n", mpps);
                last_ns = get_time_ns();
                secs++;
                /* Time limit */
                if (worker_settings.time_limit &&
                    secs >= worker_settings.time_limit) {
                    printf("Time limit have reached \n");
                    atomic_store(&running.val, false);
                }
            }
        }
    }

    return 0;
}

/* Main RX worker */
static int
lcore_rx_worker(void *arg)
{
    struct rte_mbuf *rte_mbufs[BATCH_SIZE];
    struct worker_settings worker_settings;
    uint64_t last_ns, current_ns, diff_ns;
    uint64_t latency_ns, timestamp;
    long diff_counter, diff_total;
    long counter, err_counter;
    struct vector *local_vector;
    uint16_t packets;
    int core;
    int retval;

    get_void_arg_bytes(&worker_settings,
                       arg,
                       sizeof(worker_settings),
                       true);
    core = rte_lcore_id();
    last_ns = get_time_ns();

    /* Local vector for latency values */
    local_vector = vector_init(sizeof(uint64_t));

    while(running.val) {

        /* Get a batch of packets */
        packets = rte_eth_rx_burst(rx_settings.port_id,
                                   worker_settings.queue_index,
                                   rte_mbufs,
                                   BATCH_SIZE);

        diff_total = 0;
        diff_counter = 0;
        err_counter = 0;
        current_ns = get_time_ns();

        /* Check timestamps, update latency, free memory */
        for (uint16_t i=0; i<packets; i++) {
            retval = read_packet(rte_mbufs[i], &timestamp);
            rte_pktmbuf_free(rte_mbufs[i]);
            if (retval) {
                err_counter++;
                continue;
            }
            /* Update local stats */
            latency_ns = current_ns - timestamp;
            diff_total += latency_ns;
            diff_counter++;
            /* Update local vector every LATENCY_COLLECTOR_GAP packets */
            if(worker_settings.collect_latency_stats &&
              (i%LATENCY_COLLECTOR_GAP==0)) {
                vector_push(local_vector, &latency_ns);
            }
        }

        /* Update RX counters */
        if (packets > 0) {
           atomic_fetch_add(&rx_counter.val, packets);
        }
        if (err_counter > 0) {
            atomic_fetch_add(&rx_err_counter.val, err_counter);
        }

        /* Update latency counters */
        if (diff_counter > 0) {
            rte_spinlock_lock(&latency_lock);
            atomic_fetch_add(&latency_total, diff_total);
            atomic_fetch_add(&latency_counter, diff_counter);
            rte_spinlock_unlock(&latency_lock);
        }

        /* Leader prints to screen */
        if (core == worker_settings.rx_leader_core_id) {
            diff_ns = get_time_ns() - last_ns;
            if (diff_ns > 1e9) {
                /* Calculate RX, RX errors */
                counter = atomic_exchange(&rx_counter.val, 0);
                double mpps = (double)counter/1e6/(diff_ns/1e9);
                err_counter = atomic_exchange(&rx_err_counter.val, 0);

                /* Calc avg latency */
                rte_spinlock_lock(&latency_lock);
                diff_total = atomic_exchange(&latency_total, 0);
                diff_counter = atomic_exchange(&latency_counter, 0);
                double avg_latency_usec = (diff_counter == 0) ? 0 :
                        (double)diff_total / diff_counter / 1e3;
                rte_spinlock_unlock(&latency_lock);

                printf("RX %.4lf Mpps, errors: %lu, avg. latency %.1lf usec\n",
                       mpps, err_counter, avg_latency_usec);
                last_ns = get_time_ns();
            }
        }
    }

    /* Push values from local vector into the global vector */
    uint64_t val;
    VECTOR_FOR_EACH(local_vector, val, uint64_t) {
        vector_push(latency_vector, &val);
    }
    vector_destroy(local_vector);

    return 0;
}
