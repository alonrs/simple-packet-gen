#include <rte_byteorder.h>
#include <netinet/in.h>

#include "common.h"
#include "generator.h"

void
generator_policy_superspreader(uint64_t pkt_num,
                               uint16_t queue_idx,
                               uint16_t queue_total,
                               struct ftuple *ftuple,
                               void *args)
{
    /* Args represent number of flows */
    static uint32_t nflows = 1;

    /* First packet */
    if (!pkt_num) {
        nflows = get_void_arg_uint32_t(args);
        ftuple->ip_proto = IPPROTO_TCP;
        ftuple->src_ip = get_ip_address(192,168,0,1);
        ftuple->dst_ip = get_ip_address(192,168,0,10);
        ftuple->src_port = get_port(100);
        ftuple->dst_port = get_port(1);
    } else {
        /* Parse current flow */
        uint32_t dst_ip = rte_be_to_cpu_32(ftuple->dst_ip);
        uint16_t dst_port = rte_be_to_cpu_16(ftuple->dst_port);

        /* Make sure not to generate more than nflows */
        if (dst_port >= nflows) {
            dst_port = 0;
            dst_ip = rte_be_to_cpu_32(get_ip_address(192,168,0,0));
        }

        ftuple->dst_ip = rte_cpu_to_be_32(dst_ip + 1);
        ftuple->dst_port = rte_cpu_to_be_16(dst_port + 1);
    }
}
