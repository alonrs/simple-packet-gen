#ifndef _CONFIG_H_
#define _CONFIG_H_

/* Debug flags */
#define DEBUG_PRINT_PACKETS false

/* Packet generation flags */
#define PACKET_TCP_WINSIZE 8192
#define PACKET_TTL 64
#define PACKET_SIZE 64

#define BATCH_SIZE 64

#define DEVICE_MEMPOOL_DEF_SIZE 2048  
#define DEVICE_MEMPOOL_CACHE_SIZE 256 /* Maximum */

#endif
