#ifndef _MAP_H
#define _MAP_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include "common.h"

/* Concurrent map. Supports several concurrent readers, and a single concurrent
 * writer. To iterate, the user need to acuire a "map state" (snapshop). */

struct map_node {
    struct map_node *next; /* Next node with same hash. */
    uint32_t hash;
};

/* Used for going over all map nodes */
struct map_cursor {
    struct map_node *node; /* Pointer to map_node */
    struct map_node *next; /* Pointer to map_node */
    size_t entry_idx;      /* Current entry */
    bool accross_entries;  /* Hold cursor accross map entries */
};

/* Map state (snapshot), must be acquired before map iteration, and released
 * afterwards. Opaque data structure */
struct map_state;

/* Concurrent hash map. */
struct map {
    struct map_state *impl;
};

/* Initialization. */
void map_init(struct map *);
void map_destroy(struct map *);

/* Counters. */
size_t map_size(const struct map *);
bool map_is_empty(const struct map *);
double map_utilization(const struct map *map);

/* Insertion and deletion. Return the current count after the operation. */
size_t map_insert(struct map *, struct map_node *, uint32_t hash);
size_t map_remove(struct map *, struct map_node *);

/* Acquire/release map concurrent state. Use with iteration macros.
 * Each acquired state must be released. */
struct map_state* map_state_acquire(struct map *map);
void map_state_release(struct map_state *state);

/* Iteration macros. Usage example:
 *
 * struct {
 *     struct map_node node;
 *     int value;
 * } *data;
 * struct map_state *map_state = map_state_acquire(&map);
 * MAP_FOR_EACH(data, node, map_state) {
 *      ...
 * }
 * map_state_release(map_state);
 */
#define MAP_FOR_EACH(NODE, MEMBER, STATE) \
    MAP_FOR_EACH__(NODE, MEMBER, MAP, map_start__(STATE), STATE)

#define MAP_FOR_EACH_WITH_HASH(NODE, MEMBER, HASH, STATE) \
    MAP_FOR_EACH__(NODE, MEMBER, MAP, map_find__(STATE, HASH), STATE)

/* Ieration, private methods. Use iteration macros instead */
struct map_cursor map_start__(struct map_state *state);
struct map_cursor map_find__(struct map_state *state, uint32_t hash);
void map_next__(struct map_state *state, struct map_cursor *cursor);

#define MAP_FOR_EACH__(NODE, MEMBER, MAP, START, STATE)                 \
    for(struct map_cursor cursor_ = START;                              \
    (cursor_.node ? (INIT_CONTAINER(NODE, cursor_.node, MEMBER), true)  \
                   : false); map_next__(STATE, &cursor_))


#endif
