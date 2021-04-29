#include <stdlib.h>
#include <stddef.h>
#include "common.h"
#include "map.h"

struct map_entry {
    struct map_node *first;
};

struct map_impl {
    struct map_entry *arr;   /* Map entreis */
    size_t count;            /* Number of elements in this */
    size_t max;              /* Capacity of this */
    size_t utilization;      /* Number of utialized entries */
};

static void map_expand(struct map *map);
static size_t map_count__(const struct map *map);
static void map_insert__(struct map_impl *, struct map_node *);

/* Only a single concurrent writer to map is allowed */
static void
map_insert__(struct map_impl *impl, struct map_node *node)
{
    size_t i = node->hash & impl->max;
    node->next = impl->arr[i].first;
    if (!impl->arr[i].first) {
        impl->utilization++;
    }
    impl->arr[i].first = node;
}


static inline struct map_impl*
map_impl_get(struct map *map)
{
    ASSERT(map);
    return map->impl;
}

static struct map_impl*
map_impl_init(size_t entry_num)
{
    struct map_impl *impl;
    size_t size;

    size=sizeof(*impl)+sizeof(struct map_entry)*entry_num;

    impl=(struct map_impl*)xmalloc(size);
    impl->max = entry_num-1;
    impl->count = 0;
    impl->utilization = 0;
    impl->arr = OBJECT_END(struct map_entry*, impl);

    for (int i=0; i<entry_num; ++i) {
        impl->arr[i].first = NULL;
    }
    return impl;
}

static void
map_expand(struct map *map)
{
    struct map_impl *impl_old;
    struct map_impl *impl_new;
    struct map_node *c, *n;

    impl_old = map_impl_get(map);
    impl_new = map_impl_init((impl_old->max+1)*2);
    impl_new->count = impl_old->count;

    /* Rehash */
    for (int i=0; i<=impl_old->max; i++) {
        for(c = impl_old->arr[i].first; c; c=n) {
            n=c->next;
            map_insert__(impl_new, c);
        }
    }

    free(impl_old);
    map->impl = impl_new;
}


/* Initialization of "map". "size" shoule be a power of 2 */
void
map_init(struct map *map, size_t size)
{
    map->impl = map_impl_init(size);
}

void
map_destroy(struct map *map)
{
    free(map->impl);
}

static size_t
map_count__(const struct map *map)
{
    struct map_impl *impl = map_impl_get((struct map*)map);
    return impl->count;
}

double
map_utilization(const struct map *map)
{
    struct map_impl *impl = map_impl_get((struct map*)map);
    return impl->utilization;
}

size_t
map_size(const struct map *map)
{
    return map_count__(map);
}

bool
map_is_empty(const struct map *map)
{
    return map_count__(map) == 0;
}

size_t
map_insert(struct map *map, struct map_node *node, uint32_t hash)
{
    struct map_impl *impl;
    size_t count;

    impl = map_impl_get(map);
    node->hash = hash;
    map_insert__(impl, node);

    impl->count++;
    count=impl->count;

    if (impl->count > impl->max) {
        map_expand(map);
    }
    return count;
}

size_t
map_remove(struct map *map, struct map_node *node)
{
    size_t pos, count;
    struct map_entry *map_entry;
    struct map_impl *impl;
    struct map_node **node_p;

    impl = map_impl_get(map);
    pos = node->hash & impl->max;
    map_entry = &impl->arr[pos];
    count=impl->count;

    node_p = &map_entry->first;
    while (*node_p) {
        if (*node_p == node) {
            *node_p = node->next;
            count--;
            break;
        }
        node_p = &(*node_p)->next;
    }
    impl->count=count;
    return count;
}

struct map_cursor
map_find__(struct map *map, uint32_t hash)
{
    struct map_impl *impl;
    struct map_cursor cursor;

    impl = map_impl_get(map);
    cursor.entry_idx = hash & impl->max;
    cursor.node = impl->arr[cursor.entry_idx].first;
    cursor.next = NULL;
    cursor.accross_entries = false;
    if (cursor.node) {
        cursor.next = cursor.node->next;
    }
    return cursor;
}

struct map_cursor
map_start__(struct map *map)
{
    struct map_cursor cursor = map_find__(map, 0);
    cursor.accross_entries = true;
    /* Don't start with an empty node */
    if (!cursor.node) {
        map_next__(map, &cursor);
    }
    return cursor;
}

void
map_next__(struct map *map, struct map_cursor *cursor)
{
    struct map_impl *impl;
    impl = map_impl_get(map);

    cursor->node = cursor->next;
    if (cursor->node) {
        cursor->next = cursor->node->next;
        return;
    }

    /* We got to the end of the current entry. Try to find
     * a valid node in next entries */
    while (cursor->accross_entries) {
        cursor->entry_idx++;
        if (cursor->entry_idx > impl->max) {
            break;
        }
        cursor->node = impl->arr[cursor->entry_idx].first;
        if (cursor->node) {
            cursor->next = cursor->node->next;
            return;
        }
    }

    cursor->node = NULL;
    cursor->next = NULL;
}
