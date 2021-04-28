#include <stdlib.h>
#include <stddef.h>
#include "common.h"
#include "map.h"
#include "rcu.h"
#include "locks.h"

#define MAP_INITIAL_SIZE 16

struct map_entry {
    struct map_node *first;
};

struct map_impl {
    struct map_entry *arr;   /* Map entreis */
    size_t count;            /* Number of elements in this */
    size_t max;              /* Capacity of this */
    size_t utilization;      /* Number of utialized entries */
    struct cond fence;       /* Prevent new reads while old still exist */
};

struct map_impl_pair {
    struct map_impl *old;
    struct map_impl *new;
};

/* Map state holds a RCU pointer */
struct map_state {
    rcu_t p;
};

static void map_expand(struct map *map);
static void map_expand_callback(void *args);
static void map_destroy_callback(void *args);
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

static void
map_destroy_callback(void *args)
{
    struct map_impl *impl = (struct map_impl*)args;
    cond_destroy(&impl->fence);
    free(impl);
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
    cond_init(&impl->fence);

    for (int i=0; i<entry_num; ++i) {
        impl->arr[i].first = NULL;
    }
    return impl;
}

static void
map_expand_callback(void *args)
{
    struct map_impl_pair *pair = (struct map_impl_pair*)args;
    struct map_node *c, *n;

    /* Rehash */
    for (int i=0; i<=pair->old->max; i++) {
        for(c = pair->old->arr[i].first; c; c=n) {
            n=c->next;
            map_insert__(pair->new, c);
        }
    }

    /* Remove fence */
    cond_unlock(&pair->new->fence);
    free(pair->old);
    free(pair);
}

/* Only a single concurrent writer to map is allowed */
static void
map_expand(struct map *map)
{
    struct map_impl_pair *pair;
    rcu_t impl_rcu;

    impl_rcu = rcu_acquire(map->impl->p);

    pair = xmalloc(sizeof(*pair));
    pair->old = rcu_get(impl_rcu, struct map_impl*);

    /* Do not allow two expansions in parallel */
    /* Prevent new reads while old still exist */
    while(cond_is_locked(&pair->old->fence)) {
        rcu_release(impl_rcu);
        cond_wait(&pair->old->fence);
        impl_rcu = rcu_acquire(map->impl->p);
        pair->old = rcu_get(impl_rcu, struct map_impl*);
    }

    /* Initiate new rehash array */
    pair->new = map_impl_init((pair->old->max+1)*2);
    pair->new->count = pair->old->count;

    /* Prevent new reads/updates while old reads still exist */
    cond_lock(&pair->new->fence);

    rcu_postpone(impl_rcu, map_expand_callback, pair);
    rcu_release(impl_rcu);
    rcu_set(map->impl->p, pair->new);
}


/* Initialization. */
void
map_init(struct map *map)
{
    struct map_impl *impl = map_impl_init(MAP_INITIAL_SIZE);
    map->impl = xmalloc(sizeof(*map->impl));
    rcu_init(map->impl->p, impl);
}

void
map_destroy(struct map *map)
{
    if (!map) {
        return;
    }
    rcu_t impl_rcu = rcu_acquire(map->impl->p);
    struct map_impl *impl = rcu_get(impl_rcu, struct map_impl*);
    rcu_postpone(impl_rcu, map_destroy_callback, impl);
    rcu_release(impl_rcu);
    rcu_destroy(impl_rcu);
    free(map->impl);
}

static size_t
map_count__(const struct map *map)
{
    rcu_t impl_rcu = rcu_acquire(map->impl->p);
    struct map_impl *impl = rcu_get(impl_rcu, struct map_impl*);
    size_t count = impl->count;
    rcu_release(impl_rcu);
    return count;
}

double
map_utilization(const struct map *map)
{
    rcu_t impl_rcu = rcu_acquire(map->impl->p);
    struct map_impl *impl = rcu_get(impl_rcu, struct map_impl*);
    double res = (double)impl->utilization / (impl->max+1);
    rcu_release(impl_rcu);
    return res;
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

/* Only one concurrent writer */
size_t
map_insert(struct map *map, struct map_node *node, uint32_t hash)
{
    rcu_t impl_rcu;
    struct map_impl *impl;
    size_t count;
    bool expand;

    node->hash = hash;

    impl_rcu = rcu_acquire(map->impl->p);
    impl = rcu_get(impl_rcu, struct map_impl*);
    map_insert__(impl, node);
    impl->count++;
    count=impl->count;
    expand = impl->count > impl->max*2;
    rcu_release(impl_rcu);

    if (expand) {
        map_expand(map);
    }
    return count;
}

/* Only one concurrent writer */
size_t
map_remove(struct map *map, struct map_node *node)
{
    size_t pos, count;
    struct map_entry *map_entry;
    struct map_impl *impl;
    struct map_node **node_p;
    rcu_t impl_rcu;

    impl_rcu = rcu_acquire(map->impl->p);
    impl = rcu_get(impl_rcu, struct map_impl*);
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
    rcu_release(impl_rcu);
    return count;
}

struct map_state *
map_state_acquire(struct map *map) {
    struct map_state *state;
    state = xmalloc(sizeof(*state));
    state->p = rcu_acquire(map->impl->p);
    return state;
}

void
map_state_release(struct map_state *state) {
    rcu_release(state->p);
    free(state);
}


struct map_cursor
map_find__(struct map_state *state, uint32_t hash)
{
    struct map_impl *impl;
    struct map_cursor cursor;

    impl = rcu_get(state->p, struct map_impl*);

    /* Prevent new reads while old still exist */
    while(cond_is_locked(&impl->fence)) {
        cond_wait(&impl->fence);
    }

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
map_start__(struct map_state *state)
{
    struct map_cursor cursor = map_find__(state, 0);
    cursor.accross_entries = true;
    /* Don't start with an empty node */
    if (!cursor.node) {
        map_next__(state, &cursor);
    }
    return cursor;
}

void
map_next__(struct map_state *state, struct map_cursor *cursor)
{
    struct map_impl *impl;
    impl = rcu_get(state->p, struct map_impl*);

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
