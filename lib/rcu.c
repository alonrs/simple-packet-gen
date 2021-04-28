#include <stdlib.h>
#include <stdatomic.h>
#include "common.h"
#include "rcu.h"
#include "locks.h"
#include "list.h"

struct rcu_cb {
    struct list node;  /* Inside "struct rcu" */
    rcu_callback_t cb;
    void *args;
};

static inline rcu_t
rcu_allocate_new(void *val)
{
    rcu_t new_rcu;
    new_rcu=(rcu_t)xmalloc(sizeof(*new_rcu));
    list_init(&new_rcu->cb_list);
    spinlock_init(&new_rcu->lock);
    atomic_init(&new_rcu->counter, 1);
    new_rcu->ptr = val;
    return new_rcu;
}

static void
rcu_free(rcu_t rcu)
{
    struct rcu_cb *rcu_cb;
    LIST_FOR_EACH_POP(rcu_cb, node, &rcu->cb_list) {
        rcu_cb->cb(rcu_cb->args);
        free(rcu_cb);
    }
    spinlock_destroy(&rcu->lock);
    free(rcu);
}

void
rcu_init__(rcu_t *rcu_p, void *val)
{
    rcu_t new_rcu = rcu_allocate_new(val);
    atomic_init(rcu_p, new_rcu);
}

void
rcu_destroy__(rcu_t rcu)
{
    uint32_t counter = atomic_fetch_sub(&rcu->counter, 1);
    ASSERT(counter == 1);
    rcu_free(rcu);
}

rcu_t
rcu_acquire__(rcu_t *rcu_p)
{
    rcu_t rcu = atomic_load(rcu_p);
    atomic_fetch_add(&rcu->counter, 1);
    return rcu;
}

void
rcu_release__(rcu_t rcu)
{
    uint32_t counter = atomic_fetch_sub(&rcu->counter, 1);
    if (counter == 1) {
        rcu_free(rcu);
    }
}

void
rcu_set__(rcu_t *rcu_p, void *val)
{
    rcu_t old_rcu = atomic_load(rcu_p);
    rcu_t new_rcu = rcu_allocate_new(val);
    atomic_store(rcu_p, new_rcu);
    uint32_t counter = atomic_fetch_sub(&old_rcu->counter, 1);
    if (counter == 1) {
        rcu_free(old_rcu);
    }
}

void
rcu_postpone__(rcu_t rcu, rcu_callback_t cb, void *args, const char *where)
{
    struct rcu_cb *rcu_cb;
    rcu_cb=(struct rcu_cb*)xmalloc(sizeof(*rcu_cb));
    rcu_cb->cb=cb;
    rcu_cb->args=args;
    spinlock_lock_at(&rcu->lock, where);
    list_push_back(&rcu->cb_list, &rcu_cb->node);
    spinlock_unlock(&rcu->lock);
}
