#ifndef _RCU_H
#define _RCU_H

#include <stdatomic.h>
#include <pthread.h>
#include "common.h"
#include "locks.h"
#include "list.h"

/* Callback method for RCU type */
typedef void(*rcu_callback_t)(void*);

struct rcu {
    struct list cb_list;  /* Holds "struct rcu_cb" */
    struct spinlock lock; /* Locks on "cb_list" */
    void *ptr;            /* Pointer to data */
    atomic_uint counter;  /* Number of active pointers to this */
};

/* RCU type declaration */
typedef _Atomic(struct rcu *) rcu_t;

/* Initiate VAR to VAL */
#define rcu_init(VAR, VAL) rcu_init__(CONST_CAST(rcu_t*, &VAR), VAL)
#define rcu_destroy(VAR) rcu_destroy__(VAR)

/* Acquire & release an RCU pointer
 * Usage:
 * rcu_t var = rcu_acquire(&rcu);
 * ...
 * rcu_release(var); */
#define rcu_acquire(VAR) rcu_acquire__(CONST_CAST(rcu_t*, &VAR))
#define rcu_release(VAR) rcu_release__(VAR)

/* Getter, setter. */
#define rcu_get(VAR, TYPE) ((TYPE)VAR->ptr)
#define rcu_set(VAR, VAL) rcu_set__(CONST_CAST(rcu_t*, &VAR), VAL)

/* Postpone FUNCTION(ARG) when the current value of VAR is not longer used */
#define rcu_postpone(VAR, FUNCTION, ARG)                     \
     rcu_postpone__(VAR, FUNCTION, ARG, SOURCE_LOCATOR)

void rcu_init__(rcu_t *, void *val);
void rcu_destroy__(rcu_t );
rcu_t rcu_acquire__(rcu_t *);
void rcu_release__(rcu_t);
void rcu_set__(rcu_t *, void *val);
void rcu_set_and_wait__(rcu_t *, void *val);
void rcu_postpone__(rcu_t,
                    rcu_callback_t,
                    void *args,
                    const char *where);

#endif
