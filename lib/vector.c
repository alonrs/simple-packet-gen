#include <stdint.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <string.h>

#include "common.h"
#include "vector.h"
#include "list.h"

#define CHUNK_SIZE 4076

struct vector {
    struct list chunks; /* List of chunks in this */
    size_t elements;    /* Total number of elements */
    atomic_uint lock;   /* Private spinlock */
    int elem_size;      /* Bytes per element */
    int num_chunks;     /* Number of chunks */
};

/* A chunk is 4KB size */
struct chunk {
    struct list node;
    int size;
    char items[CHUNK_SIZE];
};


/* Init new chunk */
static struct chunk*
chunk_init()
{
    struct chunk *chunk;
    chunk = xmalloc(sizeof(*chunk));
    chunk->size = 0;
    return chunk;
}

/* Chunk is full */
static inline bool
chunk_is_full(struct chunk *chunk, const int elem_size)
{
    return chunk->size + elem_size>= CHUNK_SIZE;
}

/* Push new element */
static void
chunk_push(struct chunk *chunk,const void *element, const int size)
{
    memcpy(&chunk->items[chunk->size], element, size);
    chunk->size += size;
}

struct vector *
vector_init(int elem_size)
{
    struct vector *vector;
    vector = xmalloc(sizeof(*vector));
    list_init(&vector->chunks);
    vector->elements = 0;
    vector->num_chunks = 0;
    vector->elem_size = elem_size;
    ASSERT(elem_size); /* Must not be zero */
    atomic_init(&vector->lock, 0);
    return vector;
}

void
vector_destroy(struct vector *vector)
{
    struct chunk *chunk;
    LIST_FOR_EACH_POP(chunk, node, &vector->chunks) {
        free(chunk);
    }
    free(vector);
}

static inline void
vector_lock(struct vector *vector)
{
    const uint32_t zero = 0;
    while (!atomic_compare_exchange_strong(&vector->lock, &zero, 1));
}

static inline void
vector_unlock(struct vector *vector)
{
    atomic_store(&vector->lock, 0);
}

size_t
vector_size(struct vector *vector)
{
    size_t ret;
    vector_lock(vector);
    ret = vector->elements;
    vector_unlock(vector);
    return ret;
}

void
vector_push(struct vector *vector, const void *element)
{
    struct chunk *chunk = NULL;

    vector_lock(vector);
    if (!list_is_empty(&vector->chunks)) {
        chunk = CONTAINER_OF(list_back(&vector->chunks), struct chunk, node);
    }

    if (!chunk || chunk_is_full(chunk, vector->elem_size)) {
        chunk = chunk_init();
        list_push_back(&vector->chunks, &chunk->node);
        vector->num_chunks++;
    }

    chunk_push(chunk, element, vector->elem_size);
    vector->elements++;
    vector_unlock(vector);
}

void
vector_push_unsafe(struct vector *vector, const void *element)
{
    struct chunk *chunk = NULL;
    if (!list_is_empty(&vector->chunks)) {
        chunk = CONTAINER_OF(list_back(&vector->chunks), struct chunk, node);
    }

    if (!chunk || chunk_is_full(chunk, vector->elem_size)) {
        chunk = chunk_init();
        list_push_back(&vector->chunks, &chunk->node);
        vector->num_chunks++;
    }

    chunk_push(chunk, element, vector->elem_size);
    vector->elements++;
}

void*
vector_get_slow(struct vector *vector, size_t idx)
{
    struct chunk *chunk;
    int elem_per_chunk;
    int chunk_idx;
    void *ptr;


    vector_lock(vector);
    if (idx >= vector->elements) {
        vector_unlock(vector);
        return NULL;
    }

    elem_per_chunk = CHUNK_SIZE / vector->elem_size;
    chunk_idx = idx / elem_per_chunk;

    LIST_FOR_EACH(chunk, node, &vector->chunks) {
        if (chunk_idx == 0) {
            ptr = &chunk->items[idx*vector->elem_size];
            vector_unlock(vector);
            return ptr;
        }
        idx -= elem_per_chunk;
        chunk_idx--;
    }

    vector_unlock(vector);
    return NULL;
}

struct vector_iterator
vector_begin(struct vector *vector)
{
    struct vector_iterator it = {
            .vector = vector,
            .chunk_index = 0,
            .elem_index = 0,
            .chunk = CONTAINER_OF(list_front(&vector->chunks),
                                  struct chunk,
                                  node)
    };
    return it;
}

bool
vector_iterator_valid(struct vector_iterator *it)
{
    uint32_t num_elements = it->chunk->size / it->vector->elem_size;
    bool in_last_chunk = (it->vector->num_chunks == it->chunk_index);
    bool in_middle_of_chunk = (it->elem_index < num_elements);

    return it->vector &&
           ((it->vector->num_chunks > it->chunk_index) ||
            (in_last_chunk && in_middle_of_chunk));
}

void
vector_iterator_next(struct vector_iterator *it)
{
    uint32_t num_elements = it->chunk->size / it->vector->elem_size;
    if (it->elem_index < num_elements-1) {
        it->elem_index++;
    } else {
        it->chunk_index++;
        it->elem_index = 0;
        it->chunk = CONTAINER_OF(it->chunk->node.next,
                    struct chunk,
                    node);
    }
}

void*
vector_iterator_get(struct vector_iterator *it)
{
    return &it->chunk->items[it->elem_index*it->vector->elem_size];
}
