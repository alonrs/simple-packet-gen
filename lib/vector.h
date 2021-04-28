#ifndef _VECTOR_H_
#define _VECTOR_H_

#include <stddef.h>
#include <stdbool.h>

struct vector;
struct chunk;

/* Points to an element within the vector */
struct vector_iterator {
    struct vector *vector;
    struct chunk *chunk;
    int chunk_index;
    int elem_index;
};

/* Initiates a vector s.t each elements has "elem_size" bytes */
struct vector* vector_init(int elem_size);
void vector_destroy(struct vector *vector);

/* Returns the number of elements in "vector". Thread safe. */
size_t vector_size(struct vector *vector);
/* Insert "element" into "vector". Thread safe. */
void vector_push(struct vector *vector, const void *element);
/* Insert "element" into "vector". Fast, thread unsafe. */
void vector_push_unsafe(struct vector *vector, const void *element);
/* Get a pointer to a random element with "idx" within "vector". Thread safe */
void* vector_get_slow(struct vector *vector, size_t idx);
/* Returns an iterator to the beginning of the vector */
struct vector_iterator vector_begin(struct vector *vector);
/* Returns true iff "it" is valid */
bool vector_iterator_valid(struct vector_iterator *it);
/* Modifies "it" to point to the next element */
void vector_iterator_next(struct vector_iterator *it);
/* Returns a pointer to the element pointed by "it" */
void* vector_iterator_get(struct vector_iterator *it);

/* Go over all elements of type TYPE in VECTOR, populate in VAR */
#define VECTOR_FOR_EACH(VECTOR, VAR, TYPE)                                 \
    for(struct vector_iterator it = vector_begin(VECTOR);                  \
        vector_iterator_valid(&it) ? (VAR=*(TYPE*)vector_iterator_get(&it),\
        true) : false; vector_iterator_next(&it))


#endif
