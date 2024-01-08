#ifndef CACHE_PROXY_CACHE_H
#define CACHE_PROXY_CACHE_H

#include <pthread.h>

#include "message.h"

//////// Cache entry ////////

struct cache_entry_t {
    // Request
    char *request;
    size_t request_len;

    // Response
    message_t *response;

    // Sync
    pthread_mutex_t mutex;
    pthread_cond_t ready_cond;
    atomic_int deleted;
};
typedef struct cache_entry_t cache_entry_t;

cache_entry_t *cache_entry_create(const char *request, size_t request_len, const message_t *response);
void cache_entry_destroy(cache_entry_t *entry);

//////// Cache ////////

#define SUCCESS     0
#define ERROR       (-1)
#define NOT_FOUND   (-2)

struct cache_t;
typedef struct cache_t cache_t;

cache_t *cache_create(int capacity, time_t cache_expired_time_ms);
cache_entry_t *cache_get(cache_t *cache, const char *request, size_t request_len);
int cache_add(cache_t *cache, cache_entry_t *entry);
int cache_delete(cache_t *cache, const char *request, size_t request_len);
void cache_destroy(cache_t *cache);

#endif // CACHE_PROXY_CACHE_H