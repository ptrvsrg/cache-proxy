#include "cache.h"

#include <errno.h>
#include <malloc.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>

#include "log.h"

#define MIN(x, y) (x < y) ? x : y

typedef struct cache_node_t {
    cache_entry_t *entry;
    struct timeval last_modified_time;
    pthread_rwlock_t lock;
    struct cache_node_t *next;
} cache_node_t;

struct cache_t {
    // Hash map
    int capacity;
    cache_node_t **array;

    // Garbage collector
    atomic_int garbage_collector_running;
    time_t entry_expired_time_ms;
    pthread_t garbage_collector;
};

static int hash(const char *request, size_t request_len, int size);
static cache_node_t *cache_node_create(cache_entry_t *entry);
static void cache_node_destroy(cache_node_t *node);
static void *garbage_collector_routine(void *arg);

cache_t *cache_create(int capacity, time_t cache_expired_time_ms) {
    errno = 0;
    cache_t *cache = malloc(sizeof(cache_t));
    if (cache == NULL) {
        if (errno == ENOMEM) log_error("Cache creation error: %s", strerror(errno));
        else log_error("Cache creation error: failed to reallocate memory");
        return NULL;
    }

    cache->capacity = capacity;
    cache->entry_expired_time_ms = cache_expired_time_ms;
    cache->garbage_collector_running = 1;

    errno = 0;
    cache->array = calloc(sizeof(cache_node_t *), capacity);
    if (cache->array == NULL) {
        if (errno == ENOMEM) log_error("Cache creation error: %s", strerror(errno));
        else log_error("Cache creation error: failed to reallocate memory");

        free(cache);
        return NULL;
    }
    for (int i = 0; i < capacity; i++) cache->array[i] = NULL;

    // Start garbage collector
    pthread_create(&cache->garbage_collector, NULL, garbage_collector_routine, cache);

    char thread_name[16];
    snprintf(thread_name, 16, "garbage-collector");
    pthread_setname_np(cache->garbage_collector, thread_name);

    return cache;
}

cache_entry_t *cache_get(cache_t *cache, const char *request, size_t request_len) {
    if (cache == NULL) {
        log_error("Cache getting error: cache is NULL");
        return NULL;
    }

    // Get hash basket
    int index = hash(request, request_len, cache->capacity);
    cache_node_t *curr = cache->array[index];

    // Find entry
    cache_node_t *prev = NULL;
    while (curr != NULL) {
        pthread_rwlock_rdlock(&curr->lock);

        if (curr->entry->request_len == request_len && strncmp(curr->entry->request, request, request_len) == 0) {
            // Update time
            gettimeofday(&curr->last_modified_time, 0);
            pthread_rwlock_unlock(&curr->lock);
            return curr->entry;
        }

        prev = curr;
        curr = curr->next;
        pthread_rwlock_unlock(&prev->lock);
    }
    return NULL;
}

int cache_add(cache_t *cache, cache_entry_t *entry) {
    if (cache == NULL) {
        log_error("Cache adding error: cache is NULL");
        return ERROR;
    }
    if (entry == NULL) {
        log_error("Cache adding error: cache entry is NULL");
        return ERROR;
    }

    // Create node
    cache_node_t *node = cache_node_create(entry);
    if (node == NULL) return ERROR;

    // Get hash basket
    pthread_rwlock_rdlock(&entry->lock);
    int index = hash(entry->request, entry->request_len, cache->capacity);
    pthread_rwlock_unlock(&entry->lock);

    pthread_rwlock_wrlock(&node->lock);
    node->next = cache->array[index];
    pthread_rwlock_unlock(&node->lock);

    cache->array[index] = node;

    log_debug("Add new cache entry");
    return SUCCESS;
}

int cache_delete(cache_t *cache, const char *request, size_t request_len) {
    if (cache == NULL) {
        log_error("Cache deleting error: cache is NULL");
        return ERROR;
    }

    // Get hash basket
    int index = hash(request, request_len, cache->capacity);
    cache_node_t *curr = cache->array[index];

    if (curr == NULL) return NOT_FOUND;

    // Find entry
    cache_node_t *prev = NULL;
    while (curr != NULL) {
        if (strncmp(curr->entry->request, request, request_len) == 0) {
            if (prev == NULL) {
                cache_node_t *next = curr->next;
                if (next == NULL) cache->array[index] = NULL;
            } else {
                pthread_rwlock_wrlock(&prev->lock);
                prev->next = curr->next;
                pthread_rwlock_unlock(&prev->lock);
            }

            pthread_rwlock_unlock(&curr->lock);
            cache_node_destroy(curr);
            log_debug("Cache entry destroy");
            return SUCCESS;
        }

        prev = curr;
        curr = curr->next;

        pthread_rwlock_unlock(&prev->lock);
    }

    return NOT_FOUND;
}

void cache_destroy(cache_t *cache) {
    if (cache == NULL) {
        log_error("Cache destroying error: cache is NULL");
        return;
    }

    cache->garbage_collector_running = 0;
    pthread_join(cache->garbage_collector, NULL);

    for (int i = 0; i < cache->capacity; i++) {
        cache_node_t *curr = cache->array[i];
        while (curr != NULL) {
            cache_node_t *next = curr->next;
            log_debug("Delete entry: %s", curr->entry->request);
            cache_node_destroy(curr);
            curr = next;
        }
    }

    free(cache->array);
    free(cache);
}

static int hash(const char *request, size_t request_len, int size) {
    if (request == NULL) return 0;

    int hash_value = 0;
    for (size_t i = 0; i < request_len; i++) hash_value = (hash_value * 31 + request[i]) % size;
    return hash_value;
}

static cache_node_t *cache_node_create(cache_entry_t *entry) {
    errno = 0;
    cache_node_t *node = malloc(sizeof(cache_node_t));
    if (node == NULL) {
        if (errno == ENOMEM) log_error("Cache node creation error: %s", strerror(errno));
        else log_error("Cache node creation error: failed to reallocate memory");
        return NULL;
    }

    node->entry = entry;
    gettimeofday(&node->last_modified_time, 0);
    pthread_rwlock_init(&node->lock, NULL);
    node->next = NULL;

    return node;
}

static void cache_node_destroy(cache_node_t *node) {
    if (node == NULL) {
        log_error("Cache node destroying error: node is NULL");
        return;
    }

    cache_entry_destroy(node->entry);
    pthread_rwlock_destroy(&node->lock);
}

static void *garbage_collector_routine(void *arg) {
    if (arg == NULL) {
        log_error("Cache garbage collector error: cache is NULL");
        pthread_exit(NULL);
    }
    cache_t *cache = (cache_t *) arg;
    log_debug("Cache garbage collector start");

    struct timeval curr_time;
    while (cache->garbage_collector_running) {
        usleep(MIN(1000 * cache->entry_expired_time_ms / 2, 1000000));
        log_trace("Garbage collector running");

        gettimeofday(&curr_time, 0);
        for (int i = 0; i < cache->capacity; i++) {
            cache_node_t *curr = cache->array[i];

            if (curr == NULL) continue;

            pthread_rwlock_rdlock(&curr->lock);

            cache_node_t *next = NULL;
            while (curr != NULL) {
                time_t diff = (curr_time.tv_sec - curr->last_modified_time.tv_sec) * 1000 +
                        (curr_time.tv_usec - curr->last_modified_time.tv_usec) / 1000;
                if (diff >= cache->entry_expired_time_ms) {
                    pthread_rwlock_rdlock(&curr->lock);
                    next = curr->next;
                    char *request = curr->entry->request;
                    size_t request_len = curr->entry->request_len;
                    pthread_rwlock_unlock(&curr->lock);

                    cache_delete(cache, request, request_len);
                } else {
                    pthread_rwlock_rdlock(&curr->lock);
                    next = curr->next;
                    pthread_rwlock_unlock(&curr->lock);
                }

                curr = next;
            }
        }
    }

    log_debug("Cache garbage collector destroy");
    pthread_exit(NULL);
}
