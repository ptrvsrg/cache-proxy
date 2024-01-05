#include "cache.h"

#include <errno.h>
#include <malloc.h>
#include <string.h>

#include "log.h"

cache_entry_t *cache_entry_create(const char *request, size_t request_len, const message_t *response) {
    errno = 0;
    cache_entry_t *entry = malloc(sizeof(cache_entry_t));
    if (entry == NULL) {
        if (errno == ENOMEM) log_error("Cache entry creation error: %s", strerror(errno));
        else log_error("Cache entry creation error: failed to reallocate memory");
        return NULL;
    }

    entry->request = (char *) request;
    entry->request_len = request_len;
    entry->response = (message_t *) response;
    pthread_rwlock_init(&entry->lock, NULL);

    return entry;
}

void cache_entry_destroy(cache_entry_t *entry) {
    if (entry == NULL) {
        log_error("Cache entry destroying error: entry is NULL");
        return;
    }

    pthread_rwlock_destroy(&entry->lock);
    if (entry->request != NULL) {
        free(entry->request);
        entry->request = NULL;
    }
    if (entry->response != NULL) message_destroy(&entry->response);
    free(entry);
}