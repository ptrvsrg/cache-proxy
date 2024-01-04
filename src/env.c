#include "env.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "log.h"

#define HANDLER_COUNT_DEFAULT           1
#define CACHE_EXPIRED_TIME_MS_DEFAULT   (24 * 60 * 60 * 1000)

int env_get_log_level() {
    char *level_env = getenv("CACHE_PROXY_LOG_LEVEL");
    if (level_env == NULL) {
        log_warning("CACHE_PROXY_LOG_LEVEL getting error: variable not set");
        return LOG_LEVEL_DEFAULT;
    }

    if (strcasecmp(level_env, LOG_ALL_TEXT) == 0)       return LOG_ALL_LEVEL;
    if (strcasecmp(level_env, LOG_TRACE_TEXT) == 0)     return LOG_TRACE_LEVEL;
    if (strcasecmp(level_env, LOG_DEBUG_TEXT) == 0)     return LOG_DEBUG_LEVEL;
    if (strcasecmp(level_env, LOG_INFO_TEXT) == 0)      return LOG_INFO_LEVEL;
    if (strcasecmp(level_env, LOG_WARNING_TEXT) == 0)   return LOG_WARNING_LEVEL;
    if (strcasecmp(level_env, LOG_ERROR_TEXT) == 0)     return LOG_ERROR_LEVEL;
    if (strcasecmp(level_env, LOG_FATAL_TEXT) == 0)     return LOG_FATAL_LEVEL;
    if (strcasecmp(level_env, LOG_OFF_TEXT) == 0)       return LOG_OFF_LEVEL;

    log_warning("CACHE_PROXY_LOG_LEVEL getting error: variable has invalid value");
    return LOG_LEVEL_DEFAULT;
}

int env_get_client_handler_count() {
    char *handler_count_env = getenv("CACHE_PROXY_THREAD_POOL_SIZE");
    if (handler_count_env == NULL) {
        log_warning("CACHE_PROXY_THREAD_POOL_SIZE getting error: variable not set");
        return HANDLER_COUNT_DEFAULT;
    }

    errno = 0;
    char *end;
    int handler_count = (int) strtol(handler_count_env, &end, 0);
    if (errno != 0) {
        log_warning("CACHE_PROXY_THREAD_POOL_SIZE getting error: %s", strerror(errno));
        return HANDLER_COUNT_DEFAULT;
    }
    if (end == handler_count_env) {
        log_warning("CACHE_PROXY_THREAD_POOL_SIZE getting error: no digits were found");
        return HANDLER_COUNT_DEFAULT;
    }

    return handler_count;
}

time_t env_get_cache_expired_time_ms() {
    char *cache_expired_time_ms_env = getenv("CACHE_PROXY_CACHE_EXPIRED_TIME_MS");
    if (cache_expired_time_ms_env == NULL) {
        log_warning("CACHE_PROXY_CACHE_EXPIRED_TIME_MS getting error: variable not set");
        return CACHE_EXPIRED_TIME_MS_DEFAULT;
    }

    errno = 0;
    char *end;
    time_t cache_expired_time_ms = strtol(cache_expired_time_ms_env, &end, 0);
    if (errno != 0) {
        log_warning("CACHE_PROXY_CACHE_EXPIRED_TIME_MS getting error: %s", strerror(errno));
        return CACHE_EXPIRED_TIME_MS_DEFAULT;
    }
    if (end == cache_expired_time_ms_env) {
        log_warning("CACHE_PROXY_CACHE_EXPIRED_TIME_MS getting error: no digits were found");
        return CACHE_EXPIRED_TIME_MS_DEFAULT;
    }

    return cache_expired_time_ms;
}
