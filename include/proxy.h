#ifndef CACHE_PROXY_PROXY_H
#define CACHE_PROXY_PROXY_H

#include <time.h>

struct proxy_t;
typedef struct proxy_t proxy_t;

proxy_t *proxy_create(int handler_count, time_t cache_expired_time_ms);
void proxy_start(proxy_t *proxy, int port);
void proxy_destroy(proxy_t *proxy);

#endif // CACHE_PROXY_PROXY_H
