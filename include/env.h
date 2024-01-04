#ifndef CACHE_PROXY_ENV_H
#define CACHE_PROXY_ENV_H

#include <time.h>

int env_get_log_level();
int env_get_client_handler_count();
time_t env_get_cache_expired_time_ms();

#endif //CACHE_PROXY_ENV_H
