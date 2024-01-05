#ifndef CACHE_PROXY_THREAD_POOL_H
#define CACHE_PROXY_THREAD_POOL_H

struct thread_pool_t;
typedef struct thread_pool_t thread_pool_t;

typedef void (*routine_t)(void *arg);

thread_pool_t *thread_pool_create(int executor_count, int task_queue_capacity);
void thread_pool_execute(thread_pool_t *pool, routine_t routine, void *arg);
void thread_pool_shutdown(thread_pool_t *pool);

#endif // CACHE_PROXY_THREAD_POOL_H
