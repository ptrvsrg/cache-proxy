#include "thread_pool.h"

#include <errno.h>
#include <malloc.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>

#include "log.h"

static long id_counter = 0;

static void *executor_routine(void *arg);

struct task_t {
    long id;
    void (*routine)(void *arg);
    void *arg;
};
typedef struct task_t task_t;

struct thread_pool_t {
    // Task queue
    task_t *tasks;
    int capacity;
    int size;
    int front;
    int rear;
    pthread_mutex_t mutex;
    pthread_cond_t not_empty;
    pthread_cond_t not_full;

    // Executors
    pthread_t *executors;
    int num_executors;

    // Termination
    atomic_int shutdown;
};

thread_pool_t * thread_pool_create(int executor_count, int task_queue_capacity) {
    errno = 0;
    thread_pool_t *pool = malloc(sizeof(thread_pool_t));
    if (pool == NULL) {
        if (errno == ENOMEM) log_error("Thread pool creation error: %s", strerror(errno));
        else log_error("Thread pool creation error: failed to reallocate memory");
        return NULL;
    }

    errno = 0;
    pool->tasks = calloc(sizeof(task_t), task_queue_capacity);
    if (pool->tasks == NULL) {
        if (errno == ENOMEM) log_error("Thread pool creation error: %s", strerror(errno));
        else log_error("Thread pool creation error: failed to reallocate memory");

        free(pool);
        return NULL;
    }

    pool->capacity = task_queue_capacity;
    pool->size = 0;
    pool->front = 0;
    pool->rear = 0;
    pool->shutdown = 0;
    pool->num_executors = executor_count;

    pthread_mutex_init(&pool->mutex, NULL);
    pthread_cond_init(&pool->not_empty, NULL);
    pthread_cond_init(&pool->not_full, NULL);

    errno = 0;
    pool->executors = calloc(sizeof(pthread_t), executor_count);
    if (pool->executors == NULL) {
        if (errno == ENOMEM) log_error("Thread pool creation error: %s", strerror(errno));
        else log_error("Thread pool creation error: failed to reallocate memory");

        pthread_mutex_destroy(&pool->mutex);
        pthread_cond_destroy(&pool->not_empty);
        pthread_cond_destroy(&pool->not_full);
        free(pool);
        return NULL;
    }

    char thread_name[16];
    for (int i = 0; i < executor_count; i++) {
        pthread_create(&pool->executors[i], NULL, executor_routine, pool);

        snprintf(thread_name, 16, "thread-pool-%d", i);
        pthread_setname_np(pool->executors[i], thread_name);
    }

    return pool;
}

void thread_pool_execute(thread_pool_t *pool, routine_t routine, void *arg) {
    if (pool->shutdown) {
        log_error("Thread pool execution error: thread pool was shutdown");
        return;
    }

    pthread_mutex_lock(&pool->mutex);

    // Wait until the queue is not full
    while (pool->size == pool->capacity && !pool->shutdown) pthread_cond_wait(&pool->not_full, &pool->mutex);

    // Exit check
    if (pool->shutdown) {
        pthread_mutex_unlock(&pool->mutex);
        return;
    }

    // Adding a task to the queue
    pool->tasks[pool->rear].id = id_counter++;
    pool->tasks[pool->rear].routine = routine;
    pool->tasks[pool->rear].arg = arg;
    pool->rear = (pool->rear + 1) % pool->capacity;
    pool->size++;

    // Signaling that the queue is not empty
    pthread_cond_signal(&pool->not_empty);

    pthread_mutex_unlock(&pool->mutex);
}

void thread_pool_shutdown(thread_pool_t *pool) {
    pool->shutdown = 1;

    // Wake up all the streams
    pthread_cond_broadcast(&pool->not_empty);
    pthread_cond_broadcast(&pool->not_full);

    // Wait for all threads to complete
    for (int i = 0; i < pool->num_executors; i++) pthread_join(pool->executors[i], NULL);

    free(pool->tasks);
    free(pool->executors);

    pthread_mutex_destroy(&pool->mutex);
    pthread_cond_destroy(&pool->not_empty);
    pthread_cond_destroy(&pool->not_full);

    free(pool);
}

static void *executor_routine(void *arg) {
    thread_pool_t *pool = (thread_pool_t *) arg;
    while (1) {
        pthread_mutex_lock(&pool->mutex);

        // Wait until the queue is empty
        while (pool->size == 0 && !pool->shutdown) pthread_cond_wait(&pool->not_empty, &pool->mutex);

        // Exit check
        if (pool->shutdown) {
            pthread_mutex_unlock(&pool->mutex);
            pthread_exit(NULL);
        }

        // Removing a task from the queue
        task_t task = pool->tasks[pool->front];
        pool->front = (pool->front + 1) % pool->capacity;
        pool->size--;

        // Signaling that the queue is not full
        pthread_cond_signal(&pool->not_full);

        pthread_mutex_unlock(&pool->mutex);

        // Run task
        log_trace("Start executing task %d", task.id);
        task.routine(task.arg);
        log_trace("Finish executing task %d", task.id);
    }
}
