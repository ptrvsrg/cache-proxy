#include "proxy.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "cache.h"
#include "log.h"
#include "thread_pool.h"

#include "picohttpparser.h"

#define BUFFER_SIZE             1024
#define CACHE_CAPACITY          100
#define TASK_QUEUE_CAPACITY     100
#define MAX_USERS_COUNT         10
#define ACCEPT_TIMEOUT_MS       1000
#define READ_WRITE_TIMEOUT_MS   3000

#define SUCCESS             0
#define ERROR               (-1)
#define NO_CLIENT           (-2)

static proxy_t *proxy_instance = NULL;

static void termination_handler(__attribute__((unused)) int signal);
static int create_server_socket(int port);
static int accept_client(int server_socket);
static void handle_client(void *arg);
static ssize_t receive_with_timeout(int fd, char **data, size_t data_len);
static ssize_t send_with_timeout(int fd, const char *data, size_t data_len);
static int receive_full(int fd, char **data, size_t *data_len);
static int send_full(int fd, const char *data, size_t data_len);
static int send_message(int fd, const message_t *message);
static int receive_and_send_message(int ifd, int ofd, message_t **message);
static int parse_request(const char *request, size_t request_len, const char **method,
                         size_t *method_len, const char **host, size_t *host_len);
static int need_cache(const char *method, size_t method_len);
static int connect_to_remote(char *host, size_t host_len);

struct proxy_t {
    cache_t *cache;
    thread_pool_t *handlers;
    atomic_int running;
};

typedef struct client_handler_context_t {
    proxy_t *proxy;
    int client_socket;
} client_handler_context_t;

proxy_t *proxy_create(int handler_count, time_t cache_expired_time_ms) {
    errno = 0;
    proxy_t *proxy = malloc(sizeof(proxy_t));
    if (proxy == NULL) {
        if (errno == ENOMEM) log_error("Proxy creation error: %s", strerror(errno));
        else log_error("Proxy creation error: failed to reallocate memory");
        return NULL;
    }

    proxy->cache = cache_create(CACHE_CAPACITY, cache_expired_time_ms);
    if (proxy->cache == NULL) {
        free(proxy);
        return NULL;
    }

    proxy->handlers = thread_pool_create(handler_count, TASK_QUEUE_CAPACITY);
    if (proxy->handlers == NULL) {
        cache_destroy(proxy->cache);
        free(proxy);
        return NULL;
    }

    proxy->running = 1;

    return proxy;
}

void proxy_start(proxy_t *proxy, int port) {
    if (proxy == NULL) {
        log_error("Proxy starting error: proxy is NULL");
        return;
    }

    // Handle termination signal
    proxy_instance = proxy;
    signal(SIGINT, termination_handler);
    signal(SIGTERM, termination_handler);

    // Create server socket
    int server_socket = create_server_socket(port);
    if (server_socket == ERROR) goto delete_proxy_instance;

    // Accept and handle clients
    while (proxy->running) {
        int client_socket = accept_client(server_socket);
        if (client_socket == NO_CLIENT) continue;
        if (client_socket == ERROR) goto close_server_socket;

        errno = 0;
        client_handler_context_t *ctx = malloc(sizeof(client_handler_context_t));
        if (ctx == NULL) {
            if (errno == ENOMEM) log_error("Client handler context creation error: %s", strerror(errno));
            else log_error("Client handler context creation error: failed to reallocate memory");

            close(client_socket);
            goto close_server_socket;
        }
        ctx->client_socket = client_socket;
        ctx->proxy = proxy;

        thread_pool_execute(proxy->handlers, handle_client, ctx);
    }

close_server_socket:
    close(server_socket);
delete_proxy_instance:
    proxy_instance = NULL;
}

void proxy_destroy(proxy_t *proxy) {
    if (proxy == NULL) {
        log_error("Proxy destroying error: proxy is NULL");
        return;
    }

    log_debug("Destroy cache");
    cache_destroy(proxy->cache);

    log_debug("Destroy handlers");
    thread_pool_shutdown(proxy->handlers);

    log_debug("Destroy proxy");
    free(proxy);
}

static void termination_handler(__attribute__((unused)) int signal) {
    if (proxy_instance != NULL && proxy_instance->running) {
        proxy_instance->running = 0;
        log_info("Wait for the job to complete");
    }
}

static int create_server_socket(int port) {
    // Create socket
    int server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket == ERROR) {
        log_error("Creating server socket error: %s", strerror(errno));
        return ERROR;
    }

    int true = 1;
    setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &true, sizeof(int));

    // Set Internet address
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_UNSPEC;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(port);

    // Bind address to socket
    int err = bind(server_socket, (struct sockaddr *) &server_addr, sizeof(server_addr));
    if (err == ERROR) {
        log_error("Bind socket error: %s", strerror(errno));
        close(server_socket);
        return ERROR;
    }

    // Listen for connections
    err = listen(server_socket, MAX_USERS_COUNT);
    if (err == ERROR) {
        log_error("Listen socket error: %s", strerror(errno));
        close(server_socket);
        return ERROR;
    }

    log_info("Proxy listen on port %d", port);

    return server_socket;
}

static int accept_client(int server_socket) {
    // Set timeout
    fd_set read_fds;
    FD_ZERO(&read_fds);
    FD_SET(server_socket, &read_fds);

    struct timeval timeout;
    timeout.tv_sec = ACCEPT_TIMEOUT_MS / 1000;
    timeout.tv_usec = (ACCEPT_TIMEOUT_MS % 1000) * 1000;

    int ready = select(server_socket + 1, &read_fds, NULL, NULL, &timeout);
    if (ready == ERROR) {
        if (errno != EINTR) log_error("Accept client error: %s", strerror(errno));
        return ERROR;
    }
    else if (ready == 0) return NO_CLIENT;

    // Accept client
    struct sockaddr_in client_addr;
    socklen_t client_addr_size = sizeof(client_addr);
    int client_socket = accept(server_socket, (struct sockaddr *) &client_addr, &client_addr_size);
    if (client_socket == ERROR) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) return NO_CLIENT;
        else {
            log_error("Accept client error: %s", strerror(errno));
            return ERROR;
        }
    }

    // Make socket non-blocking
    int flags = fcntl(client_socket, F_GETFL, 0);
    fcntl(client_socket, F_SETFL, flags | O_NONBLOCK);

    log_info("Accept client %s:%d", inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
    return client_socket;
}

static void handle_client(void *arg) {
    client_handler_context_t *ctx = (client_handler_context_t *) arg;

    // Read request
    char *request = NULL;
    size_t request_len = 0;
    if (receive_full(ctx->client_socket, &request, &request_len) == ERROR) goto destroy_ctx;

    // Parse request
    char *method, *host;
    size_t method_len, host_len;
    if (parse_request(request, request_len, (const char **) &method, &method_len, (const char **) &host, &host_len) == ERROR) goto destroy_ctx;

    // Get response from cache
    cache_entry_t *entry = cache_get(ctx->proxy->cache, request, request_len);
    if (entry != NULL && entry->response != NULL) {
        log_debug("Cache hit");
        send_message(ctx->client_socket, entry->response);
        free(request);
        goto destroy_ctx;
    }

    log_debug("Cache miss");

    // Load response to cache
    if (need_cache(method, method_len)) {
        entry = cache_entry_create(request, request_len, NULL);
        cache_add(ctx->proxy->cache, entry);
        pthread_rwlock_wrlock(&entry->lock);
    }

    // Connect to the remote host, receive response and add to cache if necessary
    int remote_socket = connect_to_remote(host, host_len);
    if (remote_socket == ERROR) goto destroy_entry;

    if (send_full(remote_socket, request, request_len) == ERROR) goto destroy_entry;

    message_t *response = NULL;
    if (receive_and_send_message(remote_socket, ctx->client_socket, &response) == ERROR) goto destroy_entry;

    if (need_cache(method, method_len)) {
        entry->response = response;
        pthread_rwlock_unlock(&entry->lock);
    }

    goto destroy_ctx;

destroy_entry:
    if (need_cache(method, method_len)) {
        size_t deleted_request_len = entry->request_len;
        char *deleted_request = entry->request;
        pthread_rwlock_unlock(&entry->lock);
        cache_delete(ctx->proxy->cache, deleted_request, deleted_request_len);
    }
destroy_ctx:
    close(ctx->client_socket);
    free(ctx);
}

static ssize_t receive_with_timeout(int fd, char **data, size_t data_len) {
    // Set timeout
    fd_set read_fds;
    FD_ZERO(&read_fds);
    FD_SET(fd, &read_fds);

    struct timeval timeout;
    timeout.tv_sec = READ_WRITE_TIMEOUT_MS / 1000;
    timeout.tv_usec = (READ_WRITE_TIMEOUT_MS % 1000) * 1000;

    // Wait event
    int ready = select(fd + 1, &read_fds, NULL, NULL, &timeout);
    if (ready == -1) {
        if (errno != EINTR) log_error("Data receiving error: %s", strerror(errno));
        return ERROR;
    } else if (ready == 0) {
        log_error("Data receiving error: timeout");
        return ERROR;
    }

    // Receive
    ssize_t read_bytes = recv(fd, data, data_len, 0);
    if (read_bytes < 0) {
        log_error("Data receiving error: %s", strerror(errno));
        return ERROR;
    }
    log_trace("Received: %s", data);
    return read_bytes;
}

static ssize_t send_with_timeout(int fd, const char *data, size_t data_len) {
    // Set timeout
    fd_set write_fds;
    FD_ZERO(&write_fds);
    FD_SET(fd, &write_fds);

    struct timeval timeout;
    timeout.tv_sec = READ_WRITE_TIMEOUT_MS / 1000;
    timeout.tv_usec = (READ_WRITE_TIMEOUT_MS % 1000) * 1000;

    // Wait event
    int ready = select(fd + 1, NULL, &write_fds, NULL, &timeout);
    if (ready == -1) {
        if (errno != EINTR) log_error("Data sending error: %s", strerror(errno));
        return ERROR;
    } else if (ready == 0) {
        log_error("Data sending error: timeout");
        return ERROR;
    }

    // Send
    ssize_t written_bytes = send(fd, data, data_len, 0);
    if (written_bytes == ERROR) {
        log_error("Data sending error: %s", strerror(errno));
        return ERROR;
    }
    log_trace("Sent: %s", data);
    return written_bytes;
}

static int receive_full(int fd, char **data, size_t *data_len) {
    *data = NULL;

    ssize_t all_read_bytes = 0;
    char buf[BUFFER_SIZE + 1];
    while (1) {
        ssize_t read_bytes = receive_with_timeout(fd, (char **) &buf, BUFFER_SIZE);
        if (read_bytes == ERROR) return ERROR;
        if (read_bytes == 0) break;

        all_read_bytes += read_bytes;
        char *temp = realloc(*data, all_read_bytes + 1);
        if (temp == NULL) {
            if (errno == ENOMEM) log_error("Data receiving error: %s", strerror(errno));
            else log_error("Data receiving error: failed to reallocate memory");

            free(*data);
            *data = NULL;
            return ERROR;
        }
        *data = temp;

        strncpy(*data + all_read_bytes - read_bytes, buf, read_bytes);

        if (read_bytes < BUFFER_SIZE) break;
    }

    *data_len = all_read_bytes;

    return SUCCESS;
}

static int send_full(int fd, const char *data, size_t data_len) {
    ssize_t all_written_bytes = 0;
    while (1) {
        ssize_t written_bytes = send_with_timeout(fd, data + all_written_bytes, data_len - all_written_bytes);
        if (written_bytes == ERROR) return ERROR;

        all_written_bytes += written_bytes;
        if ((size_t) all_written_bytes == data_len) break;
    }

    return SUCCESS;
}

static int send_message(int fd, const message_t *message) {
    message_t *curr = (message_t *) message;
    while (curr != NULL) {
        if (send_full(fd, curr->part, curr->part_len) == ERROR) return ERROR;
        curr = curr->next;
    }

    return SUCCESS;
}

static int receive_and_send_message(int ifd, int ofd, message_t **message) {
    char buf[BUFFER_SIZE + 1];
    while (1) {
        ssize_t read_bytes = receive_with_timeout(ifd, (char **) &buf, BUFFER_SIZE);
        if (read_bytes == ERROR) return ERROR;
        if (read_bytes == 0) break;

        ssize_t written_bytes = send_with_timeout(ofd, buf, BUFFER_SIZE);
        if (written_bytes == ERROR) return ERROR;

        message_add_part(message, buf, read_bytes);

        if (read_bytes < BUFFER_SIZE) break;
    }

    return SUCCESS;
}

static int parse_request(const char *request, size_t request_len, const char **method, size_t *method_len,
                         const char **host, size_t *host_len) {
    char *path;
    struct phr_header headers[100];
    size_t path_len, num_headers = 100;
    int minor_version;
    int pret = phr_parse_request(request, request_len, method, method_len, (const char **) &path,
                                 &path_len, &minor_version, headers, &num_headers, 0);
    if (pret == -2) {
        log_error("Request parsing error: request is partial");
        return ERROR;
    }
    if (pret == -1) {
        log_error("Request parsing error: failed");
        return ERROR;
    }
    for (int i = 0; i < 100; ++i) {
        if (strncmp(headers[i].name, "Host", 4) == 0) {
            *host = headers[i].value;
            *host_len = headers[i].value_len;
            break;
        }
    }
    if (host == NULL) {
        log_error("Request parsing error: host header not found");
        return ERROR;
    }
    return SUCCESS;
}

static int need_cache(const char *method, size_t method_len) {
    return strncmp(method, "GET", method_len) == 0;
}

static int connect_to_remote(char *host, size_t host_len) {
    // Get remote address
    char *host1 = calloc(sizeof(char), host_len + 1);
    if (host1 == NULL) return ERROR;
    strncpy(host1, host, host_len);

    short port;
    char *port_str = strchr(host1, ':');
    if (port_str == NULL) {
        port = 80;
    } else {
        *port_str = 0;
        port = (short) strtol(port_str + 1, NULL, 0);
    }

    struct hostent *h = gethostbyname(host1);
    if (h == NULL) {
        log_error("Connect to remote error: %s", hstrerror(h_errno));
        free(host1);
        return ERROR;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_port = htons(port);
    addr.sin_family = AF_INET;
    memcpy(&addr.sin_addr, h->h_addr, h->h_length);

    // Create socket
    int remote_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (remote_socket == ERROR) {
        log_error("Connect to remote error: %s", strerror(errno));
        free(host1);
        return ERROR;
    }

    // Connect to remote host
    if (connect(remote_socket, (struct sockaddr *) &addr, sizeof(struct sockaddr_in)) == ERROR) {
        log_error("Connect to remote error: %s", strerror(errno));
        free(host1);
        close(remote_socket);
        return ERROR;
    }

    return remote_socket;
}