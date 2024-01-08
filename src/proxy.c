#include "proxy.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <regex.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "cache.h"
#include "log.h"
#include "thread_pool.h"

#include "picohttpparser.h"

#define BUFFER_SIZE             4096
#define CACHE_CAPACITY          100
#define TASK_QUEUE_CAPACITY     100
#define MAX_USERS_COUNT         10
#define ACCEPT_TIMEOUT_MS       1000
#define READ_WRITE_TIMEOUT_MS   10000

#define SUCCESS             0
#define ERROR               (-1)
#define NO_CLIENT           (-2)

static proxy_t *instance = NULL;

static void termination_handler(__attribute__((unused)) int signal);
static int create_server_socket(int port);
static int accept_client(int server_socket);
static void handle_client(void *arg);
static int connect_to_remote(const char *host, int port);

static ssize_t receive_with_timeout(int fd, char **data, size_t data_len);
static ssize_t send_with_timeout(int fd, const char *data, size_t data_len);
static ssize_t receive_full_data(int fd, char **data);
static ssize_t send_full_data(int fd, const char *data, size_t data_len);
static ssize_t send_message(int fd, const message_t *message);
static ssize_t receive_and_send_data(int ifd, int ofd, char **data);
static ssize_t receive_and_send_message(int ifd, int ofd, message_t **message);

static int get_host_port(const char *host_port, char *host, int *port);
static int parse_request(const char *request, size_t request_len, const char **method, size_t *method_len, const char **host, size_t *host_len);
static int parse_response(const char *response, size_t response_len, int *status, size_t *content_len, int *content_length_header);
static int check_request(const char *method, size_t method_len);
static int check_response(int status);

struct proxy_t {
    // Cache
    cache_t *cache;
    pthread_mutex_t lock;

    // Handlers
    thread_pool_t *handlers;

    // State
    atomic_int running;
};

struct client_handler_context_t {
    proxy_t *proxy;
    int client_socket;
};
typedef struct client_handler_context_t client_handler_context_t;

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

    pthread_mutex_init(&proxy->lock, NULL);

    proxy->running = 1;

    return proxy;
}

void proxy_start(proxy_t *proxy, int port) {
    if (proxy == NULL) {
        log_error("Proxy starting error: proxy is NULL");
        return;
    }

    // Handle termination signal
    instance = proxy;
    signal(SIGINT, termination_handler);
    signal(SIGTERM, termination_handler);

    // Create server socket
    int server_socket = create_server_socket(port);
    if (server_socket == ERROR) goto delete_proxy_instance;

    while (proxy->running) {
        // Accept client
        int client_socket = accept_client(server_socket);
        if (client_socket == NO_CLIENT) continue;
        if (client_socket == ERROR) goto close_server_socket;

        // Initialize context
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

        // Handle client
        thread_pool_execute(proxy->handlers, handle_client, ctx);
    }

close_server_socket:
    close(server_socket);
delete_proxy_instance:
    instance = NULL;
}

void proxy_destroy(proxy_t *proxy) {
    if (proxy == NULL) {
        log_error("Proxy destroying error: proxy is NULL");
        return;
    }

    log_debug("Destroy handlers");
    thread_pool_shutdown(proxy->handlers);

    log_debug("Destroy cache");
    cache_destroy(proxy->cache);
    pthread_mutex_destroy(&proxy->lock);

    log_debug("Destroy proxy");
    free(proxy);

    instance = NULL;
}

static void termination_handler(__attribute__((unused)) int signal) {
    if (instance != NULL && instance->running) {
        instance->running = 0;
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

    // Reuse address
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

    // Wait event
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
    if (arg == NULL) {
        log_error("Proxy error: client handler context is NULL");
        return;
    }
    client_handler_context_t *ctx = (client_handler_context_t *) arg;

    // Read request
    char *request = NULL;
    size_t request_len = receive_full_data(ctx->client_socket, &request);
    if (request_len == ERROR) goto destroy_ctx;

    // Parse request
    char *method, *host_port;
    size_t method_len, host_len;
    if (parse_request(request, request_len, (const char **) &method, &method_len, (const char **)
                      &host_port, &host_len) == ERROR) goto destroy_ctx;

    // Create cache entry
    cache_entry_t *entry = NULL;
    if (check_request(method, method_len)) {
        pthread_mutex_lock(&ctx->proxy->lock);

        entry = cache_get(ctx->proxy->cache, request, request_len);
        if (entry != NULL) {
            if (entry->response == NULL) {
                pthread_rwlock_rdlock(&entry->lock);
                pthread_rwlock_unlock(&entry->lock);
            }
            log_debug("Cache hit");
            send_message(ctx->client_socket, entry->response);
            pthread_mutex_unlock(&ctx->proxy->lock);
            goto destroy_ctx;
        }

        entry = cache_entry_create(request, request_len, NULL);
        if (entry == NULL) {
            pthread_mutex_unlock(&ctx->proxy->lock);
            goto destroy_ctx;
        }

        if (cache_add(ctx->proxy->cache, entry) == ERROR) {
            pthread_mutex_unlock(&ctx->proxy->lock);
            cache_entry_destroy(entry);
            goto destroy_ctx;
        }
        pthread_rwlock_wrlock(&entry->lock);
        pthread_mutex_unlock(&ctx->proxy->lock);
    }

    log_debug("Cache miss");

    // Connect to the remote host
    char host_port1[BUFFER_SIZE];
    strncpy(host_port1, host_port, host_len);

    char host[BUFFER_SIZE];
    int port;
    get_host_port(host_port1, host, &port);
    int remote_socket = connect_to_remote(host, port);
    if (remote_socket == ERROR) goto destroy_entry;

    // Send request
    if (send_full_data(remote_socket, request, request_len) == ERROR) goto destroy_entry;

    // Receive response
    char *response_data = NULL;
    ssize_t response_data_len = receive_and_send_data(remote_socket, ctx->client_socket, &response_data);
    if (response_data_len == ERROR) {
        if (response_data != NULL) free(response_data);
        goto destroy_entry;
    }

    // Parse response
    int status, content_length_header;
    size_t content_len;
    if (parse_response(response_data, response_data_len, &status, &content_len, &content_length_header) == ERROR) {
        free(response_data);
        goto destroy_entry;
    }

    // Create message
    message_t *response = NULL;
    message_add_part(&response, response_data, response_data_len);

    // Receive remaining content if not received completely
    while (content_len < content_length_header) {
        response_data_len = receive_and_send_message(remote_socket, ctx->client_socket, &response);
        if (response_data_len == ERROR) {
            message_destroy(&response);
            goto destroy_entry;
        }
        content_len += response_data_len;
    }

    // Upload response to cache
    if (check_request(method, method_len)) {
        entry->response = response;
        pthread_rwlock_unlock(&entry->lock);
        log_debug("Set response to entry");
    }

    goto destroy_ctx;

destroy_entry:
    if (check_request(method, method_len)) {
        size_t deleted_request_len = entry->request_len;
        char *deleted_request = entry->request;
        pthread_rwlock_unlock(&entry->lock);
        cache_delete(ctx->proxy->cache, deleted_request, deleted_request_len);
    }
destroy_ctx:
    close(ctx->client_socket);
    free(ctx);
}

static int connect_to_remote(const char *host, int port) {
    // Resolve address
    struct hostent *h = gethostbyname(host);
    if (h == NULL) {
        log_error("Connect to remote error: %s", hstrerror(h_errno));
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
        return ERROR;
    }

    // Connect to remote host
    if (connect(remote_socket, (struct sockaddr *) &addr, sizeof(struct sockaddr_in)) == ERROR) {
        log_error("Connect to remote error: %s", strerror(errno));
        close(remote_socket);
        return ERROR;
    }

    return remote_socket;
}

//////// Read / Write ////////

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
    ssize_t received_bytes = recv(fd, data, data_len, 0);
    if (received_bytes < 0) {
        log_error("Data receiving error: %s", strerror(errno));
        return ERROR;
    }
    log_trace("Received: %s", data);
    return received_bytes;
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
    ssize_t sent_bytes = send(fd, data, data_len, 0);
    if (sent_bytes == ERROR) {
        log_error("Data sending error: %s", strerror(errno));
        return ERROR;
    }
    log_trace("Sent: %s", data);
    return sent_bytes;
}

static ssize_t receive_full_data(int fd, char **data) {
    *data = NULL;

    ssize_t all_received_bytes = 0;
    char buf[BUFFER_SIZE + 1];
    while (1) {
        memset(buf, 0, BUFFER_SIZE);
        ssize_t received_bytes = receive_with_timeout(fd, (char **) &buf, BUFFER_SIZE);
        if (received_bytes == ERROR) return ERROR;
        if (received_bytes == 0) break;

        all_received_bytes += received_bytes;
        char *temp = realloc(*data, all_received_bytes + 1);
        if (temp == NULL) {
            if (errno == ENOMEM) log_error("Data receiving error: %s", strerror(errno));
            else log_error("Data receiving error: failed to reallocate memory");

            free(*data);
            *data = NULL;
            return ERROR;
        }
        *data = temp;
        strncpy(*data + all_received_bytes - received_bytes, buf, received_bytes);

        if (received_bytes < BUFFER_SIZE) break;
    }

    return all_received_bytes;
}

static ssize_t send_full_data(int fd, const char *data, size_t data_len) {
    ssize_t all_sent_bytes = 0;
    while (1) {
        ssize_t sent_bytes = send_with_timeout(fd, data + all_sent_bytes, data_len - all_sent_bytes);
        if (sent_bytes == ERROR) return ERROR;

        all_sent_bytes += sent_bytes;
        if ((size_t) all_sent_bytes == data_len) break;
    }

    return all_sent_bytes;
}

static ssize_t send_message(int fd, const message_t *message) {
    message_t *curr = (message_t *) message;
    ssize_t all_sent_bytes = 0;
    while (curr != NULL) {
        ssize_t sent_bytes = send_full_data(fd, curr->part, curr->part_len);
        if (sent_bytes == ERROR) return ERROR;
        all_sent_bytes += sent_bytes;
        curr = curr->next;
    }

    return all_sent_bytes;
}

static ssize_t receive_and_send_data(int ifd, int ofd, char **data) {
    char buf[BUFFER_SIZE + 1];
    ssize_t all_received_bytes = 0;
    while (1) {
        memset(buf, 0, BUFFER_SIZE);
        ssize_t received_bytes = receive_with_timeout(ifd, (char **) &buf, BUFFER_SIZE);
        if (received_bytes == ERROR) return ERROR;
        if (received_bytes == 0) break;

        ssize_t sent_bytes = send_with_timeout(ofd, buf, received_bytes);
        if (sent_bytes == ERROR) return ERROR;

        all_received_bytes += received_bytes;
        char *temp = realloc(*data, all_received_bytes);
        if (temp == NULL) {
            if (errno == ENOMEM) log_error("Data receiving error: %s", strerror(errno));
            else log_error("Data receiving error: failed to reallocate memory");

            free(*data);
            *data = NULL;
            return ERROR;
        }
        *data = temp;
        strncpy(*data + all_received_bytes - received_bytes, buf, received_bytes);

        if (received_bytes < BUFFER_SIZE) break;
    }

    return all_received_bytes;
}

static ssize_t receive_and_send_message(int ifd, int ofd, message_t **message) {
    char buf[BUFFER_SIZE + 1];
    ssize_t all_sent_bytes = 0;
    while (1) {
        memset(buf, 0, BUFFER_SIZE);
        ssize_t received_bytes = receive_with_timeout(ifd, (char **) &buf, BUFFER_SIZE);
        if (received_bytes == ERROR) return ERROR;
        if (received_bytes == 0) break;

        ssize_t sent_bytes = send_with_timeout(ofd, buf, received_bytes);
        if (sent_bytes == ERROR) return ERROR;

        if (message_add_part(message, buf, received_bytes) == ERROR) return ERROR;
        all_sent_bytes += sent_bytes;

        if (received_bytes < BUFFER_SIZE) break;
    }

    return all_sent_bytes;
}

//////// Request / Response ////////

static int get_host_port(const char *host_port, char *host, int *port) {
    regex_t regex = {};
    char *pattern = "^(http|https)?(://)?([^:/]+)(:([0-9]+))?";
    regmatch_t match[6] = {};

    int ret = regcomp(&regex, pattern, REG_EXTENDED);
    if (ret != 0) {
        log_error("Host and port getting error: failed to regex pattern compilation");
        return ERROR;
    }

    ret = regexec(&regex, host_port, 6, match, 0);
    if (ret == 0) {
        // Get host
        int host_start = match[3].rm_so;
        int host_end = match[3].rm_eo;
        strncpy(host, &host_port[host_start], host_end - host_start);
        host[host_end - host_start] = '\0';

        // Get port
        int port_start = match[5].rm_so;
        int port_end = match[5].rm_eo;
        if (port_start != -1 && port_end != -1) {
            char port_str[port_end - port_start + 1];
            strncpy(port_str, &host_port[port_start], port_end - port_start);

            errno = 0;
            char *end;
            *port = (int) strtol(port_str, &end, 0);
            if (errno != 0) {
                log_warning("Host and port getting error: %s", strerror(errno));
                return ERROR;
            }
            if (end == port_str) {
                log_warning("Host and port getting error: no digits were found");
                return ERROR;
            }
        } else {
            *port = (match[1].rm_so != -1 &&
                     match[1].rm_eo != -1 &&
                     strncmp("https", &host_port[match[1].rm_so], match[1].rm_eo - match[1].rm_so) == 0) ? 443 : 80;
        }
    } else if (ret == REG_NOMATCH) {
        log_error("Host and port getting error: no host or/and port");
        return ERROR;
    } else {
        char buf[BUFFER_SIZE];
        regerror(ret, &regex, buf, BUFFER_SIZE);
        log_error("Host and port getting error: %s", buf);
        return ERROR;
    }

    regfree(&regex);
    return 0;
}

static int parse_request(const char *request, size_t request_len, const char **method, size_t *method_len, const char **host, size_t *host_len) {
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

static int parse_response(const char *response, size_t response_len, int *status, size_t *content_len, int *content_length_header) {
    const char *msg = NULL;
    struct phr_header headers[100];
    size_t msg_len = 0;
    size_t num_headers = 100;
    int minor_version = 0;
    int pret = phr_parse_response(response, response_len, &minor_version, status, &msg, &msg_len, headers,
                                  &num_headers, 0);
    if (pret == -2) {
        log_error("Response parsing error: response is partial");
        return ERROR;
    }
    if (pret == -1) {
        log_error("Response parsing error: failed");
        return ERROR;
    }

    int content_length_idx = -1;
    for (int i = 0; i < 100; ++i) {
        if (strncmp(headers[i].name, "Content-Length", 14) == 0) {
            content_length_idx = i;
            break;
        }
    }
    if (content_length_idx == -1) {
        log_error("Response parsing error: Content-Length header not found");
        return ERROR;
    }

    errno = 0;
    char content_length_value[headers[content_length_idx].value_len + 1];
    strncpy(content_length_value, headers[content_length_idx].value, headers[content_length_idx].value_len);
    char *end = NULL;
    *content_length_header = (int) strtol(content_length_value, &end, 0);
    if (errno != 0) {
        log_error("Response parsing error: %s", strerror(errno));
        return ERROR;
    }
    if (end == content_length_value) {
        log_error("Response parsing error: no digits were found");
        return ERROR;
    }

    char *before_content = strstr(response, "\r\n\r\n");
    if (before_content == NULL) {
        log_warning("Response parsing error: no newlines before content");
        return ERROR;
    }
    *content_len = response_len - (before_content + 4 - response);

    return SUCCESS;
}

static int check_request(const char *method, size_t method_len) {
    return strncmp(method, "GET", method_len) == 0;
}

static int check_response(int status) {
    return status < 400;
}
