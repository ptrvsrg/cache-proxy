#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>

#include "env.h"
#include "log.h"
#include "proxy.h"

static void print_usage(char *prog_name);
static void print_intro(char *version);
static int get_port(char *port_str);

int main(int argc, char **argv) {
    if (argc < 2) {
        print_usage(argv[0]);
        return EXIT_FAILURE;
    }
    print_intro("0.0.0");

    log_set_level(env_get_log_level());
    int handler_count = env_get_client_handler_count();
    time_t cache_expired_time_ms = env_get_cache_expired_time_ms();

    int port = get_port(argv[1]);
    if (port == -1) {
        return EXIT_FAILURE;
    }

    proxy_t *proxy = proxy_create(handler_count, cache_expired_time_ms);
    proxy_start(proxy, port);
    proxy_destroy(proxy);

    return EXIT_SUCCESS;
}

static void print_usage(char *prog_name) {
    printf("Usage: %s <proxy_port>\n", prog_name);
}

static void print_intro(char *version) {
    char *art = "   ______           __            ____                       \n"
                "  / ____/___ ______/ /_  ___     / __ \\_________  _  ____  __\n"
                " / /   / __ `/ ___/ __ \\/ _ \\   / /_/ / ___/ __ \\| |/_/ / / /\n"
                "/ /___/ /_/ / /__/ / / /  __/  / ____/ /  / /_/ />  </ /_/ / \n"
                "\\____/\\__,_/\\___/_/ /_/\\___/  /_/   /_/   \\____/_/|_|\\__, /  \n"
                "                                                    /____/   ";
    printf("%s\nCache Proxy: %s\n\n", art, version);
}

static int get_port(char *port_str) {
    errno = 0;
    char *end;
    int handler_count = (int) strtol(port_str, &end, 0);
    if (errno != 0) {
        log_error("Port getting error: %s", strerror(errno));
        return -1;
    }
    if (end == port_str) {
        log_error("Port getting error: no digits were found");
        return -1;
    }

    return handler_count;
}
