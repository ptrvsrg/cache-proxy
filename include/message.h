#ifndef CACHE_PROXY_MESSAGE_H
#define CACHE_PROXY_MESSAGE_H

#include <stddef.h>

#define SUCCESS 0
#define ERROR   (-1)

struct message_t {
    char *part;
    size_t part_len;
    struct message_t *next;
};
typedef struct message_t message_t;

int message_add_part(message_t **message, char *part, size_t part_len);
void message_destroy(message_t **message);

#endif // CACHE_PROXY_MESSAGE_H
