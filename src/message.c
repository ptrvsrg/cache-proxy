#include "message.h"

#include <errno.h>
#include <malloc.h>
#include <string.h>

#include "log.h"

int message_add_part(message_t **message, char *part, size_t part_len) {
    if (message == NULL) {
        log_error("Message part adding error: message pointer is NULL");
        return ERROR;
    }

    // Create node
    errno = 0;
    message_t *part_msg = malloc(sizeof(message_t));
    if (part_msg == NULL) {
        if (errno == ENOMEM) log_error("Message part adding error: %s", strerror(errno));
        else log_error("Message part adding error: failed to reallocate memory");
        return -1;
    }

    errno = 0;
    part_msg->part = calloc(sizeof(char), part_len);
    if (part_msg->part == NULL) {
        if (errno == ENOMEM) log_error("Message part adding error: %s", strerror(errno));
        else log_error("Message part adding error: failed to reallocate memory");

        free(part_msg);
        return -1;
    }
    strncpy(part_msg->part, part, part_len);
    part_msg->part_len = part_len;
    part_msg->next = NULL;

    if (*message == NULL) {
        *message = part_msg;
        return 0;
    }

    message_t *end = *message;
    while (end->next != NULL) end = end->next;
    end->next = part_msg;
    return 0;
}

size_t message_get_length(const message_t *message) {
    size_t length = 0;
    message_t *curr = (message_t *) message;
    while (curr != NULL) {
        length += curr->part_len;
        curr = curr->next;
    }
    return length;
}

void message_destroy(message_t **message) {
    if (*message == NULL) {
        return;
    }

    message_t *curr = *message, *tmp = NULL;
    while (curr != NULL) {
        tmp = curr;
        curr = curr->next;
        free(tmp);
    }

    *message = NULL;
}
