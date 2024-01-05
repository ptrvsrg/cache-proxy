#include "log.h"

#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

#define COLOR_RESET     "\033[0m"
#define COLOR_WHITE     "\033[1;37m"
#define COLOR_CYAN      "\033[1;36m"
#define COLOR_GREEN     "\033[1;32m"
#define COLOR_YELLOW    "\033[1;33m"
#define COLOR_RED       "\033[1;31m"
#define COLOR_PINK      "\033[1;35m"

#define MAX_LOG_MESSAGE_LENGTH  1024

static int log_level = LOG_LEVEL_DEFAULT;

static int check_log_level(int log_level_);
static void log_common(const char *log_level_, const char *color, const char *format, va_list args, char *msg);

void log_set_level(int log_level_) {
    log_level = log_level_;
}

void log_trace(const char *format, ...) {
    if (!check_log_level(LOG_TRACE_LEVEL)) return;

    va_list args;
    va_start(args, format);
    char msg[MAX_LOG_MESSAGE_LENGTH];
    log_common(LOG_TRACE_TEXT, COLOR_WHITE, format, args, msg);
    va_end(args);

    puts(msg);
    fflush(stdout);
}

void log_debug(const char *format, ...) {
    if (!check_log_level(LOG_DEBUG_LEVEL)) return;

    va_list args;
    va_start(args, format);
    char msg[MAX_LOG_MESSAGE_LENGTH];
    log_common(LOG_DEBUG_TEXT, COLOR_CYAN, format, args, msg);
    va_end(args);

    puts(msg);
    fflush(stdout);
}

void log_info(const char *format, ...) {
    if (!check_log_level(LOG_INFO_LEVEL)) return;

    va_list args;
    va_start(args, format);
    char msg[MAX_LOG_MESSAGE_LENGTH];
    log_common(LOG_INFO_TEXT, COLOR_GREEN, format, args, msg);
    va_end(args);

    puts(msg);
    fflush(stdout);
}

void log_warning(const char *format, ...) {
    if (!check_log_level(LOG_WARNING_LEVEL)) return;

    va_list args;
    va_start(args, format);
    char msg[MAX_LOG_MESSAGE_LENGTH];
    log_common(LOG_WARNING_TEXT, COLOR_YELLOW, format, args, msg);
    va_end(args);

    puts(msg);
    fflush(stdout);
}

void log_error(const char *format, ...) {
    if (!check_log_level(LOG_ERROR_LEVEL)) return;

    va_list args;
    va_start(args, format);
    char msg[MAX_LOG_MESSAGE_LENGTH];
    log_common(LOG_ERROR_TEXT, COLOR_RED, format, args, msg);
    va_end(args);

    puts(msg);
    fflush(stdout);
}

void log_fatal(const char *format, ...) {
    if (!check_log_level(LOG_FATAL_LEVEL)) return;

    va_list args;
    va_start(args, format);
    char msg[MAX_LOG_MESSAGE_LENGTH];
    log_common(LOG_FATAL_TEXT, COLOR_PINK, format, args, msg);
    va_end(args);

    puts(msg);
    fflush(stdout);
    exit(0);
}

static int check_log_level(int log_level_) {
    return log_level >= log_level_;
}

static void log_common(const char *log_level_, const char *color, const char *format, va_list args, char *msg) {
    struct timeval tv;
    gettimeofday(&tv, 0);

    time_t stamp_time = time(NULL);
    struct tm *tm = localtime(&stamp_time);

    char text[MAX_LOG_MESSAGE_LENGTH];
    vsnprintf(text, MAX_LOG_MESSAGE_LENGTH, format, args);

    char thread_name[256];
    pthread_getname_np(pthread_self(), thread_name, 256);

    snprintf(msg, MAX_LOG_MESSAGE_LENGTH, "%d-%02d-%02d %02d:%02d:%02d.%03ld --- [%15s] %s%5s%s : %s",
             tm->tm_year + 1900,
             tm->tm_mon + 1,
             tm->tm_mday,
             tm->tm_hour,
             tm->tm_min,
             tm->tm_sec,
             tv.tv_usec / 1000 % 1000,
             thread_name,
             color,
             log_level_,
             COLOR_RESET,
             text);
}
