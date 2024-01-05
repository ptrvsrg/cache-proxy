#ifndef CACHE_PROXY_LOG_H
#define CACHE_PROXY_LOG_H

#define LOG_ALL_TEXT     "ALL"
#define LOG_TRACE_TEXT   "TRACE"
#define LOG_DEBUG_TEXT   "DEBUG"
#define LOG_INFO_TEXT    "INFO"
#define LOG_WARNING_TEXT "WARN"
#define LOG_ERROR_TEXT   "ERROR"
#define LOG_FATAL_TEXT   "FATAL"
#define LOG_OFF_TEXT     "OFF"

#define LOG_ALL_LEVEL     6
#define LOG_TRACE_LEVEL   6
#define LOG_DEBUG_LEVEL   5
#define LOG_INFO_LEVEL    4
#define LOG_WARNING_LEVEL 3
#define LOG_ERROR_LEVEL   2
#define LOG_FATAL_LEVEL   1
#define LOG_OFF_LEVEL     0

#define LOG_LEVEL_DEFAULT LOG_INFO_LEVEL

void log_set_level(int log_level);
void log_trace(const char* format, ...);
void log_debug(const char* format, ...);
void log_info(const char* format, ...);
void log_warning(const char* format, ...);
void log_error(const char* format, ...);
void log_fatal(const char* format, ...);

#endif // CACHE_PROXY_LOG_H
