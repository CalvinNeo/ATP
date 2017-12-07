#include "atp_impl.h"


static void _log_doit(ATPSocket * socket, int level, char const *fmt, va_list va){
    char new_fmt[2048];
    std::snprintf(new_fmt, 2048, "[%s] %s\n", socket->to_string(), fmt);

    char buf[8192];
    memset(buf, 0, sizeof buf);
    switch(level){
        case LOGLEVEL_FATAL:
            std::fprintf(stderr, new_fmt, va);
            break;
        case LOGLEVEL_DEBUG:
            std::fprintf(stderr, new_fmt, va);
            break;
        case LOGLEVEL_NOTE:
            std::fprintf(stdout, new_fmt, va);
            break;
    }
}
static void _log_doit(ATPContext * context, int level, char const *fmt, va_list va){
    char new_fmt[2048];
    std::snprintf(new_fmt, 2048, "[Context] %s\n", fmt);

    char buf[8192];
    memset(buf, 0, sizeof buf);

    switch(level){
        case LOGLEVEL_FATAL:
            std::fprintf(stderr, new_fmt, va);
            break;
        case LOGLEVEL_DEBUG:
            std::fprintf(stderr, new_fmt, va);
            break;
        case LOGLEVEL_NOTE:
            std::fprintf(stdout, new_fmt, va);
            break;
    }
}

void log_fatal(ATPSocket * socket, char const *fmt, ...){
    va_list va;
    va_start(va, fmt);
    _log_doit(socket, LOGLEVEL_FATAL, fmt, va);
    va_end(va);
    exit(1);
}
void log_debug(ATPSocket * socket, char const *fmt, ...){
    va_list va;
    va_start(va, fmt);
    _log_doit(socket, LOGLEVEL_DEBUG, fmt, va);
    va_end(va);
}
void log_note(ATPSocket * socket, char const *fmt, ...){
    va_list va;
    va_start(va, fmt);
    _log_doit(socket, LOGLEVEL_NOTE, fmt, va);
    va_end(va);
}

void log_fatal(ATPContext * context, char const *fmt, ...){
    va_list va;
    va_start(va, fmt);
    _log_doit(context, LOGLEVEL_FATAL, fmt, va);
    va_end(va);
    exit(1);
}
void log_debug(ATPContext * context, char const *fmt, ...){
    va_list va;
    va_start(va, fmt);
    _log_doit(context, LOGLEVEL_DEBUG, fmt, va);
    va_end(va);
}
void log_note(ATPContext * context, char const *fmt, ...){
    va_list va;
    va_start(va, fmt);
    _log_doit(context, LOGLEVEL_NOTE, fmt, va);
    va_end(va);
}