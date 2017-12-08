#include "atp_impl.h"
#include <sstream>


static std::string tabber(const std::string & src, bool tail_crlf) {
    std::string newline;
    std::string ans = "";
    std::istringstream f(src);
    while (std::getline(f, newline)) {
        ans += '\t';
        ans += newline;
        ans += '\n';
    }
    if (!tail_crlf && ans.back() == '\n')
    {
        return ans.substr(0, ans.size() - 1);
    }
    return ans;
}

void _log_doit1(ATPSocket * socket, char const* func_name, int level, char const * fmt, va_list va){
    char new_fmt[1024];
    std::snprintf(new_fmt, 1024, "[Socket %s] <err %d: %s> at func[%s] :\n\t%s\n", socket->to_string(), errno, strerror(errno), func_name, fmt);
    char buf[4096];
    vsnprintf(buf, 4096, new_fmt, va);
    fflush(stdout);
    switch(level){
        case LOGLEVEL_FATAL:
            std::fprintf(stderr, buf);
            break;
        case LOGLEVEL_DEBUG:
            std::fprintf(stderr, buf);
            break;
        case LOGLEVEL_NOTE:
            std::fprintf(stdout, buf);
            break;
    }
    fflush(stderr);
}
void _log_doit1(ATPContext * context, char const* func_name, int level, char const * fmt, va_list va){
    char new_fmt[1024];
    std::snprintf(new_fmt, 1024, "[Context] <err %d: %s> at func[%s] :\n\t%s\n", errno, strerror(errno), func_name, fmt);
    char buf[4096];
    vsnprintf(buf, 4096, new_fmt, va);
    fflush(stdout);
    switch(level){
        case LOGLEVEL_FATAL:
            std::fprintf(stderr, buf);
            break;
        case LOGLEVEL_DEBUG:
            std::fprintf(stderr, buf);
            break;
        case LOGLEVEL_NOTE:
            std::fprintf(stdout, buf);
            break;
    }
    fflush(stderr);
}

std::function<void(ATPContext *, char const *, va_list)> _log_doit2_context(const char* func_name, int level){
    return [&](ATPContext * context, char const * fmt, va_list va){
        _log_doit1(context, func_name, level, fmt, va);
    };
}

std::function<void(ATPSocket *, char const *, va_list)> _log_doit2_socket(const char* func_name, int level){
    return [&](ATPSocket * socket, char const * fmt, va_list va){
        _log_doit1(socket, func_name, level, fmt, va);
    };
}


// void log_fatal2(ATPSocket * socket, char const *fmt, ...){
//     va_list va;
//     va_start(va, fmt);
//     _log_doit(socket, LOGLEVEL_FATAL, fmt, va);
//     va_end(va);
//     exit(1);
// }
// void log_debug2(ATPSocket * socket, char const *fmt, ...){
//     va_list va;
//     va_start(va, fmt);
//     _log_doit(socket, LOGLEVEL_DEBUG, fmt, va);
//     va_end(va);
// }
// void log_note2(ATPSocket * socket, char const *fmt, ...){
//     va_list va;
//     va_start(va, fmt);
//     _log_doit(socket,  LOGLEVEL_NOTE, fmt, va);
//     va_end(va);
// }

// void log_fatal2(ATPContext * context, char const *fmt, ...){
//     va_list va;
//     va_start(va, fmt);
//     _log_doit(context, LOGLEVEL_FATAL, fmt, va);
//     va_end(va);
//     exit(1);
// }
// void log_debug2(ATPContext * context, char const *fmt, ...){
//     va_list va;
//     va_start(va, fmt);
//     _log_doit(context, LOGLEVEL_DEBUG, fmt, va);
//     va_end(va);
// }
// void log_note2(ATPContext * context, char const *fmt, ...){
//     va_list va;
//     va_start(va, fmt);
//     _log_doit(context, LOGLEVEL_NOTE, fmt, va);
//     va_end(va);
// }

void log_fatal1(ATPSocket * socket, char const *fmt, ...){
    va_list va;
    va_start(va, fmt);
    _log_doit(socket, "", LOGLEVEL_FATAL, fmt, va);
    va_end(va);
    exit(1);
}
void log_debug1(ATPSocket * socket, char const *fmt, ...){
    va_list va;
    va_start(va, fmt);
    _log_doit(socket, "", LOGLEVEL_DEBUG, fmt, va);
    va_end(va);
}
void log_note1(ATPSocket * socket, char const *fmt, ...){
    va_list va;
    va_start(va, fmt);
    _log_doit(socket, "", LOGLEVEL_NOTE, fmt, va);
    va_end(va);
}

void log_fatal1(ATPContext * context, char const *fmt, ...){
    va_list va;
    va_start(va, fmt);
    _log_doit(context, "", LOGLEVEL_FATAL, fmt, va);
    va_end(va);
    exit(1);
}
void log_debug1(ATPContext * context, char const *fmt, ...){
    va_list va;
    va_start(va, fmt);
    _log_doit(context, "", LOGLEVEL_DEBUG, fmt, va);
    va_end(va);
}
void log_note1(ATPContext * context, char const *fmt, ...){
    va_list va;
    va_start(va, fmt);
    _log_doit(context, "", LOGLEVEL_NOTE, fmt, va);
    va_end(va);
}