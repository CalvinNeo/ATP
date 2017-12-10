#include "atp_impl.h"
#include <sstream>

const char * CONN_STATE_STRS []= {
    "CS_UNINITIALIZED",
    "CS_IDLE",
    "CS_LISTEN",
    "CS_SYN_SENT",
    "CS_SYN_RECV",
    "CS_RESET",
    "CS_CONNECTED",
    "CS_CONNECTED_FULL",
    "CS_FIN_WAIT_1",
    "CS_CLOSE_WAIT",
    "CS_FIN_WAIT_2",
    "CS_LAST_ACK", 
    "CS_TIME_WAIT",
    "CS_DESTROY",
    "CS_STATE_COUNT"
};

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

void _log_doit1(ATPSocket * socket, char const * func_name, int level, char const * fmt, va_list va){
    char new_fmt[1024];
    std::snprintf(new_fmt, 1024, "[Socket %s] %s at func[%s] \n<syserr %d: %s>\n\t%s\n"
        , socket->to_string(), CONN_STATE_STRS[socket->conn_state], func_name, errno, strerror(errno), fmt);
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
    std::snprintf(new_fmt, 1024, "[Context] at func[%s] \n<syserr %d: %s>\n\t%s\n", func_name, errno, strerror(errno), fmt);
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

void log_fatal2(std::function<void(ATPSocket *, char const *, va_list)> f, ATPSocket * socket, char const *fmt, ...){
    va_list va;
    va_start(va, fmt);
    f(socket, fmt, va);
    va_end(va);
    exit(1);
}
void log_debug2(std::function<void(ATPSocket *, char const *, va_list)> f, ATPSocket * socket, char const *fmt, ...){
    va_list va;
    va_start(va, fmt);
    f(socket, fmt, va);
    va_end(va);
}
void log_note2(std::function<void(ATPSocket *, char const *, va_list)> f, ATPSocket * socket, char const *fmt, ...){
    va_list va;
    va_start(va, fmt);
    f(socket, fmt, va);
    va_end(va);
}
void log_fatal2(std::function<void(ATPContext *, char const *, va_list)> f, ATPContext * context, char const *fmt, ...){
    va_list va;
    va_start(va, fmt);
    f(context, fmt, va);
    va_end(va);
    exit(1);
}
void log_debug2(std::function<void(ATPContext *, char const *, va_list)> f, ATPContext * context, char const *fmt, ...){
    va_list va;
    va_start(va, fmt);
    f(context, fmt, va);
    va_end(va);
}
void log_note2(std::function<void(ATPContext *, char const *, va_list)> f, ATPContext * context, char const *fmt, ...){
    va_list va;
    va_start(va, fmt);
    f(context, fmt, va);
    va_end(va);
}


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

void print_out(ATPSocket * socket, OutgoingPacket * out_pkt, const char * method){
    ATPPacket * pkt = out_pkt->get_head();
    std::string type;
    if (pkt->get_syn())
    {
        type += "S";
    }
    if (pkt->get_fin())
    {
        type += "F";
    }
    if (pkt->get_ack())
    {
        type += "A";
    }
    if (out_pkt->payload > 0 && !pkt->get_syn())
    {
        type += "D";
    }
    fprintf(stdout, "%5s %8u %5s %10u %10u %10u\n"
        , method, get_current_ms() - socket->context->start_ms, type.c_str(), pkt->seq_nr, out_pkt->payload, pkt->ack_nr);
}