/*
*   Calvin Neo
*   Copyright (C) 2017  Calvin Neo <calvinneo@calvinneo.com>
*   https://github.com/CalvinNeo/ATP
*
*   This program is free software; you can redistribute it and/or modify
*   it under the terms of the GNU General Public License as published by
*   the Free Software Foundation; either version 2 of the License, or
*   (at your option) any later version.
*
*   This program is distributed in the hope that it will be useful,
*   but WITHOUT ANY WARRANTY; without even the implied warranty of
*   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
*   GNU General Public License for more details.
*
*   You should have received a copy of the GNU General Public License along
*   with this program; if not, write to the Free Software Foundation, Inc.,
*   51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

#include "atp_impl.h"
#include <sstream>


void _log_doit1(ATPSocket * socket, char const * func_name, int line, int level, char const * fmt, va_list va){
    char new_fmt[1024];
    std::snprintf(new_fmt, 1024, "[Socket %s] %s at func[%s:%d] \n<syserr %d: %s>\n\t%s\n"
        , socket->to_string(), CONN_STATE_STRS[socket->conn_state], func_name, line, errno, strerror(errno), fmt);
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
void _log_doit1(ATPContext * context, char const* func_name, int line, int level, char const * fmt, va_list va){
    char new_fmt[1024];
    std::snprintf(new_fmt, 1024, "[Context] at func[%s:%d] \n<syserr %d: %s>\n\t%s\n", func_name, line, errno, strerror(errno), fmt);
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

#if defined (USE_DARK_MAGIC)
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

#else
void log_fatal1(ATPSocket * socket, char const *fmt, ...){
    va_list va;
    va_start(va, fmt);
    _log_doit(socket, "", 0, LOGLEVEL_FATAL, fmt, va);
    va_end(va);
    exit(1);
}
void log_debug1(ATPSocket * socket, char const *fmt, ...){
    va_list va;
    va_start(va, fmt);
    _log_doit(socket, "", 0, LOGLEVEL_DEBUG, fmt, va);
    va_end(va);
}
void log_note1(ATPSocket * socket, char const *fmt, ...){
    va_list va;
    va_start(va, fmt);
    _log_doit(socket, "", 0, LOGLEVEL_NOTE, fmt, va);
    va_end(va);
}
void log_fatal1(ATPContext * context, char const *fmt, ...){
    va_list va;
    va_start(va, fmt);
    _log_doit(context, "", 0, LOGLEVEL_FATAL, fmt, va);
    va_end(va);
    exit(1);
}
void log_debug1(ATPContext * context, char const *fmt, ...){
    va_list va;
    va_start(va, fmt);
    _log_doit(context, "", 0, LOGLEVEL_DEBUG, fmt, va);
    va_end(va);
}
void log_note1(ATPContext * context, char const *fmt, ...){
    va_list va;
    va_start(va, fmt);
    _log_doit(context, "", 0, LOGLEVEL_NOTE, fmt, va);
    va_end(va);
}
#endif

void print_out(ATPSocket * socket, OutgoingPacket * out_pkt, const char * method, FILE * stream){
    static bool flag = false;
    ATPPacket * pkt = out_pkt->get_head();
    std::string type = OutgoingPacket::get_flags_str(out_pkt);
    if (!flag)
    {
        flag = true;
        fprintf(stdout, "%10s %6s %8s %6s %10s %10s %10s\n"
            , "method", "sockid", "time", "flag", "seq", "payload", "ack");
    }
    if(stream == nullptr){
        stream = stdout;
    }
    fprintf(stream, "%10s %6d %8lld %6s %10u %10u %10u\n"
        , method, socket->sock_id, (long long)(get_current_ms() - socket->context->start_ms), type.c_str(), pkt->seq_nr, out_pkt->payload, pkt->ack_nr);
}