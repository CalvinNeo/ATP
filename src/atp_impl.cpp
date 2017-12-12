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
    static bool flag = false;
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
    if (!flag)
    {
        flag = true;
        fprintf(stdout, "%5s %8s %5s %10s %10s %10s\n"
            , "method", "ts", "flag", "seq", "payload", "ack");
    }
    fprintf(stdout, "%5s %8lld %5s %10u %10u %10u\n"
        , method, (long long)(get_current_ms() - socket->context->start_ms), type.c_str(), pkt->seq_nr, out_pkt->payload, pkt->ack_nr);
}


ATPSocket * ATPContext::find_socket_by_fd(const ATPAddrHandle & handle_to, int sockfd){
    // find in listen
    // find port by sockfd
    sockaddr_in my_sock; socklen_t my_sock_len = sizeof(my_sock);
    getsockname(sockfd, reinterpret_cast<SA *>(&my_sock), &my_sock_len);
    ATPAddrHandle handle_me(reinterpret_cast<SA *>(&my_sock));

    std::map<uint16_t, ATPSocket*>::iterator iter = this->listen_sockets.find(handle_me.host_port());
    if(iter != this->listen_sockets.end()){
        ATPSocket * socket = iter->second;
        return socket;
    } else{
        #if defined (ATP_LOG_AT_DEBUG)
            log_debug(this, "Can't locate listening socket:%u %u", handle_me.host_port());
        #endif
        return nullptr;
    }
}


ATPSocket * ATPContext::find_socket_by_head(const ATPAddrHandle & handle_to, ATPPacket * pkt){
    // find in look_up
    std::string hashing = std::string(ATPSocket::make_hash_code(pkt->peer_sock_id, handle_to));
    std::map<std::string, ATPSocket*>::iterator iter = this->look_up.find(hashing);
    if(iter != this->look_up.end()){
        ATPSocket * socket = iter->second;
        return socket;
    } else{
        // there's no such socket
        #if defined (ATP_LOG_AT_DEBUG)
            std::string ext;
            for(std::map<std::string, ATPSocket*>::value_type & pr : this->look_up)
            {
                ext += pr.first;
                ext += '\n';
            }
            log_debug(this, "Can't locate socket:%s, the exsiting %u sockets are: %s\n"
                , hashing.c_str(), this->look_up.size(), ext.c_str());
        #endif
        return nullptr;
    }
}