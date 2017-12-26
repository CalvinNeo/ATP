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
#include "udp_util.h"
#include "atp.h"
#include <functional>


atp_context * atp_create_context(){
    ATPContext * context = new ATPContext();
    return context;
}

// make C happy
static std::function<void(sigval_t)> signal_callback;
static void signal_entry(sigval_t sigval){
    signal_callback(sigval);
}

static sigfunc_t * origin_sigfunc;

static ATP_PROC_RESULT sys_loop(atp_socket * socket, std::function<int(atp_socket*)> predicate){ 
    static char sys_cache[ATP_SYSCACHE_MAX];
    if(socket == nullptr) return ATP_PROC_ERROR;
    // sys loop with blocked socket
    ATP_PROC_RESULT result;
    ATPContext * context = socket->context;
    // set timeout
    // Even if timeout is not set, recvfrom will not be forever blocked because of `alarm(1)`
    struct timeval tv;
    tv.tv_sec = 5;
    setsockopt(socket->sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    // set timer
    signal_callback = [context](sigval_t sig){
        // TODO I don't know why capture `&` is not work
        ATP_PROC_RESULT result = atp_timer_event(context, 1000);
        if (result == ATP_PROC_FINISH)
        {
            // stop triggering
            alarm(0);
            setup_signal(SIGALRM, origin_sigfunc);
        }else{
            alarm(1);
        }
    };
    origin_sigfunc = setup_signal(SIGALRM, signal_entry);
    alarm(1);
    // main loop
    while (true) {
        struct sockaddr_in peer_addr; socklen_t peer_len = sizeof(peer_addr);
        sockaddr * ppeer_addr = (SA *)&peer_addr;
        int n = recvfrom(socket->sockfd, sys_cache, ATP_SYSCACHE_MAX, 0, ppeer_addr, &peer_len);
        if (n < 0){
            if(errno == EINTR || errno == EWOULDBLOCK || errno == EAGAIN){
                // normal, timeout
                if(atp_timer_event(context, 1000) == ATP_PROC_FINISH){
                    // Context finished, mission completed, quit
                    break;
                }
            }else{
                // Error
                result = ATP_PROC_ERROR;
                break;
            }
        }else{    
            #if defined (ATP_LOG_AT_DEBUG) && defined(ATP_LOG_UDP)
                log_debug(socket, "sys_loop Recv %d bytes.", n);
            #endif
            ATPAddrHandle handle_to(reinterpret_cast<const SA *>(&peer_addr));
            socket->process(handle_to, sys_cache, n);
        }
        // TODO: here socket may be already deleted by context
        result = predicate(socket);
        if (result == ATP_PROC_FINISH)
        {   
            // the whole procedure is finished
            break;
        }else if(result == ATP_PROC_WAIT){
            continue;
        }else if(result == ATP_PROC_OK){
            break;
        }
    }
    return result;
}

int atp_getfd(atp_socket * socket){
    if(socket == nullptr) return ATP_PROC_ERROR;
    return socket->sockfd;
}

atp_socket * atp_create_socket(atp_context * context){
    ATPSocket * socket = new ATPSocket(context);
    int sockfd = socket->init(AF_INET, SOCK_DGRAM, 0);
    // now this socket is registered to context
    // but it will not be able to locate until is connected
    // thus it will have a (addr:port), and `register_to_look_up` will be called
    // and the socket will be insert into context->look_up
    context->sockets.push_back(socket);
    return socket;
}

ATP_PROC_RESULT atp_async_connect(atp_socket * socket, const struct sockaddr * to, socklen_t tolen){
    ATPAddrHandle handle(to);
    return socket->connect(to);
}

ATP_PROC_RESULT atp_connect(atp_socket * socket, const struct sockaddr * to, socklen_t tolen){
    ATPAddrHandle handle(to);
    int n;
    socket->connect(to);
    return sys_loop(socket, [](atp_socket * socket){
        if (socket->conn_state >= CS_CONNECTED)
        {
            return ATP_PROC_OK;
        }else if(socket->conn_state == CS_DESTROY){
            return ATP_PROC_FINISH;
        }
        else{
            return ATP_PROC_WAIT;
        }
    });
}

ATP_PROC_RESULT atp_listen(atp_socket * socket, uint16_t host_port){
    if(socket == nullptr) return ATP_PROC_ERROR;
    return socket->listen(host_port);
}

ATP_PROC_RESULT atp_accept(atp_socket * socket){
    return sys_loop(socket, [](atp_socket * socket){
        if (socket->conn_state >= CS_SYN_RECV)
        {
            // IMPORTANT:
            // DO NOT wait until the last handshake, the ACK packet from peer
            // because that ACK may contains with data, according to Delay ACK strategy.
            // sys_loop UDP Recv 12 bytes.
            //     method       ts   flag        seq    payload        ack
            //        rcv     1507      S      31252          2          0
            //        snd     1507     SA      50090          2      31252
            // UDP Send 12 bytes.
            // sys_loop UDP Recv 64 bytes.
            //        rcv     2509     AD      31253         54      50090
            //        snd     3001      A      50090          0      31253
            return ATP_PROC_OK;
        }else if(socket->conn_state == CS_DESTROY){
            return ATP_PROC_FINISH;
        }else{
            return ATP_PROC_WAIT;
        }
    });
}

ATP_PROC_RESULT atp_write(atp_socket * socket, void * buf, size_t length){
    if(socket == nullptr) return ATP_PROC_ERROR;
    return socket->write(buf, length);
}

ATP_PROC_RESULT atp_process_udp(atp_context * context, int sockfd, const char * buf, size_t len, const struct sockaddr * to, socklen_t tolen){
    if(socket == nullptr) return ATP_PROC_ERROR;
    ATPAddrHandle handle_to(to);
    ATP_PROC_RESULT result = ATP_PROC_OK;
    const ATPPacket * pkt = reinterpret_cast<const ATPPacket *>(buf);
    bool is_first = pkt->get_syn() && !(pkt->get_ack());
    ATPSocket * socket = nullptr;
    if (is_first)
    {
        // find in listen
        socket = context->find_socket_by_fd(handle_to, sockfd);
    } else{
        // find by packet
        socket = context->find_socket_by_head(handle_to, pkt);
    }
    if (socket == nullptr)
    {
        result = ATP_PROC_ERROR;
    }else{
        result = socket->process(handle_to, buf, len);
    }
    result = context->daily_routine();
    return result;
}

ATP_PROC_RESULT atp_close(atp_socket * socket){
    if(socket == nullptr) return ATP_PROC_ERROR;
    #if defined (ATP_LOG_AT_DEBUG)
        log_debug(socket, "User called atp_close");
    #endif
    socket->close();
    return sys_loop(socket, [](atp_socket * socket){
        if (socket->conn_state == CS_DESTROY)
        {
            return ATP_PROC_FINISH;
        }else{
            return ATP_PROC_WAIT;
        }
    });
}


ATP_PROC_RESULT atp_async_close(atp_socket * socket){
    if(socket == nullptr) return ATP_PROC_ERROR;
    #if defined (ATP_LOG_AT_DEBUG)
        log_debug(socket, "User called atp_async_close");
    #endif
    return socket->close();
}

void atp_set_callback(atp_socket * socket, int callback_type, atp_callback_func * proc){
    if(socket == nullptr) return ATP_PROC_ERROR;
    socket->callbacks[callback_type] = proc;
}

ATP_PROC_RESULT atp_eof(atp_socket * socket){
    if(socket == nullptr) return ATP_PROC_ERROR;
    if(socket->conn_state < CS_CONNECTED) return false;
    return !socket->readable();
}

ATP_PROC_RESULT atp_send_status(atp_socket * socket){
    if(socket->outbuf.size() == 0){
        return ATP_PROC_OK;
    }else{
        return ATP_PROC_WAIT;
    }
}
ATP_PROC_RESULT atp_timer_event(atp_context * context, uint64_t interval){
    if(context == nullptr) return ATP_PROC_ERROR;
    ATP_PROC_RESULT result = context->daily_routine();
    return result;
}

bool atp_destroyed(atp_socket * socket){
    if(socket == nullptr) return ATP_PROC_ERROR;
    return socket == nullptr ? true : socket->conn_state == CS_DESTROY;
}