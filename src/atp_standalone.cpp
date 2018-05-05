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
#include "atp_standalone.h"
#include <functional>


// #define ATP_USE_SIGALRM
#ifdef ATP_USE_SIGALRM
// make C happy
static std::function<void(sigval_t)> signal_callback;
static void signal_entry(sigval_t sigval){
    signal_callback(sigval);
}

static sigfunc_t * origin_sigfunc;
static ATP_PROC_RESULT atp_sys_loop(atp_socket * socket, std::function<atp_result(atp_socket*)> predicate){ 
    static char sys_cache[ATP_SYSCACHE_MAX];
    if(socket == nullptr) return ATP_PROC_ERROR;
    // sys loop with blocked socket
    ATP_PROC_RESULT result;
    ATPContext * context = socket->context;
    // set timeout
    // Even if timeout is not set, recvfrom will not be forever blocked because of `alarm(1)`
    activate_nonblock(sockfd);
    // struct timeval tv; tv.tv_sec = 1;
    // setsockopt(socket->sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    
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
        if (result == ATP_PROC_FINISH || result == ATP_PROC_OK){ break; }
        else if(result == ATP_PROC_WAIT){ continue; }
    }
    return result;
}
#else
static ATP_PROC_RESULT atp_sys_loop(atp_socket * socket, std::function<atp_result(atp_socket*)> predicate){ 
    static char sys_cache[ATP_SYSCACHE_MAX];
    if(socket == nullptr) return ATP_PROC_ERROR;
    // sys loop with blocked socket
    ATP_PROC_RESULT result;
    ATPContext * context = socket->context;
    struct pollfd pfd[1];

    // main loop
    while (true) {
        pfd[0].fd = socket->sockfd;
        pfd[0].events = POLLIN;

        int ret = poll(pfd, 1, 1000);
        if (ret < 0) {
            result = ATP_PROC_ERROR;
            break;
        }
        else if (ret == 0) {
            result = atp_timer_event(context, 1000);
            if(result == ATP_PROC_FINISH) break;
        }
        else {
            struct sockaddr_in peer_addr; socklen_t peer_len = sizeof(peer_addr);
            sockaddr * ppeer_addr = (SA *)&peer_addr;
            int n = recvfrom(socket->sockfd, sys_cache, ATP_SYSCACHE_MAX, 0, ppeer_addr, &peer_len);
            if(n > 0){
                #if defined (ATP_LOG_AT_DEBUG) && defined(ATP_LOG_UDP)
                    log_debug(socket, "sys_loop Recv %d bytes.", n);
                #endif
                ATPAddrHandle handle_to(reinterpret_cast<const SA *>(&peer_addr));
                socket->process(handle_to, sys_cache, n);
            }
        }

        result = predicate(socket);
        if (result == ATP_PROC_FINISH || result == ATP_PROC_OK){ break; }
        else if(result == ATP_PROC_WAIT){ continue; }
    }
    return result;
}
#endif


ATP_PROC_RESULT atp_standalone_connect(atp_socket * socket, const struct sockaddr * to, socklen_t tolen){
    ATPAddrHandle handle(to);
    int n;
    socket->connect(to);
    return atp_sys_loop(socket, [](atp_socket * socket){
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


ATP_PROC_RESULT atp_standalone_accept(atp_socket * socket){
    return atp_sys_loop(socket, [](atp_socket * socket){
        if (socket->conn_state >= CS_SYN_RECV)
        {
            // IMPORTANT:
            // DO NOT wait until the last handshake which is the ACK packet from peer,
            // because that ACK may contains with data, according to Delay ACK strategy.
            // atp_sys_loop UDP Recv 12 bytes.
            //     method       ts   flag        seq    payload        ack
            //        rcv     1507      S      31252          2          0
            //        snd     1507     SA      50090          2      31252
            // UDP Send 12 bytes.
            // atp_sys_loop UDP Recv 64 bytes.
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

ATP_PROC_RESULT atp_standalone_close(atp_socket * socket){
    if(socket == nullptr) return ATP_PROC_ERROR;
    #if defined (ATP_LOG_AT_DEBUG)
        log_debug(socket, "User called atp_close");
    #endif
    socket->close();
    return atp_sys_loop(socket, [](atp_socket * socket){
        if (socket->conn_state == CS_DESTROY || socket->conn_state == CS_PASSIVE_LISTEN)
        {
            return ATP_PROC_FINISH;
        }else{
            return ATP_PROC_WAIT;
        }
    });
}
