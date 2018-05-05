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

int atp_getfd(atp_socket * socket){
    if(socket == nullptr) return ATP_PROC_ERROR;
    return socket->sockfd;
}

atp_socket * atp_create_socket(atp_context * context){
    ATPSocket * socket = new ATPSocket(context);
    int sockfd = socket->init(AF_INET, SOCK_DGRAM, 0);
    // Now this socket is registered to context,
    // but it will not be able to locate until is connected.
    // Thus it will have its own (addr:port), and `register_to_look_up` will be called,
    // and the socket will be insert into `context->look_up`
    context->sockets.push_back(socket);
    return socket;
}

atp_socket * atp_fork_socket(atp_socket * origin){
    return origin->fork_me();
}

atp_socket * atp_fork_basic_socket(atp_socket * origin){
    return origin->fork_basic();
}

ATP_PROC_RESULT atp_async_connect(atp_socket * socket, const struct sockaddr * to, socklen_t tolen){
    ATPAddrHandle handle(to);
    return socket->connect(to);
}


ATP_PROC_RESULT atp_listen(atp_socket * socket, uint16_t host_port){
    if(socket == nullptr) return ATP_PROC_ERROR;
    return socket->listen(host_port);
}


ATP_PROC_RESULT atp_async_write(atp_socket * socket, void * buf, size_t length){
    if(socket == nullptr) return ATP_PROC_ERROR;
    return socket->write(buf, length);
}

ATP_PROC_RESULT atp_send_packet(atp_socket * socket, void * buf, size_t length){
    if(socket == nullptr) return ATP_PROC_ERROR;
    return socket->write(buf, length);
}

ATP_PROC_RESULT atp_send_oob(atp_socket * socket, void * buf, size_t length, uint32_t timeout){
    if(socket == nullptr) return ATP_PROC_ERROR;
    return socket->write_oob(buf, length, timeout);
}

ATP_PROC_RESULT atp_process_udp(atp_context * context, int sockfd, const char * buf, size_t len, const struct sockaddr * to, socklen_t tolen){
    if(socket == nullptr) return ATP_PROC_ERROR;
    ATPAddrHandle handle_to(to);
    ATP_PROC_RESULT result = ATP_PROC_OK;
    const ATPPacket * pkt = reinterpret_cast<const ATPPacket *>(buf);
    // Whether the packet is to initialize a connection
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

ATP_PROC_RESULT atp_async_close(atp_socket * socket){
    if(socket == nullptr) return ATP_PROC_ERROR;
    #if defined (ATP_LOG_AT_DEBUG)
        log_debug(socket, "User called atp_async_close");
    #endif
    return socket->close();
}

void atp_set_callback(atp_socket * socket, int callback_type, atp_callback_func * proc){
    if(socket != nullptr){
        socket->callbacks[callback_type] = proc;
    }
}

ATP_PROC_RESULT atp_eof(atp_socket * socket){
    if(socket == nullptr) return ATP_PROC_ERROR;
    if(socket->conn_state < CS_CONNECTED) return false;
    return !socket->readable();
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

void atp_set_long(atp_socket * socket, size_t option, size_t value){
    switch(option){
    case ATP_API_SACKOPT:
        break;
    case ATP_API_SOCKID:
        socket->sock_id = value;
        #if defined (ATP_LOG_AT_DEBUG)
            log_debug(socket, "Manually change sock_id to %u", socket->sock_id);
        #endif
        break;
    case ATP_API_REUSEPORT:
        socket->reuse_port_flag = value;
        break;
    }
}

size_t atp_get_long(atp_socket * socket, size_t option){
    switch(option){
    case ATP_API_SACKOPT:
        return socket->my_max_sack_count;
    case ATP_API_SOCKID:
        return socket->sock_id;
    case ATP_API_STATUS:
        return socket->conn_state;
    case ATP_API_WRITABLE:
        return socket->writable();
    case ATP_API_READABLE:
        return socket->readable();
    case ATP_API_EOF:
        return socket->eof();
    case ATP_API_REUSEPORT:
        return socket->reuse_port_flag;
    case ATP_API_SENDINGSTATUS:
        if(socket->outbuf.size() == 0){
            return ATP_PROC_OK;
        }else{
            return ATP_PROC_WAIT;
        }
    }
}


atp_result atp_destroy(atp_socket * socket){
    socket->destroy_hard();
}
