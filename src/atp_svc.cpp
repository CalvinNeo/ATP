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

#include "atp_svc_impl.h"

ATP_PROC_RESULT ATPContextServer::register_listen_port(ATPSocket * socket, uint16_t host_port) {
    ATPContext::register_listen_port(socket, host_port);
    ev.data.fd = socket->sockfd;
    ev.events = EPOLLIN;
    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, socket->sockfd, &ev);
}

void ATPContextServer::deregister_listen_port(uint16_t host_port) {
    std::map<uint16_t, ATPSocket *>::iterator iter = listen_sockets.find(host_port);
    if (iter != listen_sockets.end()) {
        listen_sockets.erase(iter);

        ev.data.fd = iter->second->sockfd;
        epoll_ctl(epoll_fd, EPOLL_CTL_DEL, iter->second->sockfd, &ev);
    }
}

void ATPContextServer::init_server() {
    epoll_fd = epoll_create(event_size);
    events = new epoll_event[event_size];
}

void ATPContextServer::start_server() {
    ths = std::thread([&]() {
        while (true) {
            if (main_loop() == ATP_PROC_FINISH) {
                break;
            }
        }
    });
    ths.detach();
}

void ATPContextServer::destroy_server() {
    close(epoll_fd);
    delete [] events;
}

ATP_PROC_RESULT ATPContextServer::daily_routine(){
    ATPContext::daily_routine();
    if (this->finished())
    {
        std::unique_lock<std::mutex> lk(this->mtx);
        this->cv.notify_all();
    }
}

ATP_PROC_RESULT ATPContextServer::main_loop() {
    int nfds = epoll_wait(epoll_fd, events, event_size, timeout);
    if (nfds < 0) {

    } else if (nfds == 0) {
        if (atp_timer_event(this, 1000) == ATP_PROC_FINISH) return ATP_PROC_FINISH;
    } else {
        for (int i = 0; i < nfds; ++i)
        {
            if (events[i].events & EPOLLIN)
            {
                int sockfd = events[i].data.fd;
                if (sockfd < 0)
                    continue;
                int n;
                struct sockaddr_in cli_addr; socklen_t cli_len = sizeof(cli_addr);
                n = recvfrom(sockfd, buffer, ATP_SERVER_BUFFER_SIZE, 0, (SA *)&cli_addr, &cli_len);

                if (n < 0)
                {
                    // Socket Recv Error
                } else if (n == 0){
                    // Socket Recv Error
                } else {
                    ATP_PROC_RESULT result = atp_process_udp(this, sockfd, buffer, n, (const SA *)&cli_addr, cli_len);
                    if (result == ATP_PROC_FINISH) return ATP_PROC_FINISH;
                }
                // Reset epoll events
                ev.events = EPOLLIN;
                int ans = epoll_ctl(epoll_fd, EPOLL_CTL_ADD, sockfd, &ev);
            }
        }
    }
}

atp_context * atp_create_context_server() {
    atp_context * context = new ATPContextServer();
    return context;
}

atp_socket * atp_fork_blocked_socket(atp_socket * origin){
    atp_context_server * con = dynamic_cast<atp_context_server *>(origin->context);
    return nullptr;
}

void atp_start_server(atp_context * context) {
    atp_context_server * con = dynamic_cast<atp_context_server *>(context);
    con->start_server();
}

void atp_wait_server(atp_context * context){
    // Wait until there's no task in the server, which requires
    // 1. No socket is possessed by server's context
    // 2. No fd is monitored by server's context
    atp_context_server * con = dynamic_cast<atp_context_server *>(context);
    assert(con != nullptr);

    std::unique_lock <std::mutex> lk(con->mtx);
    while (!(con->finished())) {
        con->cv.wait(lk, [&]() {
            return con->finished();
        });
    }
    con->destroy_server();
}

atp_socket * atp_create_blocked_socket(atp_context * context) {
    atp_context_server * con = dynamic_cast<atp_context_server *>(context);

    atp_blocked_socket * socket = new ATPBlockedSocket(con);
    int sockfd = socket->init(AF_INET, SOCK_DGRAM, 0);
    con->sockets.push_back(socket);

    return socket;
}

ATP_PROC_RESULT atp_blocked_connect(atp_socket * socket, const struct sockaddr * to, socklen_t tolen) {
    atp_blocked_socket * sock = dynamic_cast<atp_blocked_socket *>(socket);
    assert(sock != nullptr);

    // Register sockfd to epoll manually is IMPORTANT.
    // In `atp_blocked_accept`, function `register_listen_port` will help you do that.
    atp_context_server * con = dynamic_cast<atp_context_server *>(sock->context);
    assert(con != nullptr);
    con->ev.data.fd = socket->sockfd;
    con->ev.events = EPOLLIN;
    epoll_ctl(con->epoll_fd, EPOLL_CTL_ADD, socket->sockfd, &(con->ev));

    ATPAddrHandle handle(to);
    sock->connect(to);
    std::unique_lock <std::mutex> lk(sock->mtx);
    while (!(sock->conn_state >= CS_CONNECTED)) {
        sock->cv.wait(lk, [&]() {
            return sock->conn_state >= CS_CONNECTED;
        });
    }
    if (sock->conn_state >= CS_CONNECTED)
    {
        return ATP_PROC_OK;
    } else if (sock->conn_state == CS_DESTROY) {
        return ATP_PROC_FINISH;
    }
    else {
        return ATP_PROC_WAIT;
    }
}

ATP_PROC_RESULT atp_blocked_accept(atp_socket * socket) {
    atp_blocked_socket * sock = dynamic_cast<atp_blocked_socket *>(socket);
    assert(sock != nullptr);

    std::unique_lock <std::mutex> lk(sock->mtx);
    while (! (sock->conn_state >= CS_SYN_RECV)) {
        sock->cv.wait(lk, [&]() {
            return sock->conn_state >= CS_SYN_RECV;
        });
    }
    if (sock->conn_state >= CS_SYN_RECV)
    {
        return ATP_PROC_OK;
    } else if (sock->conn_state == CS_DESTROY) {
        return ATP_PROC_FINISH;
    } else {
        return ATP_PROC_WAIT;
    }
}

ATP_PROC_RESULT atp_blocked_close(atp_socket * socket) {
    atp_blocked_socket * sock = dynamic_cast<atp_blocked_socket *>(socket);
    assert(sock != nullptr);

    if (sock == nullptr) return ATP_PROC_ERROR;
    #if defined (ATP_LOG_AT_DEBUG)
    log_debug(sock, "User called atp_close");
    #endif
    sock->close();
    std::unique_lock <std::mutex> lk(sock->mtx);
    while (!sock->eof()) {
        sock->cv.wait(lk, [&]() {
            return sock->eof();
        });
    }
    if (sock->eof())
    {
        return ATP_PROC_FINISH;
    } else {
        return ATP_PROC_WAIT;
    }
}

ATP_PROC_RESULT atp_blocked_read(atp_socket * socket, void * buffer, size_t n){
    atp_blocked_socket * sock = dynamic_cast<atp_blocked_socket *>(socket);
    assert(sock != nullptr);

    auto old_on_recv = sock->callbacks[ATP_CALL_ON_RECV];
    size_t actual_size = 0;

    sock->callbacks[ATP_CALL_ON_RECV] = [&](atp_callback_arguments * args){
        atp_blocked_socket * sock = dynamic_cast<atp_blocked_socket *>(args->socket);
        assert(sock != nullptr);

        actual_size = args->length; 
        const char * data = args->data;

        std::memcpy(buffer, data, std::min(actual_size, n));

        #if defined (ATP_LOG_AT_DEBUG)
        log_debug(sock, "Server Recv %u of data \n", actual_size);
        #endif

        std::unique_lock<std::mutex> lk(sock->mtx);
        sock->cv.notify_all();

        return std::min(actual_size, n);
    };

    std::unique_lock<std::mutex> lk(sock->mtx);
    ATP_PROC_RESULT result = ATP_PROC_ERROR;
    while (! (actual_size > 0 || sock->eof())) {
        sock->cv.wait(lk, [&]() {
            return actual_size > 0 || sock->eof();
        });
    }
    if (actual_size > 0)
    {
        result = std::min(actual_size, n);
    } 
    if (sock->eof()){
        result = ATP_PROC_FINISH;
    }

    sock->callbacks[ATP_CALL_ON_RECV] = old_on_recv;
    return result;
}
