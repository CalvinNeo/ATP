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
#pragma once
#include "atp_svc.h"
#include "atp_impl.h"
#include "udp_util.h"
#include <sys/epoll.h>
#include <mutex>
#include <thread>
#include <condition_variable>

#define ATP_SERVER_MAX_LISTEN 100
#define ATP_SERVER_BUFFER_SIZE 65536

struct ATPContextServer : public ATPContext{
    ATPContextServer(){
        init_server();
    }

    virtual ATP_PROC_RESULT daily_routine() override;
    virtual ATP_PROC_RESULT register_listen_port(ATPSocket * socket, uint16_t host_port) override;
    virtual void deregister_listen_port(uint16_t host_port) override;

    ATP_PROC_RESULT main_loop();

    void init_server();
    void start_server();
    void destroy_server();

public:
    struct epoll_event * events;
    int event_size = ATP_SERVER_MAX_LISTEN, epoll_fd;
    int timeout = 500;
    struct epoll_event ev;
    char buffer[ATP_SERVER_BUFFER_SIZE];
    std::thread ths;
    
    std::mutex mtx;
    std::condition_variable cv;
};

struct ATPBlockedSocket : public ATPSocket{
    ATPBlockedSocket(ATPContext * context) : ATPSocket(context){
        
    }

    virtual ATPSocket * fork_me() override{
        ATPSocket * socket = new ATPBlockedSocket(context);
        int sockfd = socket->init_fork(this);
        context->sockets.push_back(socket);
        return socket;
    }

    virtual void switch_state(CONN_STATE_ENUM new_state) override{
        conn_state = new_state;
        // When interesting event occured, trigger cv.
        // For blocked read, refer to `atp_blocked_read`
        switch (new_state)
        {
            case CS_CONNECTED: // Connection established
            case CS_PASSIVE_LISTEN: // Connection closed on a dominant socket
            case CS_DESTROY: // Connection closed on a non-dominant socket
                std::unique_lock<std::mutex> lk(mtx);
                cv.notify_all();
        }
    }

    std::mutex mtx;
    std::condition_variable cv;
};