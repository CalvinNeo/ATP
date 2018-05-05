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
#include "atp_standalone.h"
#include "udp_util.h"
#include "test.inc.h"
#include <iostream>
#include <thread>
#include <unistd.h>

std::vector<atp_socket *> valid_sockets;
int sockfd = 0;
ATP_PROC_RESULT data_arrived(atp_callback_arguments * args){
    atp_socket * socket = args->socket;
    size_t length = args->length; 
    const char * data = args->data;

    printf("data arrived: %.*s\n", length, data);
    return ATP_PROC_OK;
}

ATP_PROC_RESULT before_rep_accept(atp_callback_arguments * args){
    return ATP_PROC_OK;
}

ATP_PROC_RESULT on_fork(atp_callback_arguments * args){
    printf("Fork socket.\n");
    args->socket = atp_fork_socket(args->socket);
    atp_set_callback(args->socket, ATP_CALL_ON_RECV, data_arrived);
    valid_sockets.push_back(args->socket);
}
void connect_loop(atp_context * context, uint16_t serv_port){
    atp_socket * socket;
    if(sockfd == 0){
        socket = atp_create_socket(context);
        atp_set_long(socket, ATP_API_REUSEPORT, true);
    }
    atp_set_callback(socket, ATP_CALL_ON_RECV, data_arrived);
    atp_set_callback(socket, ATP_CALL_BEFORE_REP_ACCEPT, before_rep_accept);
    atp_set_callback(socket, ATP_CALL_ON_FORK, on_fork);
    

    if (sockfd == 0){
        sockfd = atp_getfd(socket);
        struct sockaddr_in srv_addr;
        srv_addr = make_socketaddr_in(AF_INET, nullptr, serv_port);

        int opt = 1;
        setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (const void *)&opt, sizeof(opt));

        if(bind(sockfd, (SA *) &srv_addr, sizeof srv_addr) < 0)
            printf("bind error: %s", strerror(errno));
    }
    atp_listen(socket, serv_port);
    if(atp_standalone_accept(socket) != ATP_PROC_OK){
        puts("Connection Abort.");
    }
    valid_sockets.push_back(socket);
}

void message_loop(atp_context * context){
    char msg[ATP_MAX_READ_BUFFER_SIZE];
    struct sockaddr_in cli_addr; socklen_t cli_len = sizeof(cli_addr);
    struct pollfd pfd[1];
    bool stdin_hup = false;
    while (true) {

        pfd[0].fd = sockfd;
        pfd[0].events = POLLIN;

        int ret = poll(pfd, 1, 1000);
        size_t n;

        if (ret < 0) {
            // break;
        }
        else if (ret == 0) {
            if(atp_timer_event(context, 1000) == ATP_PROC_FINISH){
                break;
            }
        }
        else {
            if ((pfd[0].revents & POLLIN) == POLLIN) {
                sockaddr * psock_addr = (SA *)&cli_addr;
                int fd = sockfd;
                n = recvfrom(fd, msg, ATP_MIN_BUFFER_SIZE, 0, psock_addr, &cli_len);
                ATP_PROC_RESULT result = atp_process_udp(context, fd, msg, n, psock_addr, cli_len);
                if (result == ATP_PROC_FINISH)
                {
                    break;
                }
            }
        }
    }
}

int main(int argc, char* argv[], char* env[]){
    using namespace std::chrono_literals;
    uint16_t serv_port = 9876;

    int n;
    bool simulate_packet = false;
    int oc;

    while((oc = getopt(argc, argv, "p:s")) != -1)
    {
        switch(oc)
        {
        case 'p':
            sscanf(optarg, "%u", &serv_port);
            break;
        case 's':
            simulate_packet = true;
            break;
        }
    }

    reg_sigterm_handler(sigterm_handler);
    atp_context * context = atp_create_context();

    connect_loop(context, serv_port);
    message_loop(context);

    delete context; context = nullptr;

    return 0;
}