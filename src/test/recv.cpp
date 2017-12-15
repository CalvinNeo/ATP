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
#include "../atp.h"
#include "../udp_util.h"
#include <iostream>

ATP_PROC_RESULT data_arrived(atp_callback_arguments * args){
    atp_socket * socket = args->socket;
    size_t length = args->length; 
    const char * data = args->data;

    printf("data arrived: %.*s\n", length, data);
    return ATP_PROC_OK;
}

int main(){
    uint16_t serv_port = 9876;
    struct sockaddr_in cli_addr; socklen_t cli_len = sizeof(cli_addr);
    struct sockaddr_in srv_addr;

    char msg[ATP_MAX_READ_BUFFER_SIZE];
    int n;

    atp_context * context = atp_init();
    atp_socket * socket = atp_create_socket(context);
    int sockfd = atp_getfd(socket);
    atp_set_callback(socket, ATP_CALL_ON_RECV, data_arrived);

    srv_addr = make_socketaddr_in(AF_INET, nullptr, serv_port);

    if (bind(sockfd, (SA *) &srv_addr, sizeof srv_addr) < 0)
        err_sys("bind error");

    atp_listen(socket, serv_port);
    if(atp_accept(socket) != ATP_PROC_OK){
        puts("Connection Abort.");
    }

    while (true) {
        sockaddr * pcli_addr = (SA *)&cli_addr;

        if ((n = recvfrom(sockfd, msg, ATP_MAX_READ_BUFFER_SIZE, 0, pcli_addr, &cli_len)) < 0){
            if(!(errno == EINTR || errno == EWOULDBLOCK || errno == EAGAIN)) break; else continue;
        }
        ATP_PROC_RESULT result = atp_process_udp(context, sockfd, msg, n, (const SA *)&cli_addr, cli_len);
        if (result == ATP_PROC_FINISH)
        {
            break;
        }
    }
    return 0;
}