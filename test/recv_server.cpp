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
#include "atp_svc.h"
#include "udp_util.h"
#include "test.inc.h"
#include <iostream>
#include <cstdio>

const size_t buffer_size = 10000;
char buffer[buffer_size];

int main(int argc, char* argv[], char* env[]){
    uint16_t serv_port = 9876;
    struct sockaddr_in cli_addr; socklen_t cli_len = sizeof(cli_addr);
    struct sockaddr_in srv_addr;

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
    atp_context * context = atp_create_context_server();
    atp_start_server(context);

    atp_socket * socket = atp_create_blocked_socket(context);
    int sockfd = atp_getfd(socket);

    srv_addr = make_socketaddr_in(AF_INET, nullptr, serv_port);

    if (bind(sockfd, (SA *) &srv_addr, sizeof srv_addr) < 0)
        err_sys("bind error");

    atp_listen(socket, serv_port);

    if(atp_blocked_accept(socket) != ATP_PROC_OK){
        puts("Connection Abort.");
    }else{
        puts("Connection established.");
    }

    atp_result result;
    while(result = atp_blocked_read(socket, buffer, buffer_size)){
        if (result > 0)
        {
            puts("Data:");
            printf("%.*s\n", result, buffer);
        }else if(result == ATP_PROC_FINISH){
            puts("Recv Finished.");
            break;
        }else{
            puts("Error.");
            break;
        }
    }

    atp_wait_server(context);
    puts("Quit.");
}