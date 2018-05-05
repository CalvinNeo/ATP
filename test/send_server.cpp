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

    srv_addr = make_socketaddr_in(AF_INET, "127.0.0.1", serv_port);
    if(atp_blocked_connect(socket, (const SA *)&srv_addr, sizeof srv_addr) != ATP_PROC_OK){
        puts("Connection Abort.");
    }

    puts("Connection Established.");
    size_t n;
    char sendmsg[ATP_MIN_BUFFER_SIZE];
    while(~scanf("%s", &sendmsg)){
        n = strlen(sendmsg);
        printf("send msg %s\n", sendmsg);
        atp_async_write(socket, sendmsg, n);
    }
    atp_blocked_close(socket);
    atp_wait_server(context);
    puts("Quit.");
}