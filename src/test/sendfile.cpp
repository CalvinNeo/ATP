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
#include "test.h"
#include <unistd.h>

int main(int argc, char* argv[], char* env[]){
    int oc;
    bool simulate_loss = false;
    uint16_t serv_port = 9876;
    char input_file_name[255] = "in.dat";
    uint16_t sock_id = 0;
    while((oc = getopt(argc, argv, "i:lp:s:")) != -1)
    {
        switch(oc)
        {
        case 'l':
            simulate_loss = true;
            break;
        case 'p':
            sscanf(optarg, "%u", &serv_port);
            break;
        case 'i':
            strcpy(input_file_name, optarg);
            break;
        case 's':
            sscanf(optarg, "%u", &sock_id);
            break;
        }
    }
    struct sockaddr_in cli_addr; 
    struct sockaddr_in srv_addr; socklen_t srv_len = sizeof(srv_addr);

    char msg[ATP_MAX_READ_BUFFER_SIZE];
    char textmsg[ATP_MIN_BUFFER_SIZE];
    int n;

    atp_context * context = atp_create_context();
    atp_socket * socket = atp_create_socket(context);
    if(sock_id != 0){atp_set_long(socket, ATP_API_SOCKID, sock_id); }
    int sockfd = atp_getfd(socket);
    if(simulate_loss){
        atp_set_callback(socket, ATP_CALL_SENDTO, simulate_packet_loss_sendto);
    }else{
        atp_set_callback(socket, ATP_CALL_SENDTO, normal_sendto);
    }

    // char ip_addr_str[1000]; // "172.19.143.183"
    // printf("please input dest ip_addr\n");
    // scanf("%s", ip_addr_str);
    srv_addr = make_socketaddr_in(AF_INET, "127.0.0.1", serv_port);
    int res = atp_connect(socket, (const SA *)&srv_addr, sizeof srv_addr);
    if(res != ATP_PROC_OK){
        printf("Connection Abort.\n");
        return 0;
    }

    FILE * fin = fopen(input_file_name, "rb");
    while (true) {
        sockaddr * psock_addr = (SA *)&srv_addr;
        if ((n = recvfrom(sockfd, msg, ATP_MAX_READ_BUFFER_SIZE, 0, psock_addr, &srv_len)) >= 0){
            ATP_PROC_RESULT result = atp_process_udp(context, sockfd, msg, n, (const SA *)&srv_addr, srv_len);
            if (result == ATP_PROC_FINISH)
            {
                // `atp_process_udp` called `atp_timer_event` which returned ATP_PROC_FINISH
                break;
            }
        }else{
            if(!(errno == EINTR || errno == EWOULDBLOCK || errno == EAGAIN)) break;
            if(atp_timer_event(context, 1000) == ATP_PROC_FINISH){
                // Context finished, mission completed, quit
                break;
            }
        }
        if(!feof(fin)){
            size_t nn = fread(&textmsg, 1, ATP_MIN_BUFFER_SIZE, fin);
            if(nn == 0){
                continue;
            }else{
                atp_write(socket, textmsg, nn);
            }
        }else{
            if (atp_sending_status(socket) == ATP_PROC_OK)
            {
                // all packets are ACKed
                puts("Trans Finished");
                atp_close(socket);
                break;
            }
        }
    }
    fclose(fin);
    puts("Quit.");
    delete context; context = nullptr;
    return 0;
};