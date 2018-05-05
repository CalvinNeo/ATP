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
#include "atp_impl.h" // For debugging use
#include "test.inc.h"

int main(int argc, char* argv[], char* env[]){
    uint16_t serv_port = 9876;
    struct sockaddr_in cli_addr; 
    struct sockaddr_in srv_addr; socklen_t srv_len = sizeof(srv_addr);

    char msg[ATP_MAX_READ_BUFFER_SIZE];
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
    atp_socket * socket = atp_create_socket(context);
    int sockfd = atp_getfd(socket);

    atp_set_callback(socket, ATP_CALL_SENDTO, normal_sendto);

    srv_addr = make_socketaddr_in(AF_INET, "127.0.0.1", serv_port);
    if(atp_standalone_connect(socket, (const SA *)&srv_addr, sizeof srv_addr) != ATP_PROC_OK){
        puts("Connection Abort.");
    }


    struct pollfd pfd[2];
    while (true) {
        pfd[0].fd = sockfd;
        pfd[0].events = POLLIN;

        pfd[1].fd = STDIN_FILENO;
        pfd[1].events = POLLIN;


        int ret = poll(pfd, 2, 1000);
        size_t n;

        if (ret < 0) {
        }
        else if (ret == 0) {
            if(atp_timer_event(context, 1000) == ATP_PROC_FINISH){
                break;
            }
        }
        else {
            if ((pfd[0].revents & POLLIN) == POLLIN) {
                sockaddr * psock_addr = (SA *)&srv_addr;
                if ((n = recvfrom(sockfd, msg, ATP_MAX_READ_BUFFER_SIZE, 0, psock_addr, &srv_len)) >= 0){
                    ATP_PROC_RESULT result = atp_process_udp(context, sockfd, msg, n, (const SA *)&srv_addr, srv_len);
                    if (result == ATP_PROC_FINISH){
                        break;
                    } 
                }
            }
            if ((pfd[1].revents & POLLIN) == POLLIN) {
                int n; 
                char sendmsg[ATP_MIN_BUFFER_SIZE];

                // `fread` function reads until EOF
                n = fread(&sendmsg, 1, ATP_MIN_BUFFER_SIZE, stdin);
                // n = fscanf(stdin, "%s\n", &sendmsg);
                if(n > 0){
                    if (simulate_packet)
                    {
                        char * start = strtok(sendmsg, "\n");
                        while(start){
                            send_sim(socket, start);
                            start = strtok(0, "\n");
                        }
                    }else{
                        n = strlen(sendmsg);
                        printf("send msg %s\n", sendmsg);
                        atp_async_write(socket, sendmsg, n);
                    }
                }
            }else if((pfd[1].revents & POLLHUP) == POLLHUP){
                break;
            }
        }
    }

    atp_standalone_close(socket);
    delete context; context = nullptr;
    return 0;
};