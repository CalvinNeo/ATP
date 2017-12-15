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

int main(){
    uint16_t serv_port = 9876;
    struct sockaddr_in cli_addr; 
    struct sockaddr_in srv_addr; socklen_t srv_len = sizeof(srv_addr);

    char msg[ATP_MAX_READ_BUFFER_SIZE];
    char textmsg[ATP_MIN_BUFFER_SIZE];
    int n;

    atp_context * context = atp_init();
    atp_socket * socket = atp_create_socket(context);
    int sockfd = atp_getfd(socket);


    // char ip_addr_str[1000]; // "172.19.143.183"
    // printf("please input dest ip_addr\n");
    // scanf("%s", ip_addr_str);
    srv_addr = make_socketaddr_in(AF_INET, "127.0.0.1", serv_port);
    int res = atp_connect(socket, (const SA *)&srv_addr, sizeof srv_addr);
    if(res != ATP_PROC_OK){
        printf("Connection Abort.\n");
        return 0;
    }

    FILE * fin = fopen("in.dat", "r");
    while (true) {
        sockaddr * psock_addr = (SA *)&srv_addr;
        if ((n = recvfrom(sockfd, msg, ATP_MAX_READ_BUFFER_SIZE, 0, psock_addr, &srv_len)) >= 0){
            ATP_PROC_RESULT result = atp_process_udp(context, sockfd, msg, n, (const SA *)&srv_addr, srv_len);
            if (result == ATP_PROC_FINISH )
            {
                break;
            }
        }else{
            if(!(errno == EINTR || errno == EWOULDBLOCK || errno == EAGAIN)) break;
        }
        if(fgets(textmsg, ATP_MIN_BUFFER_SIZE, fin) == NULL){
            if (feof(fin)){
                atp_close(socket);
                break;
            }else{
                continue;
            }
        }
        n = strlen(textmsg);
        atp_write(socket, textmsg, n);
    }
    fclose(fin);
    return 0;
};