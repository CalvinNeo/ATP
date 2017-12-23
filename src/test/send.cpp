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

    atp_context * context = atp_create_context();
    atp_socket * socket = atp_create_socket(context);
    int sockfd = atp_getfd(socket);

    srv_addr = make_socketaddr_in(AF_INET, "127.0.0.1", serv_port);
    if(atp_connect(socket, (const SA *)&srv_addr, sizeof srv_addr) != ATP_PROC_OK){
        puts("Connection Abort.");
    }

    while (true) {
        sockaddr * psock_addr = (SA *)&srv_addr;
        // MUST firstly run `atp_process_udp`, then run fgets.
        // if inverse this order, then `atp_process_udp` will always need to re-send the last packet sent by `atp_write`
        // because peer can't immediately send back an ACK
        if ((n = recvfrom(sockfd, msg, ATP_MAX_READ_BUFFER_SIZE, 0, psock_addr, &srv_len)) >= 0){
            ATP_PROC_RESULT result = atp_process_udp(context, sockfd, msg, n, (const SA *)&srv_addr, srv_len);
            if (result == ATP_PROC_FINISH )
            {
                // peer closed message, this would never happen, because I'm always the first to close
                // even if peer terminates, don't need to call `atp_close` or `atp_async_close` here, 
                // because already handled in callback ATP_CALL_ON_PEERCLOSE
                break;
            }
        }else{
            if(!(errno == EINTR || errno == EWOULDBLOCK || errno == EAGAIN)) break;
        }
        if(fgets(textmsg, ATP_MIN_BUFFER_SIZE, stdin) == NULL){
            if (feof(stdin)){
                atp_close(socket);
                break;
            }else{
                continue;
            }
        }
        n = strlen(textmsg);
        atp_write(socket, textmsg, n);
    }
    delete context; context = nullptr;
    return 0;
};