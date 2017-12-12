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
#include "../atp_impl.h"

void activate_nonblock(int fd)
{
    int ret;
    int flags = fcntl(fd, F_GETFL);
    if (flags == -1)
        err_sys("fcntl");
    flags |= O_NONBLOCK;
    ret = fcntl(fd, F_SETFL, flags);
    if (ret == -1)
        err_sys("fcntl");
}


int main(){
    uint16_t serv_port = 9876;
    struct sockaddr_in cli_addr; 
    struct sockaddr_in srv_addr; socklen_t srv_len = sizeof(srv_addr);

    char msg[ATP_MIN_BUFFER_SIZE];
    char ipaddr_str[INET_ADDRSTRLEN];
    int n;

    atp_context * context = atp_init();
    atp_socket * socket = atp_create_socket(context);
    int sockfd = atp_getfd(socket);

    // activate_nonblock(STDIN_FILENO);
    // activate_nonblock(sockfd);

    srv_addr = make_socketaddr_in(AF_INET, "127.0.0.1", serv_port);
    atp_async_connect(socket, (const SA *)&srv_addr, sizeof srv_addr);

    struct pollfd pfd[2];
    bool closed = false;
    while (true) {
        pfd[0].fd = STDIN_FILENO;
        if (feof(stdin))
        {
            if(!closed)
                atp_async_close(socket);
            closed = true;
        }
        pfd[0].events = feof(stdin) ? 0: POLLIN;

        pfd[1].fd = sockfd;
        pfd[1].events = POLLIN;

        int ret = poll(pfd, 2, 1000);
        size_t n;

        if (ret < 0) {
            break;
        }
        else if (ret == 0) {
            if(atp_timer_event(context, 1000) == ATP_PROC_FINISH){
                break;
            }
        }
        else {
            if ((pfd[0].revents & POLLIN) == POLLIN) {
                fgets(msg, ATP_MIN_BUFFER_SIZE, stdin);
                if (!feof(stdin))
                {
                    n = strlen(msg);
                    atp_write(socket, msg, n);
                }
            }
            if ((pfd[1].revents & POLLIN) == POLLIN) {
                sockaddr * psock_addr = (SA *)&srv_addr;
                if ((n = recvfrom(sockfd, msg, ATP_MIN_BUFFER_SIZE, 0, psock_addr, &srv_len)) < 0)
                    puts("err");
                ATP_PROC_RESULT result = atp_process_udp(context, sockfd, msg, n, (const SA *)&srv_addr, srv_len);
                if (result == ATP_PROC_FINISH)
                {
                    break;
                }
            }
        }

    }
    return 0;
};