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
#include "atp_impl.h"
#include <unistd.h>

int main(int argc, char* argv[], char* env[]){
    int oc;
    bool simulate_loss = false;
    bool simulate_delay = false;
    uint16_t serv_port = 9876;
    uint16_t cli_port = 0;
    char input_file_name[255] = "in.dat";
    uint16_t sock_id = 0;
    while((oc = getopt(argc, argv, "i:l:p:s:P:d:")) != -1)
    {
        switch(oc)
        {
        case 'd':
            sscanf(optarg, "%u", &delay_time);
            simulate_delay = true;
            break;
        case 'l':
            sscanf(optarg, "%lf", &loss_rate);
            simulate_loss = true;
            break;
        case 'p':
            sscanf(optarg, "%u", &serv_port);
            break;
        case 'P':
            sscanf(optarg, "%u", &cli_port);
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

    char recv_msg[ATP_MIN_BUFFER_SIZE];
    char send_msg[ATP_MIN_BUFFER_SIZE];
    char ipaddr_str[INET_ADDRSTRLEN];
    int n;

    reg_sigterm_handler(sigterm_handler);
    atp_context * context = atp_create_context();
    atp_socket * socket = atp_create_socket(context);
    int sockfd = atp_getfd(socket);

    if(simulate_loss){
        atp_set_callback(socket, ATP_CALL_SENDTO, simulate_packet_loss_sendto);
    }
    if(simulate_delay){
        atp_set_callback(socket, ATP_CALL_SENDTO, simulate_delayed_sendto);
    }
    if(!simulate_delay && !simulate_loss){
        atp_set_callback(socket, ATP_CALL_SENDTO, normal_sendto);
    }

    // activate_nonblock(STDIN_FILENO);
    // activate_nonblock(sockfd);

    srv_addr = make_socketaddr_in(AF_INET, "127.0.0.1", serv_port);
    atp_async_connect(socket, (const SA *)&srv_addr, sizeof srv_addr);

    FILE * fin = fopen(input_file_name, "rb");
    FileObject fin_obj {fin, ATP_MIN_BUFFER_SIZE};
    int fd_in = fileno(fin);

    struct pollfd pfd[3];
    bool stdin_hup = false;
    while (true) {
        pfd[0].fd = fd_in;
        pfd[0].events = fin_obj.eof() ? 0: POLLIN;

        pfd[1].fd = sockfd;
        pfd[1].events = POLLIN;

        pfd[2].fd = STDIN_FILENO;
        pfd[2].events = feof(stdin) ? 0: POLLIN;

        if(feof(stdin)){
            stdin_hup = true;
            printf("stdin closed %llu\n", get_current_ms());
        }
        if(fin_obj.eof() && stdin_hup){
            printf("all closed %llu\n", get_current_ms());
            atp_standalone_close(socket);
            break;
        }

        int ret = poll(pfd, 3, 1000);
        size_t n;

        if (ret < 0) {
            break;
        }
        else if (ret == 0) {
            if(atp_timer_event(context, 1000) == ATP_PROC_FINISH) break;
        }
        else {
            if ((pfd[0].revents & POLLIN) == POLLIN) {
                char * buffer = fin_obj.get(n);
                if(n == 0 || !atp_get_long(socket, ATP_API_WRITABLE)){

                }else{
                    atp_result r = atp_async_write(socket, buffer, n);
                    if (r > 0)
                    {
                        // r == 0 or r < 0 means error
                        fin_obj.ack_by_n(r);
                    }
                }
            }
            if ((pfd[1].revents & POLLIN) == POLLIN) {
                sockaddr * psock_addr = (SA *)&srv_addr;
                n = recvfrom(sockfd, recv_msg, ATP_MIN_BUFFER_SIZE, 0, psock_addr, &srv_len);
                if (n < 0) puts("err");
                ATP_PROC_RESULT result = atp_process_udp(context, sockfd, recv_msg, n, (const SA *)&srv_addr, srv_len);
                if (result == ATP_PROC_FINISH) break;
            }
            if ((pfd[2].revents & POLLIN) == POLLIN) {
                // n = fread(&send_msg, 1, ATP_MIN_BUFFER_SIZE, stdin);
                n = fread(&send_msg, 1, ATP_MIN_BUFFER_SIZE, stdin);
                if(n == 0){
                    if(feof(stdin)){
                        stdin_hup = true;
                    }
                }else{
                    printf("send urg data[%u]: %.*s \n", n, n, send_msg);
                    // The urgent message is request to be sent to peer within 1000ms
                    atp_send_oob(socket, send_msg, n, 1000);
                    fflush(stdin);
                    fflush(stdout);
                }
            }else if((pfd[2].revents & POLLHUP) == POLLHUP){
                stdin_hup = true;
                printf("stdin hup at time %llu\n", get_current_ms());
            }
        }
    }
    fclose(fin);
    puts("Quit.");
    delete context; context = nullptr;
    return 0;
};