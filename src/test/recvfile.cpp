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
#include "../scaffold.h"
#include "test.inc.h"
#include <unistd.h>

FILE * fout;

ATP_PROC_RESULT data_arrived(atp_callback_arguments * args){
    atp_socket * socket = args->socket;
    size_t length = args->length; 
    const char * data = args->data;

    fwrite(data, 1, length, fout);
    return ATP_PROC_OK;
}

ATP_PROC_RESULT urg_msg_arrived(atp_callback_arguments * args){
    atp_socket * socket = args->socket;
    size_t length = args->length; 
    const char * data = args->data;
    printf("URG: ");
    fwrite(data, 1, length, stdout);
    return ATP_PROC_OK;
};

int main(int argc, char* argv[], char* env[]){
    int oc;
    bool simulate_loss = false;
    bool simulate_delay = false;
    uint16_t serv_port = 9876;
    uint16_t cli_port = 0;
    char output_file_name[255] = "out.dat";
    uint16_t sock_id = 0;
    while((oc = getopt(argc, argv, "o:l:p:s:P:d:")) != -1)
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
        case 'o':
            strcpy(output_file_name, optarg);
            break;
        case 's':
            sscanf(optarg, "%u", &sock_id);
            break;
        }
    }
    reg_sigterm_handler(sigterm_handler);
    fout = fopen(output_file_name, "wb");

    struct sockaddr_in cli_addr; socklen_t cli_len = sizeof(cli_addr);
    struct sockaddr_in srv_addr;

    char msg[ATP_MAX_READ_BUFFER_SIZE];
    int n;

    atp_context * context = atp_create_context();
    atp_socket * socket = atp_create_socket(context);
    if(sock_id != 0){atp_set_long(socket, ATP_API_SOCKID, sock_id); }
    
    int sockfd = atp_getfd(socket);
    atp_set_callback(socket, ATP_CALL_ON_RECV, data_arrived);
    atp_set_callback(socket, ATP_CALL_ON_RECVURG, urg_msg_arrived);

    if(simulate_loss){
        atp_set_callback(socket, ATP_CALL_SENDTO, simulate_packet_loss_sendto);
    }
    if(simulate_delay){
        atp_set_callback(socket, ATP_CALL_SENDTO, simulate_delayed_sendto);
    }
    if(!simulate_delay && !simulate_loss){
        atp_set_callback(socket, ATP_CALL_SENDTO, normal_sendto);
    }

    srv_addr = make_socketaddr_in(AF_INET, nullptr, serv_port);

    if (bind(sockfd, (SA *) &srv_addr, sizeof srv_addr) < 0)
        err_sys("bind error");
    atp_listen(socket, serv_port);
    if(atp_accept(socket) != ATP_PROC_OK){
        puts("Connection Abort.");
        return 0;
    }
    bool file_open = true;
    ATP_PROC_RESULT result;
    while (true) {
        sockaddr * pcli_addr = (SA *)&cli_addr;
        if ((n = recvfrom(sockfd, msg, ATP_MAX_READ_BUFFER_SIZE, 0, pcli_addr, &cli_len)) < 0){
            if(!(errno == EINTR || errno == EWOULDBLOCK || errno == EAGAIN)) {
                break; 
            }
            if(atp_timer_event(context, 1000) == ATP_PROC_FINISH){
                // Context finished, mission completed, quit
                break;
            }
        }else{
            result = atp_process_udp(context, sockfd, msg, n, (const SA *)&cli_addr, cli_len);
        }
        if (atp_eof(socket))
        {
            if (file_open)
            {
                fclose(fout);
            }
            file_open = false;
        }
        if (result == ATP_PROC_FINISH)
        {
            break;
        }
    }
    puts("Quit.");
    delete context; context = nullptr;
    return 0;
}