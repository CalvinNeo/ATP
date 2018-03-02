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
#include "test.inc.h"
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
    struct sockaddr_in srv_addr; socklen_t srv_len = sizeof(srv_addr);

    char recv_msg[ATP_MAX_READ_BUFFER_SIZE];
    int n;

    reg_sigterm_handler(sigterm_handler);
    atp_context * context = atp_create_context();
    atp_socket * socket = atp_create_socket(context);
    if(sock_id != 0){atp_set_long(socket, ATP_API_SOCKID, sock_id); }
    int sockfd = atp_getfd(socket);

    if(cli_port != 0){
        struct sockaddr_in cli_addr = make_socketaddr_in(AF_INET, "127.0.0.1", cli_port); 
        if (bind(sockfd, (SA *) &cli_addr, sizeof cli_addr) < 0)
            err_sys("bind error");
    }


    if(simulate_loss){
        atp_set_callback(socket, ATP_CALL_SENDTO, simulate_packet_loss_sendto);
    }
    if(simulate_delay){
        atp_set_callback(socket, ATP_CALL_SENDTO, simulate_delayed_sendto);
    }
    if(!simulate_delay && !simulate_loss){
        atp_set_callback(socket, ATP_CALL_SENDTO, normal_sendto);
    }

    srv_addr = make_socketaddr_in(AF_INET, "127.0.0.1", serv_port);
    int res = atp_connect(socket, (const SA *)&srv_addr, sizeof srv_addr);
    if(res != ATP_PROC_OK){
        printf("Connection Abort.\n");
        return 0;
    }

    FILE * fin = fopen(input_file_name, "rb");
    FileObject fin_obj {fin, ATP_MIN_BUFFER_SIZE};
    while (true) {
        sockaddr * psock_addr = (SA *)&srv_addr;
        if ((n = recvfrom(sockfd, recv_msg, ATP_MAX_READ_BUFFER_SIZE, 0, psock_addr, &srv_len)) >= 0){
            ATP_PROC_RESULT result = atp_process_udp(context, sockfd, recv_msg, n, (const SA *)&srv_addr, srv_len);
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
        if(!fin_obj.eof()){
            while(!fin_obj.eof()){
                size_t buffer_sz;
                char * buffer = fin_obj.get(buffer_sz);
                atp_result r = atp_write(socket, buffer, buffer_sz);
                if (r >= 0)
                {
                    fin_obj.ack_by_n(r);
                }
                if (r != buffer_sz)
                {
                   // Can't hold
                   break; 
                }
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