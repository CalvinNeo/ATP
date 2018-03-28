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
#include "../atp_impl.h" // For debugging use
#include "test.inc.h"

int send_sim(atp_socket * socket, char * sendmsg){
    char oc;
    uint16_t port;
    uint16_t src_port = 0;

    OutgoingPacket * out_pkt = socket->basic_send_packet(0);
    size_t temp;

    int pos = 0;
    int delta;
    while(~sscanf(sendmsg + pos, "%c%n", &oc, &delta))
    {
        pos += delta;
        switch(oc)
        {
        case 's':
            // seq_nr
            sscanf(sendmsg + pos, "%u%n", &temp, &delta);
            pos += delta;
            if((int)temp != 0) {out_pkt->get_head()->seq_nr = temp;}
            break;
        case 'a':
            // ack_nr
            sscanf(sendmsg + pos, "%u%n", &temp, &delta);
            pos += delta;
            if((int)temp != 0) {out_pkt->get_head()->ack_nr = temp;}
            break;
        case 'i':
            // peer_sock_id
            sscanf(sendmsg + pos, "%u%n", &temp, &delta);
            pos += delta;
            if((int)temp != 0) {out_pkt->get_head()->peer_sock_id = temp;}
            break;
        case 'o':
            // opts_count
            sscanf(sendmsg + pos, "%u%n", &temp, &delta);
            pos += delta;
            if((int)temp != 0) {out_pkt->get_head()->opts_count = temp;}
            break;
        case 'f':
        {
            // flags
            uint8_t flags;
            while(~sscanf(sendmsg + pos, "%c%n", &oc, &delta)){
                pos += delta;
                switch(oc){
                case 'S':
                    flags |= PACKETFLAG_SYN;
                    break;
                case 'A':
                    flags |= PACKETFLAG_ACK;
                    break;
                case 'F':
                    flags |= PACKETFLAG_FIN;
                    break;
                case 'U':
                    flags |= PACKETFLAG_URG;
                    break;
                case 'R':
                    flags |= PACKETFLAG_RST;
                    break;
                case 'P':
                    flags |= PACKETFLAG_PSH;
                    break;
                case ' ':
                    goto OUT;
                }
            }
            OUT:
            if((int)flags != 0) {out_pkt->get_head()->flags = flags;}
            break;
        }
        case 'w':
            // window_size
            sscanf(sendmsg + pos, "%u%n", &temp, &delta);
            pos += delta;
            if((int)temp != 0) {out_pkt->get_head()->window_size = temp;}
            break;
        case 'O':
        {
            // options
            char name[64]; size_t length; 
            while(~sscanf(sendmsg + pos, "{%s %u %n", &name, &length, &delta)){
                pos += delta;
                std::string opt_name{name};
                printf("Option %s\n", name);
                if(opt_name == "ATP_OPT_SOCKID"){
                    uint16_t new_sock_id;
                    sscanf(sendmsg + pos, "%u}%n", &new_sock_id, &delta);
                    pos += delta;
                    socket->add_option(out_pkt, ATP_OPT_SOCKID, length, reinterpret_cast<char*>(&new_sock_id));
                }else if(opt_name == "ATP_OPT_MSS"){
                    uint32_t new_mss;
                    sscanf(sendmsg + pos, "%u}%n", &new_mss, &delta);
                    pos += delta;
                    socket->add_option(out_pkt, ATP_OPT_MSS, length, reinterpret_cast<char*>(&new_mss));
                }else if(opt_name == "ATP_OPT_SACK"){

                }else if(opt_name == "ATP_OPT_SACKOPT"){
                    
                }else if(opt_name == "ATP_OPT_TIMESTAMP"){
                    
                }else{
                    puts("option name error.");
                }
            }
            break;
        }
        case 'd':
            // data
            break;
        case 'p':
            // dest port
            sscanf(sendmsg + pos, "%u%n", &port, &delta);
            pos += delta;
            break;
        case 'P':
            // src port
            sscanf(sendmsg + pos, "%u%n", &src_port, &delta);
            pos += delta;
            break;
        case '\n':
            goto FINISH;
        default:
            break;
        }
    }
FINISH:
    // Must send through the sockets fd, so the following can't work
    // int n = send_simulated_packet(*(out_pkt->get_head()), port, src_port);
    int n = socket->send_packet(out_pkt, true, true);
    if(n != ATP_PROC_OK){
        printf("Error. errno: %u, %s\n", errno, strerror(errno));
    }else{
        printf("Sent a simulated packet. seq_nr:%u, ack_nr:%u, flag:%s, payload:%u, peer_sock_id:%u, port:%u, src_port:%u\n",
         out_pkt->get_head()->seq_nr, out_pkt->get_head()->ack_nr, OutgoingPacket::get_flags_str(out_pkt).c_str(), out_pkt->payload, out_pkt->get_head()->peer_sock_id, port, src_port);
    }
    delete out_pkt;
}

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
    if(atp_connect(socket, (const SA *)&srv_addr, sizeof srv_addr) != ATP_PROC_OK){
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
                            if(start[0] == ':'){
                                // This is a command
                                if(start[1] == 'S'){
                                    puts("Begin compute clock skew");
                                    socket->compute_clock_skew();
                                }
                            }else{
                                send_sim(socket, start);
                            }
                            start = strtok(0, "\n");
                        }
                    }else{
                        n = strlen(sendmsg);
                        printf("send msg %s\n", sendmsg);
                        atp_write(socket, sendmsg, n);
                    }
                }
            }else if((pfd[1].revents & POLLHUP) == POLLHUP){
                break;
            }
        }
    }

    atp_close(socket);
    delete context; context = nullptr;
    return 0;
};