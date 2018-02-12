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
#include "test.h"

// This program simulates a ATPPacket

char cmd[2000]; 
char outbuf[5000];
int main(int argc, char* argv[], char* env[]){
    int oc;char *pch = nullptr;
    uint16_t seq_nr; 
    uint16_t ack_nr;
    uint16_t peer_sock_id; 
    uint8_t opts_count; uint8_t flags = 0;
    uint16_t window_size;
    uint16_t port;
    uint16_t src_port = 0;
    // if(argc > 1){
    //     for(int i = 1; i < argc; i++){
    //         printf("arg %d is %s\n", i, argv[i]);
    //     }
    // }
    while((oc = getopt(argc, argv, "s:a:i:o:f:w:O:d:p:P:")) != -1)
    {
        switch(oc)
        {
        case 's':
            // seq_nr
            sscanf(optarg, "%u", &seq_nr);
            break;
        case 'a':
            // ack_nr
            sscanf(optarg, "%u", &ack_nr);
            break;
        case 'i':
            // peer_sock_id
            sscanf(optarg, "%u", &peer_sock_id);
            break;
        case 'o':
            // opts_count
            sscanf(optarg, "%u", &opts_count);
            break;
        case 'f':
            // flags
            strcpy(cmd, optarg);
            pch = cmd;
            while(*pch != 0){
                switch(*pch){
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
                }
                pch++;
            }
            break;
        case 'w':
            // window_size
            sscanf(optarg, "%u", &window_size);
            break;
        case 'O':
            // options
            strcpy(cmd, optarg);
            break;
        case 'd':
            // data
            strcpy(cmd, optarg);
            break;
        case 'p':
            // dest port
            sscanf(optarg, "%u", &port);
            break;
        case 'P':
            // src port
            sscanf(optarg, "%u", &src_port);
            break;
        }
    }
    size_t length = 0;
    ATPPacket pkt = ATPPacket{
        seq_nr, // seq_nr, updated in send_packet
        ack_nr, // ack_nr
        peer_sock_id, // peer_sock_id
        opts_count,// opts_count
        flags, // flags
        window_size // my window
    };
    memcpy(outbuf, &pkt, sizeof(ATPPacket));
    length += sizeof(ATPPacket);

    struct sockaddr_in addr; socklen_t addr_len = sizeof(addr);
    addr = make_socketaddr_in(AF_INET, "127.0.0.1", port);
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    
    if(src_port != 0){
        struct sockaddr_in my_addr = make_socketaddr_in(AF_INET, "127.0.0.1", src_port); 
        if (bind(sockfd, (SA *) &my_addr, sizeof my_addr) < 0)
            err_sys("bind error");
    }
    
    int n = sendto(sockfd, outbuf, length, 0, (const SA *)(&addr), addr_len);

    if(n != length){
        printf("Error. errno: %u, %s\n", errno, strerror(errno));
    }else{
        puts("Succeed.");
    }
    return 0;
}