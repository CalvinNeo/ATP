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

#pragma once

#include <random>
#include <thread>
#include "../src/atp_impl.h"
#include "../src/udp_util.h"

ATP_PROC_RESULT normal_sendto(atp_callback_arguments * args);

static double loss_rate;
static size_t delay_time;

inline void sigterm_handler(int signum)
{
    puts("Signal Term reiceved for timeout termination.");
    exit(0);
}

void reg_sigterm_handler(void (*handler)(int s))
{
    // struct sigaction action, old_action;

    // action.sa_handler = handler;
    // sigemptyset(&action.sa_mask);
    // action.sa_flags = 0;

    // sigaction(SIGTERM, NULL, &old_action);
    // if (old_action.sa_handler != SIG_IGN) {
    //     sigaction(SIGTERM, &action, NULL);
    // }

    setup_signal(SIGTERM, handler);
}


inline ATP_PROC_RESULT simulate_packet_loss_sendto(atp_callback_arguments * args){
    static std::default_random_engine e{get_current_ms()};
    static std::uniform_real_distribution<double> u{0, 1};
    double drop_rate_judge = u(e);
    if (drop_rate_judge < loss_rate)
    {
        puts("simulated packet loss");
        return ATP_PROC_OK;
    }else{
        return normal_sendto(args);
    }
}

inline ATP_PROC_RESULT simulate_delayed_sendto(atp_callback_arguments * args){
    char * data = new char[args->length];
    std::memcpy(data, args->data, args->length);
    char * addr = new char[args->addr_len];
    std::memcpy(addr, args->addr, args->addr_len);

    // create a copy of arguments
    atp_callback_arguments * new_arg = new atp_callback_arguments(*args);
    new_arg->data = data;
    new_arg->addr = (const SA *)addr;

    // std::atomic_thread_fence(std::memory_order_seq_cst);
    std::thread send_thread{[=](){
        // printf("sleep at %llu\n", get_current_ms());
        #if defined(ATP_LOG_UDP) && defined(ATP_LOG_AT_DEBUG)
            log_debug(new_arg->socket, "UDP delay a packet for %u ms.", delay_time);
        #endif
        std::this_thread::sleep_for(std::chrono::milliseconds(delay_time));
        // printf("wake and send at %llu\n", get_current_ms());
        #if defined(ATP_LOG_UDP) && defined(ATP_LOG_AT_DEBUG)
            log_debug(new_arg->socket, "UDP sent delayed packet.");
        #endif
        normal_sendto(new_arg);
        delete [] new_arg->data;
        delete [] new_arg->addr;
        delete new_arg;
    }};
    // std::atomic_thread_fence(std::memory_order_seq_cst);
    if (send_thread.joinable()) {
        send_thread.detach();
    }
    return ATP_PROC_OK;
}


inline int send_simulated_packet(const ATPPacket & pkt, uint16_t port, uint16_t src_port){
    char outbuf[5000];
    size_t length = 0;
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
    if (n != length)
    {
        return -1;
    }
    return n;
}

inline int send_simulated_packet(
    uint16_t seq_nr,
    uint16_t ack_nr,
    uint16_t peer_sock_id,
    uint8_t opts_count, uint8_t flags,
    uint16_t window_size,
    uint16_t port,
    uint16_t src_port){

    ATPPacket pkt = ATPPacket{
        seq_nr, // seq_nr, updated in send_packet
        ack_nr, // ack_nr
        peer_sock_id, // peer_sock_id
        opts_count,// opts_count
        flags, // flags
        window_size // my window
    };
    return send_simulated_packet(pkt, port, src_port);
}

struct FileObject{
    FILE* fp;
    size_t cache_size;
    char * cache;
    size_t current_p;
    size_t current_size;
    FileObject(int _fp, size_t _cache_size): fp(_fp), cache_size(_cache_size){
        cache = new char [cache_size];
        current_p = 0;
        current_size = 0;
    }
    ~FileObject(){
        delete [] cache;
    }
    char * get(size_t & n){
        if (current_p >= 0 && (current_p < current_size))
        {
            // There's unsend data in cache
            n = current_size - current_p;
            return cache + current_p;
        }else{
            // re-fill cache
            current_size = fread(cache, 1, cache_size, fp);
            current_p = 0;
            n = current_size;
            return cache;
        }
    }
    void ack_by_n(size_t n){
        current_p += n;
    }
    bool eof() const {
        return feof(fp) && !(current_p >= 0 && (current_p < current_size));
    }
};

int send_sim(atp_socket * socket, char * sendmsg){
    char oc;
    uint16_t port;
    uint16_t src_port = 0;

    OutgoingPacket * out_pkt = socket->basic_send_packet(0);
    size_t temp;

    int pos = 0;
    int delta;
    if(sendmsg[0] == ':'){
        // This is a command
        if(sendmsg[1] == 'S'){
            puts("Begin compute clock skew");
            socket->compute_clock_skew();
        }
        return 0;
    }
    // This is normal sim packet
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