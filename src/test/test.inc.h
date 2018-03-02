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
#include "../atp_impl.h"
#include "../udp_util.h"

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
    struct sigaction action, old_action;

    action.sa_handler = handler;
    sigemptyset(&action.sa_mask);
    action.sa_flags = 0;

    sigaction(SIGTERM, NULL, &old_action);
    if (old_action.sa_handler != SIG_IGN) {
        sigaction(SIGTERM, &action, NULL);
    }
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
