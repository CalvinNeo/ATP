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

#include "error.h"
#include "scaffold.h"
#include "atp_common.h"
#include <cstdio>
#include <string>
#include <map>
#include <tuple>
#include <array>
#include <cstdlib>
#include <algorithm>
#include <functional>
#include <queue>
#include <type_traits>

#define LOGLEVEL_FATAL 1
#define LOGLEVEL_NOTE 2
#define LOGLEVEL_DEBUG 3
#define ATP_LOG_AT_NOTE
// #define ATP_LOG_AT_DEBUG
// #define ATP_LOG_UDP
// #define ATP_DEBUG_TEST_OVERFLOW

#define _log_doit _log_doit1
void _log_doit1(ATPSocket * socket, char const* func_name, int level, char const * fmt, va_list va);
void _log_doit1(ATPContext * context, char const* func_name, int level, char const * fmt, va_list va);
struct _log_doit2{
    operator std::function<void(ATPSocket *, char const *, va_list)> () const{
        return [&](ATPSocket * x, char const * fmt, va_list va){
            _log_doit1(x, func_name, level, fmt, va);
        };
    }
    operator std::function<void(ATPContext *, char const *, va_list)> () const{
        return [&](ATPContext * x, char const * fmt, va_list va){
            _log_doit1(x, func_name, level, fmt, va);
        };
    }
    _log_doit2(const char* f, int l) : func_name(f), level(l){

    }
    const char* func_name;
    int level;
};
void log_fatal1(ATPSocket * socket, char const *fmt, ...);
void log_debug1(ATPSocket * socket, char const *fmt, ...);
void log_note1(ATPSocket * socket, char const *fmt, ...);
void log_fatal1(ATPContext * context, char const *fmt, ...);
void log_debug1(ATPContext * context, char const *fmt, ...);
void log_note1(ATPContext * context, char const *fmt, ...);
void log_fatal2(std::function<void(ATPSocket *, char const *, va_list)> f, ATPSocket * socket, char const *fmt, ...);
void log_debug2(std::function<void(ATPSocket *, char const *, va_list)> f, ATPSocket * socket, char const *fmt, ...);
void log_note2(std::function<void(ATPSocket *, char const *, va_list)> f, ATPSocket * socket, char const *fmt, ...);
void log_fatal2(std::function<void(ATPContext *, char const *, va_list)> f, ATPContext * context, char const *fmt, ...);
void log_debug2(std::function<void(ATPContext *, char const *, va_list)> f, ATPContext * context, char const *fmt, ...);
void log_note2(std::function<void(ATPContext *, char const *, va_list)> f, ATPContext * context, char const *fmt, ...);
#define _log_fatal2(s, f, ...) log_fatal2(_log_doit2(__FUNCTION__, LOGLEVEL_FATAL), s, f, ##__VA_ARGS__)
#define _log_debug2(s, f,...) log_debug2(_log_doit2(__FUNCTION__, LOGLEVEL_DEBUG), s, f, ##__VA_ARGS__)
#define _log_note2(s, f, ...) log_note2(_log_doit2(__FUNCTION__, LOGLEVEL_NOTE), s, f, ##__VA_ARGS__)
// #define _log_fatal2(...) log_fatal2(_log_doit2(__FUNCTION__, LOGLEVEL_FATAL), __VA_ARGS__)
// #define _log_debug2(...) log_debug2(_log_doit2(__FUNCTION__, LOGLEVEL_DEBUG), __VA_ARGS__)
// #define _log_note2(...) log_note2(_log_doit2(__FUNCTION__, LOGLEVEL_NOTE), __VA_ARGS__)
#define USE_DARK_MAGIC
#if defined USE_DARK_MAGIC
#define log_fatal _log_fatal2
#define log_debug _log_debug2
#define log_note _log_note2
#else
#define log_fatal log_fatal1
#define log_debug log_debug1
#define log_note log_note1
#endif

#define SA struct sockaddr

#define PACKETFLAG_FIN 0x1
#define PACKETFLAG_SYN 0x2
#define PACKETFLAG_RST 0x4
#define PACKETFLAG_PSH 0x8
#define PACKETFLAG_ACK 0x10
#define PACKETFLAG_URG 0x20
#define PACKETFLAG_MASK 0xff

struct PACKED_ATTRIBUTE ATPPacket : public CATPPacket{
    // apt packet layout, trivial

#define MAKE_FLAGS_GETTER_SETTER(fn, mn) void set_##fn(uint8_t fn){ \
        if(fn == 1) flags |= mn; else flags &= (~mn); \
        flags &= PACKETFLAG_MASK; } \
    uint8_t get_##fn() const{ return (flags & mn) == 0 ? 0 : 1;} 

    MAKE_FLAGS_GETTER_SETTER(fin, PACKETFLAG_FIN);
    MAKE_FLAGS_GETTER_SETTER(syn, PACKETFLAG_SYN);
    MAKE_FLAGS_GETTER_SETTER(rst, PACKETFLAG_RST);
    MAKE_FLAGS_GETTER_SETTER(psh, PACKETFLAG_PSH);
    MAKE_FLAGS_GETTER_SETTER(ack, PACKETFLAG_ACK);
    MAKE_FLAGS_GETTER_SETTER(urg, PACKETFLAG_URG);

    template <typename ... Args>
    static uint16_t create_flags(Args&& ... args){
        uint16_t f = 0;
        f = ( ... | args);
        f &= PACKETFLAG_MASK;
        return f;
    }

    bool has(uint8_t f) const{
        return (flags & f) == 0 ? 0 : 1;
    }

    template <typename ... Args>
    static bool any(Args&& ... args){
        std::array<uint16_t, sizeof...(Args)> value = { args... };
        for(const auto & s: value){
            if(has(s)){
                return true;
            }
        }
        return false;
    }
    template <typename ... Args>
    static bool all(Args&& ... args){
        std::array<uint16_t, sizeof...(Args)> value = { args... };
        for(const auto & s: value){
            if(!has(s)){
                return false;
            }
        }
        return true;
    }

    uint32_t get_full_seq_nr(ATPSocket * socket) const;
};

static_assert(std::is_trivial<ATPPacket>::value, "ATPPacket is not trivial");
static_assert(std::is_pod<ATPPacket>::value, "ATPPacket is not pod");
static_assert(std::is_aggregate<ATPPacket>::value, "ATPPacket is not aggregate");
static_assert(sizeof(ATPPacket) == 10, "ATPPacket's size is not equal to 10");

extern const char * CONN_STATE_STRS [];

struct ATPAddrHandle{
    ATPAddrHandle(){
        std::memset(&sa, 0, sizeof sa);
    }
    ATPAddrHandle(const struct sockaddr * _sa){
        sa = *(reinterpret_cast<const sockaddr_in *>(_sa));
    }
    ATPAddrHandle & operator=(const ATPAddrHandle & rhs){
        if(this == &rhs){
            return *this;
        }
        sa = rhs.sa;
        return *this;
    }
    ATPAddrHandle & operator=(const sockaddr_in & rhs){
        sa = rhs;
        return *this;
    }
    bool operator==(const ATPAddrHandle & rhs) const{
        if(this == &rhs){
            return true;
        }
        return (port() == rhs.port() && addr() == rhs.addr());
    }
    bool operator!=(const ATPAddrHandle & rhs) const{
        return !(*this == rhs);
    }
    void from_string(const char * _ipaddstr, int _port){
        int n;
        if ((n = ::inet_pton(sa.sin_family, _ipaddstr, &(sa.sin_addr.s_addr))) < 0)
            err_sys("inet_pton error -1"); 
        else if (n == 0)
            err_sys("inet_pton error 0"); 
        set_port(_port);
    }
    const char * to_string() const{
        ::inet_ntop(sa.sin_family, &addr(), fmt, INET_ADDRSTRLEN);
        return const_cast<const char *>(fmt);
    }
    const char * hash_code() const{
        std::sprintf(fmt, "%s:%05u", to_string(), host_port());
        return const_cast<const char *>(fmt);
    }
    void set_port(in_port_t _port){
        sa.sin_port = htons(_port);
    }
    void set_addr(in_addr_t _addr){
        sa.sin_addr.s_addr = htonl(_addr);
    }
    in_port_t & port(){
        return sa.sin_port;
    }
    in_addr_t & addr(){
        return sa.sin_addr.s_addr;
    }
    const in_port_t & port() const{
        return sa.sin_port;
    }
    const in_addr_t & addr() const{
        return sa.sin_addr.s_addr;
    }
    uint16_t host_port() const{
        return ntohs(sa.sin_port);
    }
    uint32_t host_addr() const{
        return ntohl(sa.sin_addr.s_addr);
    }
    decltype(sockaddr_in::sin_family) & family() {
        return sa.sin_family;
    }
    size_t length() const{
        return sizeof sa;
    }
    struct sockaddr_in sa;
private:
    mutable char fmt[INET_ADDRSTRLEN];
};

struct OutgoingPacket{
    ~OutgoingPacket(){
        if(holder)
            destroy();
    }
    bool holder = true;
    bool marked = false;
    size_t length = 0; // length of the whole
    size_t payload = 0;
    uint64_t timestamp; // microseconds
    uint32_t transmissions = 0; // total number of transmissions
    bool need_resend;
    uint32_t full_seq_nr;
    char * data; // = head + data

    void destroy(){
        // TODO now manually managing memory, swith to smart pointers later
        std::free(data);
        data = nullptr;
    }
    bool is_empty_ack() const{
        return !is_promised_packet();
    }
    bool is_promised_packet() const{
        // a promist packet will be resend if not got ACK from peer
        // only promised packet has seq_nr
        if(get_head()->get_syn() || get_head()->get_fin()){
            return true;
        }
        if (payload == 0)
        {
            // an payload == 0 packet must ACK
            assert(get_head()->get_ack());
            return false;
        }
        return true;
    }
    bool has_user_data() const{
        if (payload == 0)
        {
            return false;
        }
        if(get_head()->get_syn() || get_head()->get_fin()){
            return false;
        }
        return true;
    }
    ATPPacket * get_head(){
        return reinterpret_cast<ATPPacket *>(data);
    }
    const ATPPacket * get_head() const {
        return reinterpret_cast<ATPPacket *>(data);
    }
};

struct ATPSocket{
    ATPContext * context = nullptr;
    // function as "port"
    uint16_t sock_id;
    uint16_t peer_sock_id = 0;

    mutable ATPAddrHandle src_addr;
    ATPAddrHandle & get_src_addr(){
        if (conn_state == CS_UNINITIALIZED)
        {
            return src_addr;
        }else{
            if (src_addr.host_port() == 0 && src_addr.host_addr() == 0)
            {
            }
            socklen_t my_sock_len = sizeof(src_addr.sa);
            getsockname(sockfd, reinterpret_cast<SA*> (&src_addr.sa), &my_sock_len);
            return src_addr;
        }
    }
    ATPAddrHandle dest_addr;
    int family; int type; int protocol;
    int sockfd;

    CONN_STATE_ENUM conn_state;

    struct _cmp_outgoingpacket_fullseq{  
        bool operator()(OutgoingPacket * left, OutgoingPacket * right){  
            if(left->full_seq_nr == right->full_seq_nr)  return left > right;  
            return left->full_seq_nr > right->full_seq_nr;  
        }  
    }; 
    struct _cmp_outgoingpacket{  
        bool operator()(OutgoingPacket * left, OutgoingPacket * right){  
            if(left->get_head()->seq_nr == right->get_head()->seq_nr)  return left > right;  
            return left->get_head()->seq_nr > right->get_head()->seq_nr;  
        }  
    }; 
    struct _cmp_outgoingpacket_marked{  
        bool operator()(OutgoingPacket * left, OutgoingPacket * right){  
            if(left->marked == right->marked)  return left > right;  
            // false | false | ... | true
            return left->marked == false ? true: false;  
        }  
    }; 
    // std::priority_queue<OutgoingPacket*, std::vector<OutgoingPacket*>, _cmp_outgoingpacket> inbuf;
    std::vector<OutgoingPacket*> outbuf;
    std::vector<OutgoingPacket*> inbuf;
    std::vector<OutgoingPacket*> inbuf_cache2;


    // my seq number
    uint32_t seq_nr = 0;
    // peer's seq number acked by me
    uint32_t ack_nr = 0;
    bool overflow_lock = false;
    static const uint32_t seq_nr_mask = 0xffff;
    // when peer's seq_nr wrap to 0, peer_seq_nr_base += std::numeric_limits<T>::max()
    uint32_t peer_seq_nr_base = 0;
    // my seq number acked by peer
    uint32_t my_seq_acked_by_peer = 0;

    uint32_t rtt = 0;
    uint32_t rtt_var = 800; // Default 800
    uint32_t rto = 2000; // Default 3000, recommend no less than timer event interval
    uint64_t rto_timeout = 0; // at this exact time(ms) will this socket timeout
    uint64_t death_timeout = 0; // at this exact time change from TIME_WAIT to DESTROY
    uint64_t persist_timeout = 0; // at this exact time probe peer's window
    uint32_t ack_delayed_time = 200; // default 200, set 0 to disable delayed ACK
    uint64_t delay_ack_timeout = 0; // at this exact time send delayed ACK

    uint16_t atp_retries1 = 3; // TCP RFC recommends 3
    uint16_t atp_retries2 = 8; // TCP RFC recommends 15
    uint16_t atp_syn_retries1 = 5;

    // Not used yet
    uint32_t cur_window_packets = 1; 
    // the number of packets in the send queue
    // including unsend and un-acked packets
    // the oldest un-acked packet in the send queue is seq_nr - used_window_packets
    uint32_t used_window_packets = 0; 

    // this is byte-wise, set by peer
    // by default = MAX_ATP_READ_BUFFER_SIZE
    size_t cur_window = ATP_MAX_READ_BUFFER_SIZE;
    // this is byte-wise, payload of in-flight packets + payload of needing to be re-sent packets
    size_t used_window = 0;
    size_t my_window = ATP_MAX_WRITE_BUFFER_SIZE;
    
    // determined by MTU
    size_t current_mss = ATP_MSS_CEILING;

    atp_callback_func * callbacks[ATP_CALLBACK_SIZE];


    ~ATPSocket(){
        #if defined (ATP_LOG_AT_DEBUG)
            log_debug(this, "Socket destructed.");
        #endif
        clear();
    }
    ATPSocket(ATPContext * _context);
    // HELPERS
    void register_to_look_up();
    atp_callback_arguments make_atp_callback_arguments(int method, OutgoingPacket * out_pkt, const ATPAddrHandle & addr);
    OutgoingPacket * basic_send_packet(uint16_t flags);

    // INTERFACES
    void clear(){
        for(OutgoingPacket * op : outbuf){
            delete op;
        }
        outbuf.clear();
        for(OutgoingPacket * op : inbuf){
            delete op;
        }
        inbuf.clear();
    }
    // called by atp_create_socket, returns sockfd
    int init(int family, int type, int protocol);
    // active connect
    ATP_PROC_RESULT connect(const ATPAddrHandle & to_addr);
    ATP_PROC_RESULT listen(uint16_t host_port);
    ATP_PROC_RESULT bind(const ATPAddrHandle & to_addr);
    // passive connect
    ATP_PROC_RESULT accept(const ATPAddrHandle & to_addr, OutgoingPacket * recv_pkt);
    ATP_PROC_RESULT receive(OutgoingPacket * recv_pkt);
    void reset_timer(){

    }

    ATP_PROC_RESULT send_packet_noguard(OutgoingPacket * out_pkt);
    void check_unsend_packet();
    // `send_packet` will take over possession of `out_pkt`
    ATP_PROC_RESULT send_packet(OutgoingPacket * out_pkt);
    ATP_PROC_RESULT close();
    bool writable() const;
    bool readable() const;
    void add_selective_ack_option(OutgoingPacket * out_pkt);
    void add_data(OutgoingPacket * out_pkt, const void * buf, const size_t len);
    size_t bytes_can_send_once() const ;
    size_t bytes_can_send_one_packet() const ;
    bool is_full() const {return bytes_can_send_once() == 0;}
    // this function returns immediately after the packet is sent(whether succeed or fail)
    ATP_PROC_RESULT write(const void * buf, const size_t len);
    // this function returns only when got ack from peer
    ATP_PROC_RESULT blocked_write(const void * buf, const size_t len);
    // handles FIN
    ATP_PROC_RESULT check_fin(OutgoingPacket * recv_pkt);
    // handles ACK, when a ack packet comes, update ack_nr
    ATP_PROC_RESULT update_myack(OutgoingPacket * recv_pkt);
    ATP_PROC_RESULT handle_recv_packet(OutgoingPacket * recv_pkt, bool from_cache);
    ATP_PROC_RESULT process(const ATPAddrHandle & addr, const char * buffer, size_t len);
    ATP_PROC_RESULT invoke_callback(int callback_type, atp_callback_arguments * args);
    // update my_seq_acked_by_peer
    ATP_PROC_RESULT do_ack_packet(OutgoingPacket * recv_pkt);
    // according to current base
    uint32_t get_full_seq_nr(uint32_t raw_peer_seq_nr){
        return raw_peer_seq_nr + peer_seq_nr_base;
    }
    // guess which base
    uint32_t guess_full_seq_nr(uint32_t raw_peer_seq);
    uint32_t guess_full_ack_nr(uint32_t raw_peer_ack);
    void update_rto(OutgoingPacket * recv_pkt);
    void destroy();
    ATP_PROC_RESULT check_timeout();
    const char * hash_code() const{
        return ATPSocket::make_hash_code(sock_id, dest_addr);
    }
    const char * to_string() const{
        sprintf(hash_str, "[%05u](%s:%05u)->(%s:%05u) fd:%d", sock_id, this->get_src_addr().to_string(), this->get_src_addr().host_port()
            , dest_addr.to_string(), dest_addr.host_port(), sockfd);
        return const_cast<const char *>(hash_str);
    }
    static const char * make_hash_code(uint16_t sock_id, const ATPAddrHandle & dest_addr){
        static char hash_str[INET_ADDRSTRLEN * 2 + 5 * 2 + 10 * 3];
        sprintf(hash_str, "[%05u]%s", sock_id, dest_addr.hash_code());
        return const_cast<const char *>(hash_str);
    }
private:
    mutable char hash_str[INET_ADDRSTRLEN * 2 + 5 * 2 + 10 * 3];
};


struct ATPContext{
    void clear(){
        for(ATPSocket * socket : sockets){
            delete (socket);
            socket = nullptr;
        }
        sockets.clear();
        look_up.clear();
        listen_sockets.clear();
    }
    void init(){
        clear();
        start_ms = get_current_ms();
        std::srand(start_ms);
    }

    ATPContext(){
        init();
    }
    ~ATPContext(){
        #if defined (ATP_LOG_AT_DEBUG)
            fprintf(stderr, "Context destroyed.\n");
        #endif
        clear();
    }

    // because we have peer_sock_id in ATPPacket, 
    // so we don't need to wait actually 2msl, 
    // waiting for rto time is enough. 
    // But you can still set a minimum
    uint32_t min_msl2 = 6000; 

    std::vector<ATPSocket *> sockets;
    std::map<std::string, ATPSocket *> look_up;
    std::map<uint16_t, ATPSocket *> listen_sockets;
    std::vector<ATPSocket *> destroyed_sockets;
    uint64_t start_ms;

    uint16_t new_sock_id(){
        uint16_t s = 0;
        while(s == 0){
            s = std::rand();
        }
        return s;
    }

    void destroy(ATPSocket * socket){
        #if defined (ATP_LOG_AT_DEBUG)
            log_debug(socket, "Context are destroying me. Goodbye. There are %u sockets left in the context including me", sockets.size());
        #endif
        auto iter = std::find(sockets.begin(), sockets.end(), socket);
        sockets.erase(iter);
        auto map_iter1 = look_up.find(socket->hash_code());
        if (map_iter1 != look_up.end())
        {
            look_up.erase(map_iter1);
        }
        auto map_iter2 = listen_sockets.find(socket->get_src_addr().host_port());
        if (map_iter2 != listen_sockets.end())
        {
            listen_sockets.erase(map_iter2);
        }
        delete socket;
    }

    ATP_PROC_RESULT daily_routine(){
        // notify all exsiting sockets
        // trigger1: once a message arrived
        // trigger2: timeout
        ATP_PROC_RESULT result = ATP_PROC_OK;
        for(ATPSocket * socket: this->sockets){
            ATP_PROC_RESULT sub_result = socket->check_timeout();
            if (sub_result == ATP_PROC_ERROR)
            {
                result = ATP_PROC_ERROR;
            }else if (sub_result == ATP_PROC_OK)
            {
                result = ATP_PROC_OK;
            }else if (sub_result == ATP_PROC_FINISH)
            {
                // one socket calling on finish don't mean finishing
                // because other sockets may still processing
                result = ATP_PROC_OK;
            }else{
                result = ATP_PROC_OK;
            }
        } 
        // clear destroyed sockets
        for(ATPSocket * socket : destroyed_sockets){
            this->destroy(socket);
        }
        destroyed_sockets.clear();
        if (this->sockets.size() == 0 && this->destroyed_sockets.size() == 0)
        {
            #if defined (ATP_LOG_AT_DEBUG)
                log_debug(this, "Context finished.");
            #endif
            // There's no sockets active
            // Case 1: If ATP is built in an user program, user catchs the return value ATP_PROC_FINISH,
            // if he has no other missions, he can destroy the context safely by calling `exit(0)`
            // Case 2: If ATP is a service, user should not handle the return value ATP_PROC_FINISH,
            return ATP_PROC_FINISH;
        }else{
            return result;
        }
    }

    ATPSocket * find_socket_by_fd(const ATPAddrHandle & handle_to, int sockfd);
    ATPSocket * find_socket_by_head(const ATPAddrHandle & handle_to, ATPPacket * pkt);
};


void print_out(ATPSocket * socket, OutgoingPacket * out_pkt, const char * method);

void init_callbacks(ATPSocket * socket);

std::string tabber(const std::string & src, bool tail_crlf = true);
