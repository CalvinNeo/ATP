#pragma once

#include "udp_util.h"
#include "atp.h"
#include "scaffold.h"
#include <cstdio>
#include <string>
#include <map>
#include <tuple>

#define ETHERNET_MTU 1500
#define IPV4_HEADER_SIZE 20
#define IPV6_HEADER_SIZE 40
#define UDP_HEADER_SIZE 8


#if defined __GNUC__
    #define PACKED_ATTRIBUTE __attribute__((__packed__))
#else
    #define PACKED_ATTRIBUTE
#endif

struct PACKED_ATTRIBUTE ATPPacket{
    // apt packet layout, trivial
    // strictly aligned to 4
    uint32_t seq_nr;
    uint32_t ack_nr;
    uint16_t head_size; uint16_t flags;
};

struct ATPPacketHandle : ATPPacket{

};

enum CONN_STATE_ENUM {
    CS_UNINITIALIZED = 0,
    CS_IDLE,
    CS_SYN_SENT,
    CS_SYN_RECV,
    CS_CONNECTED,
    CS_CONNECTED_FULL,
    CS_GOT_FIN,
    CS_DESTROY_DELAY,
    CS_FIN_SENT,
    CS_RESET,
    CS_DESTROY,

    CS_STATE_COUNT
};

struct ATPAddrHandle{
    // apt addr layout, trivial
    ATPAddrHandle(){
        memset(&sa, 0, sizeof sa);
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
    void from_string(int family, const char * _ipaddstr, int _port){
        int n;
        if ((n = inet_pton(family, _ipaddstr, &(sa.sin_addr.s_addr))) < 0)
            err_sys("inet_pton error -1"); 
        else if (n == 0)
            err_sys("inet_pton error 0"); 
        sa.sin_port = htons(_port);
    }
    const char * to_string(int family) const{
        inet_ntop(family, &addr(), fmt, INET_ADDRSTRLEN);
        return const_cast<const char *>(fmt);
    }
    in_port_t & port(){
        return sa.sin_port;
    }
    in_addr_t & addr(){
        return sa.sin_addr.s_addr;
    }
    int16_t host_port(){
        return ntohs(sa.sin_port);
    }
    int32_t host_addr(){
        return ntohl(sa.sin_addr.s_addr);
    }

    struct sockaddr_in sa;
private:
    char fmt[INET_ADDRSTRLEN];
};

struct ATPSocket{

    ATPContext * context = nullptr;
    size_t sock_id; // can conflict

    ATPAddrHandle src_addr;
    ATPAddrHandle dest_addr;
    int family; int type; int protocol;
    int sockfd;

    CONN_STATE_ENUM conn_state;

    SizableCircularBuffer<char*> inbuf{15}, outbuf{15};

    uint32_t seq_nr = 1;
    uint32_t ack_nr = 0;

    uint32_t rtt = 0;
    uint32_t rtt_var = 800;
    uint32_t rto = 3000;
    uint64_t rto_timeout; // at this exact time(ms) will this socket timeout

    ~ATPSocket(){

    }
    ATPSocket(ATPContext * _context) : context(_context), conn_state(CS_UNINITIALIZED){
        sock_id = std::rand();
    }
    clear(){

    }
    void init(int family, int type, int protocol){
        conn_state = CS_IDLE;
        if ((sockfd = socket(family, type, protocol)) < 0)
            err_sys("socket error");
    }
    int connect(struct sockaddr_in to_addr){
        assert(context != nullptr);
        dest_addr = to_addr;

        assert(conn_state == CS_IDLE);
        conn_state = CS_SYN_SENT;

        uint64_t current_ms = get_current_ms();
        rto_timeout = current_ms + rto;

        seq_nr = rand();

    }
    void listen(){

    }
    void accept(){

    }
    void bind_default(){
        if (::bind(sockfd, (SA *) &(src_addr.sa), sizeof src_addr.sa) < 0)
            err_sys("bind error");
    }
    void close(){

    }

    void send_packet(){

    }

    const char * hash_code() const {
        sprintf(hash_str, "[%010d](%s:%d)->(%s:%d)", sock_id, src_addr.to_string(family), src_addr.port()
            , dest_addr.to_string(family), dest_addr.port());
        return const_cast<const char *>(hash_str);
    }
private:
    const char hash_str[INET_ADDRSTRLEN * 2 + 5 * 2 + 10 * 3];
};

struct OutgoingPacket{
    size_t length; // length of the whole
    size_t payload;
    uint64_t time_sent; // microseconds
    uint32_t transmissions; // total number of transmissions
    bool need_resend;
    // TODO remove VLA
    char data[1];
};

struct ATPContext{
    ATPContext(){
        memset(callbacks, 0, sizeof callbacks);
    }

    atp_callback_t * callbacks[ATP_CALLBACK_SIZE];

    size_t opt_sndbuf;
    size_t opt_rcvbuf;

    std::map<std::string, ATPSocket> sockets;
};