#pragma once

#include "udp_util.h"
#include "atp.h"
#include "scaffold.h"
#include "atp_callback.h"
#include <cstdio>
#include <string>
#include <map>
#include <tuple>
#include <array>
#include <cstdlib>
#include <algorithm>
#include <functional>

#define ETHERNET_MTU 1500
#define IPV4_HEADER_SIZE 20
#define IPV6_HEADER_SIZE 40
#define UDP_HEADER_SIZE 8

#define PACKETFLAG_FIN 0x1
#define PACKETFLAG_SYN 0x2
#define PACKETFLAG_RST 0x4
#define PACKETFLAG_PSH 0x8
#define PACKETFLAG_ACK 0x10
#define PACKETFLAG_URG 0x20
#define PACKETFLAG_MASK 0x3f

#if defined __GNUC__
    #define PACKED_ATTRIBUTE __attribute__((__packed__))
#else
    #define PACKED_ATTRIBUTE
#endif

#define LOGLEVEL_FATAL 1
#define LOGLEVEL_NOTE 2
#define LOGLEVEL_DEBUG 3
#define ATP_LOG LOGLEVEL_DEBUG

void log_fatal(ATPSocket * socket, char const *fmt, ...);
void log_debug(ATPSocket * socket, char const *fmt, ...);
void log_note(ATPSocket * socket, char const *fmt, ...);

struct PACKED_ATTRIBUTE ATPPacket{
    // apt packet layout, trivial
    // strictly aligned to 4

    // seq_nr and ack_nr are now packet-wise rather than byte-wise
    uint32_t seq_nr;
    uint32_t ack_nr;
    uint16_t head_size; uint16_t flags;

#define MAKE_FLAGS_GETTER_SETTER(fn, mn) void set_##fn(char fn){ \
        if(fn == 1) flags |= mn; else flags &= (~mn); \
        flags &= PACKETFLAG_MASK; } \
    char get_##fn() const{ return (flags & mn) == 0 ? 0 : 1;} 

    MAKE_FLAGS_GETTER_SETTER(fin, PACKETFLAG_FIN);
    MAKE_FLAGS_GETTER_SETTER(syn, PACKETFLAG_SYN);
    MAKE_FLAGS_GETTER_SETTER(rst, PACKETFLAG_RST);
    MAKE_FLAGS_GETTER_SETTER(psh, PACKETFLAG_PSH);
    MAKE_FLAGS_GETTER_SETTER(ack, PACKETFLAG_ACK);
    MAKE_FLAGS_GETTER_SETTER(urg, PACKETFLAG_URG);

    template <typename ... Args>
    static uint16_t create_flags(Args&& ... args){
        uint16_t f = 0;
        std::array<uint16_t, sizeof...(Args)> value = { args... };
        for(const auto & s: value){
            f |= s;
        }
        f &= PACKETFLAG_MASK;
        return f;
    }

};

enum CONN_STATE_ENUM {
    CS_UNINITIALIZED = 0,
    CS_IDLE,

    CS_SYN_SENT,
    CS_SYN_RECV,

    CS_CONNECTED,
    CS_CONNECTED_FULL,

    CS_FIN_WAIT_1,
    CS_CLOSE_WAIT,
    CS_FIN_WAIT_2,
    CS_LAST_ACK,
    CS_TIME_WAIT,

    CS_RESET,
    CS_DESTROY,

    CS_STATE_COUNT
};

struct ATPAddrHandle{
    // apt addr layout, trivial
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
        sa.sin_port = htons(_port);
    }
    const char * to_string() const{
        ::inet_ntop(sa.sin_family, &addr(), fmt, INET_ADDRSTRLEN);
        return const_cast<const char *>(fmt);
    }
    const char * hash_code() const {
        std::sprintf(fmt, "%s:%05u", to_string(), host_port());
        return const_cast<const char *>(fmt);
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
    int16_t host_port() const{
        return ntohs(sa.sin_port);
    }
    int32_t host_addr() const{
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
    char fmt[INET_ADDRSTRLEN];
};

struct OutgoingPacket{
    ~OutgoingPacket(){
        if(holder)
            destroy();
    }
    bool holder = true;
    size_t length = 0; // length of the whole
    size_t payload = 0;
    uint64_t time_sent; // microseconds
    uint32_t transmissions = 0; // total number of transmissions
    bool need_resend;
    char * data; // = head + data

    void destroy(){
        // TODO now manually managing memory, swith to smart pointers later
        std::free(data);
    }

    ATPPacket * get_head(){
        return reinterpret_cast<ATPPacket *>(data);
    }
};

struct ATPSocket{
    ATPContext * context = nullptr;
    size_t sock_id; // can conflict

    ATPAddrHandle src_addr;
    ATPAddrHandle dest_addr;
    int family; int type; int protocol;
    int sockfd;

    CONN_STATE_ENUM conn_state;

    SizableCircularBuffer<OutgoingPacket*> inbuf{15}, outbuf{15};

    uint32_t seq_nr = 1;
    uint32_t ack_nr = 0;

    uint32_t rtt = 0;
    uint32_t rtt_var = 800;
    uint32_t rto = 3000;
    uint64_t rto_timeout; // at this exact time(ms) will this socket timeout

    // the number of packets in the send queue
    // including unsend and un-acked packets
    // the oldest un-acked packet in the send queue is seq_nr - cur_window_packets
    uint32_t cur_window_packets = 0; 
    // this is byte-wise, in-flight packets + needing to be re-sent packets
    size_t cur_window = 0;

    ~ATPSocket(){

    }
    ATPSocket(ATPContext * _context) : context(_context){
        sock_id = std::rand();
        conn_state = CS_UNINITIALIZED;
        memset(hash_str, 0, sizeof hash_str);
    }
    void clear(){

    }
    void init(int family, int type, int protocol){
        conn_state = CS_IDLE;
        src_addr.family() = family;
        dest_addr.family() = family;
        if ((sockfd = socket(family, type, protocol)) < 0)
            err_sys("socket error");
    }
    void register_to_look_up();

    OutgoingPacket * basic_send_packet(uint16_t flags){
        ATPPacket pkt = ATPPacket{
            seq_nr, //seq_nr
            ack_nr, // ack_nr
            sizeof(ATPPacket), // header_size
            flags // flags
        };
        OutgoingPacket * out_pkt = new OutgoingPacket{
            true,
            sizeof (ATPPacket), // length, update by `add_data`
            0, // payload, update by `add_data`
            0, // time_sent, set at `send_packet`
            0, // transmissions, update by `send_packet`
            false, // need_resend, update by `send_packet`
            reinterpret_cast<char *>(std::calloc(1, sizeof (ATPPacket))) // SYN packet will not contain data
        };
        std::memcpy(out_pkt->data, &pkt, sizeof (ATPPacket));
    }
    // active connect
    int connect(const ATPAddrHandle & to_addr);
    void bind_default(){
        if (::bind(sockfd, (SA *) &(src_addr.sa), sizeof src_addr.sa) < 0)
            err_sys("bind error");
    }
    // passive connect
    int accept(const ATPAddrHandle & to_addr, OutgoingPacket * recv_pkt){
        assert(context != nullptr);
        dest_addr = to_addr;

        assert(conn_state == CS_IDLE);
        conn_state = CS_SYN_RECV;
        register_to_look_up();

        seq_nr = rand();
        ack_nr = recv_pkt->get_head()->seq_nr;

        OutgoingPacket * out_pkt = basic_send_packet(ATPPacket::create_flags(PACKETFLAG_SYN, PACKETFLAG_ACK));
        send_packet(out_pkt);
        return 0;
    }
    int receive(char * buffer, size_t len){
        if(conn_state < CS_CONNECTED){
            conn_state = CS_CONNECTED;
        }
        return 0;
    }
    int update_ack(){

    }
    void send_packet(OutgoingPacket * out_pkt);
    void close(){

    }
    void add_data(OutgoingPacket * out_pkt, const void * buf, const size_t len){
        out_pkt->length += len;
        out_pkt->payload += len;

        out_pkt->data = reinterpret_cast<char *>(std::realloc(out_pkt->data, out_pkt->length));
        memcpy(out_pkt->data, out_pkt->data + out_pkt->length - len, len);
    }
    ssize_t write(const void * buf, const size_t len){

    }
    int process(const ATPAddrHandle & addr, const char * buffer, size_t len);
    const char * hash_code() const {
        return dest_addr.hash_code();
    }
    const char * to_string() const {
        sprintf(hash_str, "[%010d](%s:%05u)->(%s:%05u)", sock_id, src_addr.to_string(), src_addr.host_port()
            , dest_addr.to_string(), dest_addr.host_port());
        return const_cast<const char *>(hash_str);
    }
private:
    char hash_str[INET_ADDRSTRLEN * 2 + 5 * 2 + 10 * 3];
};


struct ATPContext{
    void clear(){
        for(ATPSocket * socket : sockets){
            delete (socket);
        }
        sockets.clear();
        look_up.clear();
    }
    void init(){
        memset(callbacks, 0, sizeof callbacks);
        callbacks[ATP_CALL_ON_ACCEPT] = atp_default_on_accept;
        callbacks[ATP_CALL_ON_ERROR] = atp_default_on_error;
        callbacks[ATP_CALL_ON_READ] = atp_default_on_read;
        callbacks[ATP_CALL_ON_STATE_CHANGE] = atp_default_on_state_change;
        callbacks[ATP_CALL_GET_READ_BUFFER_SIZE] = atp_default_get_read_buffer_size;
        callbacks[ATP_CALL_GET_RANDOM] = atp_default_get_random;
        callbacks[ATP_CALL_SENDTO] = atp_default_sendto;
        callbacks[ATP_CALL_CONNECT] = atp_default_connect;
        callbacks[ATP_CALL_LOG] = atp_default_log;
        callbacks[ATP_CALL_LOG_NORMAL] = atp_default_log_normal;
        callbacks[ATP_CALL_LOG_DEBUG] = atp_default_log_debug;
        callbacks[ATP_CALL_OPT_SENDBUF] = atp_default_opt_sndbuf;
        callbacks[ATP_CALL_OPT_RECVBUF] = atp_default_opt_rcvbuf;
        clear();
    }

    ATPContext(){
        init();
    }
    ~ATPContext(){
        clear();
    }

    atp_callback_func * callbacks[ATP_CALLBACK_SIZE];

    size_t opt_sndbuf;
    size_t opt_rcvbuf;

    std::vector<ATPSocket *> sockets;
    std::map<std::string, ATPSocket *> look_up;
};

inline ATPContext & get_context(){
    static ATPContext context;
    return context;
}

