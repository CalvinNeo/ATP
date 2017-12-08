#pragma once

#include "error.h"
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
#include <queue>


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

// void log_fatal(ATPSocket * socket, char const* func_name, char const *fmt, ...);
// void log_debug(ATPSocket * socket, char const* func_name, char const *fmt, ...);
// void log_note(ATPSocket * socket, char const* func_name, char const *fmt, ...);
// void log_fatal(ATPContext * context, char const* func_name, char const *fmt, ...);
// void log_debug(ATPContext * context, char const* func_name, char const *fmt, ...);
// void log_note(ATPContext * context, char const* func_name,char const *fmt, ...);
// #define log_fatal(socket, fmt, ...) _log_fatal(socket, __FUNCTION__, fmt, __VA_ARGS__ )
// #define log_note(socket, fmt, ...) _log_note(socket, __FUNCTION__, fmt, __VA_ARGS__ )
// #define log_debug(socket, fmt, ...) _log_debug(socket, __FUNCTION__, fmt, __VA_ARGS__ )

#define _log_doit _log_doit1
#define log_fatal log_fatal1
#define log_debug log_debug1
#define log_note log_note1
void _log_doit1(ATPSocket * socket, char const* func_name, int level, char const * fmt, va_list va);
void _log_doit1(ATPContext * context, char const* func_name, int level, char const * fmt, va_list va);
std::function<void(ATPContext *, char const *, va_list)> _log_doit2_context(const char* func_name, int level);
std::function<void(ATPSocket *, char const *, va_list)> _log_doit2_socket(const char* func_name, int level);
void log_fatal1(ATPSocket * socket, char const *fmt, ...);
void log_debug1(ATPSocket * socket, char const *fmt, ...);
void log_note1(ATPSocket * socket, char const *fmt, ...);
void log_fatal1(ATPContext * context, char const *fmt, ...);
void log_debug1(ATPContext * context, char const *fmt, ...);
void log_note1(ATPContext * context, char const *fmt, ...);
#define log_fatal2_socket _log_doit2_socket(__FUNCTION__, LOGLEVEL_FATAL)
#define log_debug2_socket _log_doit2_socket(__FUNCTION__, LOGLEVEL_DEBUG)
#define log_note2_socket _log_doit2_socket(__FUNCTION__, LOGLEVEL_NOTE)
#define log_fatal2_context _log_doit2_context(__FUNCTION__, LOGLEVEL_FATAL)
#define log_debug2_context _log_doit2_context(__FUNCTION__, LOGLEVEL_DEBUG)
#define log_note2_context _log_doit2_context(__FUNCTION__, LOGLEVEL_NOTE)

#define SA struct sockaddr

struct PACKED_ATTRIBUTE ATPPacket{
    // apt packet layout, trivial
    // strictly aligned to 4

    // seq_nr and ack_nr are now packet-wise rather than byte-wise
    uint32_t seq_nr;
    uint32_t ack_nr;
    uint16_t peer_sock_id; uint16_t flags;

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

    CS_LISTEN,
    CS_SYN_SENT,
    CS_SYN_RECV,
    CS_RESET,

    CS_CONNECTED,
    CS_CONNECTED_FULL,

    CS_FIN_WAIT_1, // A

    // this is half cloded state. B got A's is fin, and will not send data.
    // But B can still send data, then A can send ack in response
    CS_CLOSE_WAIT, // B

    // A get ack of his fin
    CS_FIN_WAIT_2, // A

    // B sent his fin
    CS_LAST_ACK, // B
    // the end of side A, wait 2 * MSL and then goto CS_DESTROY
    CS_TIME_WAIT,
    // the end of side B
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
        set_port(_port);
    }
    const char * to_string(){
        ::inet_ntop(sa.sin_family, &addr(), fmt, INET_ADDRSTRLEN);
        return const_cast<const char *>(fmt);
    }
    const char * hash_code() {
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
    uint64_t timestamp; // microseconds
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
    const ATPPacket * get_head() const {
        return reinterpret_cast<ATPPacket *>(data);
    }
};

struct ATPSocket{
    ATPContext * context = nullptr;
    // function as "port"
    uint16_t sock_id;
    uint16_t peer_sock_id;

    ATPAddrHandle src_addr;
    ATPAddrHandle & get_src_addr(){
        if (conn_state == CS_UNINITIALIZED)
        {
            return src_addr;
        }else{
            if (src_addr.host_port() == 0 && src_addr.host_addr() == 0)
            {
            }
            socklen_t my_sock_len = sizeof(src_addr.sa);
            getsockname(sockfd, (SA*) &(src_addr.sa), &my_sock_len);
            return src_addr;
        }
    }
    ATPAddrHandle dest_addr;
    int family; int type; int protocol;
    int sockfd;

    CONN_STATE_ENUM conn_state;

    std::function<bool(OutgoingPacket*, OutgoingPacket*)> _cmp_outgoingpacket = [](OutgoingPacket* left, OutgoingPacket* right){
        return (left->get_head()->seq_nr < right->get_head()->seq_nr);
    };
    std::priority_queue<OutgoingPacket*, std::vector<OutgoingPacket*>, decltype(_cmp_outgoingpacket)> inbuf;
    SizableCircularBuffer<OutgoingPacket*> outbuf{15};

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
    ATPSocket(ATPContext * _context);
    // HELPERS
    void register_to_look_up();

    atp_callback_arguments make_atp_callback_arguments(int method, OutgoingPacket * out_pkt, const ATPAddrHandle & addr){
        if(out_pkt == nullptr){
            // there's no OutgoingPacket to be sent, so pass `nullptr`
            // out_pkt->length = 0, out_pkt->data = nullptr
            return atp_callback_arguments{
                context,
                this,
                method,
                0, nullptr, 
                (const SA*)&(addr.sa),
                sizeof(sockaddr_in)
            };
        }else{
            return atp_callback_arguments{
                context,
                this,
                method,
                out_pkt->length, out_pkt->data, 
                (const SA*)&(addr.sa),
                sizeof(sockaddr_in)
            };
        }
    }
    OutgoingPacket * basic_send_packet(uint16_t flags){
        ATPPacket pkt = ATPPacket{
            seq_nr, //seq_nr
            ack_nr, // ack_nr
            peer_sock_id, // peer_sock_id
            flags // flags
        };
        OutgoingPacket * out_pkt = new OutgoingPacket{
            true,
            sizeof (ATPPacket), // length, update by `add_data`
            0, // payload, update by `add_data`
            0, // timestamp, set at `send_packet`
            0, // transmissions, update by `send_packet`
            false, // need_resend, update by `send_packet`
            reinterpret_cast<char *>(std::calloc(1, sizeof (ATPPacket))) // SYN packet will not contain data
        };
        std::memcpy(out_pkt->data, &pkt, sizeof (ATPPacket));
        return out_pkt;
    }

    // INTERFACES
    static const int perf_norm = 1;
    static const int perf_drop = 2;
    static const int perf_cache = 3;
    void clear(){

    }
    // called by atp_create_socket
    int init(int family, int type, int protocol);
    // active connect
    int connect(const ATPAddrHandle & to_addr);
    int listen(uint16_t host_port);
    int bind(const ATPAddrHandle & to_addr);
    // passive connect
    int accept(const ATPAddrHandle & to_addr, OutgoingPacket * recv_pkt);
    int receive(char * buffer, size_t len){
        return 0;
    }
    // when a ack packet comes, update ack_nr
    int update_ack(OutgoingPacket * recv_pkt);
    // `send_packet` will take over possession of `out_pkt`
    int send_packet(OutgoingPacket * out_pkt);
    int close();
    void add_data(OutgoingPacket * out_pkt, const void * buf, const size_t len);
    int write(const void * buf, const size_t len);
    int ATPSocket::process_packet(OutgoingPacket * recv_pkt);
    int process(const ATPAddrHandle & addr, const char * buffer, size_t len);
    const char * hash_code() {
        return ATPSocket::make_hash_code(sock_id, dest_addr);
    }
    const char * to_string() {
        sprintf(hash_str, "[%05u](%s:%05u)->(%s:%05u) fd:%d", sock_id, get_src_addr().to_string(), get_src_addr().host_port()
            , dest_addr.to_string(), dest_addr.host_port(), sockfd);
        return const_cast<const char *>(hash_str);
    }
    static const char * make_hash_code(uint16_t sock_id, const ATPAddrHandle & dest_addr){
        static char hash_str[INET_ADDRSTRLEN * 2 + 5 * 2 + 10 * 3];
        sprintf(hash_str, "[%05u]%s", sock_id, dest_addr.hash_code());
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
        listen_sockets.clear();
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
        callbacks[ATP_CALL_BIND] = atp_default_bind;
        callbacks[ATP_CALL_LOG] = atp_default_log;
        callbacks[ATP_CALL_LOG_NORMAL] = atp_default_log_normal;
        callbacks[ATP_CALL_LOG_DEBUG] = atp_default_log_debug;
        callbacks[ATP_CALL_OPT_SENDBUF] = atp_default_opt_sndbuf;
        callbacks[ATP_CALL_OPT_RECVBUF] = atp_default_opt_rcvbuf;
        clear();
        std::srand(get_current_ms());
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
    std::map<uint16_t, ATPSocket *> listen_sockets;

    uint16_t new_sock_id(){
        return std::rand();
    }
};

inline ATPContext & get_context(){
    static ATPContext context;
    return context;
}
