#pragma once
#include <netinet/in.h> // sockaddr
#include <arpa/inet.h> // inet_pton
#include <sys/socket.h> // socket

// ATPSocket wrap up the loop of connection open/close
// They use socket->sys_cache rather than user's cache
// because no user data is passed during such process
// so 1024 bytes are enough, which is less than MAX_ATP_PACKET_PAYLOAD for ordinary ATP Packets
#define SYSCACHE_MAX 1024

#if defined __GNUC__
    #define PACKED_ATTRIBUTE __attribute__((__packed__))
#else
    #define PACKED_ATTRIBUTE
#endif

#ifdef __cplusplus
extern "C" {
#endif

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

enum {
    ATP_PROC_OK = 0,
    ATP_PROC_ERROR = -1,
    // when conn_state is CS_DESTROY, socket->process returns ATP_PROC_FINISH, and invokes callbacks[ATP_CALL_ON_DESTROY]
    ATP_PROC_FINISH = -2,
    ATP_PROC_CACHE = -3,
    ATP_PROC_DROP = -4,
};

// typedef all interface struct to snakecase
typedef struct ATPSocket atp_socket;
typedef struct ATPContext atp_context;
typedef int ATP_PROC_RESULT;

enum ATP_CALLBACKTYPE_ENUM{
    ATP_CALL_ON_ERROR = 0,
    ATP_CALL_ON_PEERCLOSE,
    ATP_CALL_ON_DESTROY,
    ATP_CALL_ON_STATE_CHANGE,
    ATP_CALL_GET_READ_BUFFER_SIZE,
    ATP_CALL_GET_RANDOM,
    ATP_CALL_LOG,
    ATP_CALL_SOCKET,
    ATP_CALL_BIND,
    ATP_CALL_CONNECT,
    ATP_CALL_ON_ACCEPT,
    ATP_CALL_SENDTO,
    ATP_CALL_ON_RECV,

    ATP_CALLBACK_SIZE, // must be the last
};

struct atp_callback_arguments {
    atp_context * context;
    atp_socket * socket;
    ATP_CALLBACKTYPE_ENUM callback_type;
    size_t length; char * data; // len(data) == length
    CONN_STATE_ENUM state;
    union {
        const struct sockaddr * addr;
        int send;
        int error_code;
    };
    union {
        socklen_t addr_len;
    };
};

typedef ATP_PROC_RESULT atp_callback_func(atp_callback_arguments *);

struct atp_iovec {
    void * iov_base;
    size_t iov_len;
};

atp_context * atp_init();
atp_socket * atp_create_socket(atp_context * context);
int atp_listen(atp_socket * socket, uint16_t port);
int atp_connect(atp_socket * socket, const struct sockaddr * to, socklen_t tolen);
int atp_accept(atp_socket * socket);
int atp_write(atp_socket * socket, void * buf, size_t length);
ATP_PROC_RESULT atp_process_udp(atp_context * context, int sockfd, const char * buf, size_t len, const struct sockaddr * to, socklen_t tolen);
int atp_close(atp_socket * socket);
void atp_set_callback(atp_socket * socket, int callback_type, atp_callback_func * proc);
int atp_eof(atp_socket * socket);


struct PACKED_ATTRIBUTE CATPPacket{
    // apt packet layout, trivial
    // seq_nr and ack_nr are now packet-wise rather than byte-wise
    uint32_t seq_nr;
    uint32_t ack_nr;
    uint16_t peer_sock_id; uint16_t flags;
};

#define ETHERNET_MTU 1500
#define INTERNET_MTU 576
#define IP_MTU 65535
#define IPV4_HEADER_SIZE 20
#define IPV6_HEADER_SIZE 40
#define UDP_HEADER_SIZE 8
static const size_t MAX_UDP_PAYLOAD = 65535 - IPV4_HEADER_SIZE - UDP_HEADER_SIZE;
static const size_t MAX_ATP_WRITE_SIZE = 65535;
static const size_t MAX_ATP_PACKET_PAYLOAD = ETHERNET_MTU - IPV4_HEADER_SIZE - UDP_HEADER_SIZE - sizeof(CATPPacket);

#ifdef __cplusplus
}
#endif