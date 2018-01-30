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
#include <netinet/in.h> // sockaddr
#include <arpa/inet.h> // inet_pton
#include <sys/socket.h> // socket

// ATPSocket wrap up the loop of connection open/close
// They use socket->sys_cache rather than user's cache
// because no user data is passed during such process
// so 1024 bytes are enough, which is less than ATP_MSS_CEILING for ordinary ATP Packets
#define ATP_SYSCACHE_MAX 64

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
    ATP_PROC_REJECT = -5,
    ATP_PROC_WAIT = -6,
};

// typedef all interface struct to snakecase
typedef struct ATPSocket atp_socket;
typedef struct ATPContext atp_context;
typedef int ATP_PROC_RESULT;
typedef ATP_PROC_RESULT atp_result;

enum ATP_CALLBACKTYPE_ENUM{
    ATP_CALL_ON_ERROR = 0,
    ATP_CALL_ON_STATE_CHANGE,
    ATP_CALL_GET_READ_BUFFER_SIZE,

    ATP_CALL_GET_RANDOM,
    ATP_CALL_LOG,
    ATP_CALL_SOCKET,
    ATP_CALL_BIND,
    ATP_CALL_CONNECT,
    ATP_CALL_BEFORE_ACCEPT,
    ATP_CALL_ON_ACCEPT,
    ATP_CALL_ON_ESTABLISHED,
    ATP_CALL_SENDTO,
    ATP_CALL_ON_RECV,
    ATP_CALL_ON_PEERCLOSE,
    ATP_CALL_ON_DESTROY,

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

typedef atp_result atp_callback_func(atp_callback_arguments *);

struct atp_iovec {
    void * iov_base;
    size_t iov_len;
};

struct PACKED_ATTRIBUTE CATPPacket{
    // ATP packet layout, trivial
    // seq_nr and ack_nr are now packet-wise rather than byte-wise
    uint16_t seq_nr; 
    uint16_t ack_nr;
    uint16_t peer_sock_id; 
    uint8_t opts_count; uint8_t flags;
    uint16_t window_size;
};

#define ETHERNET_MTU 1500
#define INTERNET_MTU 576
#define ATP_IP_MTU 65535
#define IPV4_HEADER_SIZE 20
#define IPV6_HEADER_SIZE 40
#define UDP_HEADER_SIZE 8
#define TCP_DEFAULT_MSS 536
static const size_t MAX_UDP_PAYLOAD = ATP_IP_MTU - IPV4_HEADER_SIZE - UDP_HEADER_SIZE;
static const size_t MAX_ADP_PAYLOAD = ATP_IP_MTU - IPV4_HEADER_SIZE - UDP_HEADER_SIZE - sizeof(CATPPacket);
// Max size of an ATPPacket(including head)
static const size_t ATP_MAX_WRITE_BUFFER_SIZE = MAX_UDP_PAYLOAD;
static const size_t ATP_MAX_READ_BUFFER_SIZE = MAX_UDP_PAYLOAD;
// recommended size of buffer, when calling write once, +1 is for the last '\0'
static const size_t ATP_MIN_BUFFER_SIZE = ETHERNET_MTU - IPV4_HEADER_SIZE - sizeof(CATPPacket) - UDP_HEADER_SIZE;
// The "MSS" to avoid IP fragmentation, range from [ATP_MSS_CEILING, ATP_MSS_FLOOR]
static const size_t ATP_MSS_CEILING = ETHERNET_MTU - IPV4_HEADER_SIZE - UDP_HEADER_SIZE - sizeof(CATPPacket);
static const size_t ATP_MSS_FLOOR = INTERNET_MTU - IPV4_HEADER_SIZE - UDP_HEADER_SIZE - sizeof(CATPPacket);

#define ATP_RTO_MIN 1000
// TCP recommends 120000
#define ATP_RTO_MAX 12000
// Time event interval is close to ATP_RTO_MIN may cause re-sending
#define ATP_TIMEEVENT_INTERVAL_MAX 500

#ifdef __cplusplus
}
#endif