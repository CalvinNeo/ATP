#pragma once

#include <stdint.h>

#include <sys/types.h> // ssize_t
#include <sys/socket.h>
#include <netinet/in.h> // sockaddr
#include <arpa/inet.h>
#include "atp_common.h"
// API of ATP

#ifdef __cplusplus
extern "C" {
#endif

// typedef all interface struct to snakecase

typedef struct ATPSocket atp_socket;
typedef struct ATPContext atp_context;


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
ATP_PROC_RESULT	atp_process_udp(atp_context * context, int sockfd, const char * buf, size_t len, const struct sockaddr * to, socklen_t tolen);
int atp_close(atp_socket * socket);
void atp_set_callback(atp_socket * socket, int callback_type, atp_callback_func * proc);
int atp_eof(atp_socket * socket);

#ifdef __cplusplus
}
#endif