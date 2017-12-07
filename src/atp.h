#pragma once

#include <sys/types.h> // ssize_t
#include <sys/socket.h>
#include <netinet/in.h> // sockaddr
#include <arpa/inet.h>

#include <stdint.h>

// API of ATP

#ifdef __cplusplus
extern "C" {
#endif

// typedef all interface struct to snakecase

typedef struct ATPSocket atp_socket;
typedef struct ATPContext atp_context;


enum ATP_CALLBACKTYPE_ENUM{
    ATP_CALL_ON_ACCEPT = 0,
    ATP_CALL_ON_ERROR,
    ATP_CALL_ON_READ,
    ATP_CALL_ON_STATE_CHANGE,
    ATP_CALL_GET_READ_BUFFER_SIZE,
    ATP_CALL_GET_RANDOM,
    ATP_CALL_LOG,
    ATP_CALL_SENDTO,
    ATP_CALL_CONNECT,
    ATP_CALL_BIND,

    // context and socket options that may be set/queried
    ATP_CALL_LOG_NORMAL,
    ATP_CALL_LOG_DEBUG,
    ATP_CALL_OPT_SENDBUF,
    ATP_CALL_OPT_RECVBUF,

    ATP_CALLBACK_SIZE, // must be the last
};

struct atp_callback_arguments {
	atp_context * context;
	atp_socket * socket;
	ATP_CALLBACKTYPE_ENUM callback_type;
    size_t length; char * data; // len(data) == length

    union {
        const struct sockaddr * addr;
        int send;
        int error_code;
        int state;
    };
    union {
        socklen_t addr_len;
    };
};

typedef int atp_callback_func(atp_callback_arguments *);


struct atp_iovec {
    void * iov_base;
    size_t iov_len;
};


atp_context * atp_init();
atp_socket * atp_create_socket(atp_context * context);
int atp_connect(atp_socket * socket, const struct sockaddr * to, socklen_t tolen);
int atp_write(atp_socket * socket, void * buf, size_t length);
int	atp_process_udp(atp_context * context, const char * buf, size_t len, const struct sockaddr * to, socklen_t tolen);
int atp_close(atp_socket * socket);
void atp_set_callback(atp_context * context, atp_socket * socket, atp_callback_func * proc);

#ifdef __cplusplus
}
#endif