#pragma once

#include <sys/types.h> // ssize_t
#include <sys/socket.h>
#include <sys/time.h>
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
    ATP_ON_ERROR = 0,
    ATP_ON_READ,
    ATP_GET_MILLISECONDS,
    ATP_GET_MICROSECONDS,
    ATP_SENDTO,

    // context and socket options that may be set/queried
    ATP_LOG_NORMAL,
    ATP_LOG_MTU,
    ATP_LOG_DEBUG,
    ATP_SNDBUF,
    ATP_RCVBUF,

    ATP_CALLBACK_SIZE, // must be last
};

struct atp_callback_arguments {
	atp_context * context;
	atp_socket * socket;
	ATP_CALLBACKTYPE_ENUM callback_type;
};

typedef int atp_callback_t(atp_callback_arguments *);


atp_context * atp_init();
atp_socket * atp_create_socket(atp_context * context);
int atp_connect(atp_socket * socket, const struct sockaddr * to, socklen_t tolen);
ssize_t atp_write(atp_socket * socket, void * buf, size_t count);
int	atp_process_udp(atp_socket * context, const char * buf, size_t len, const struct sockaddr * to, socklen_t tolen);
void atp_close(atp_socket * socket);

void atp_set_callback(atp_context * context, ATP_CALLBACKTYPE_ENUM callback_type, atp_callback_t * proc);

#ifdef __cplusplus
}
#endif