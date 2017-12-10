#pragma once

#include <stdint.h>

#include <sys/types.h> // ssize_t
#include "atp_common.h"
// API of ATP

#ifdef __cplusplus
extern "C" {
#endif

atp_context * atp_init();
atp_socket * atp_create_socket(atp_context * context);
ATP_PROC_RESULT atp_listen(atp_socket * socket, uint16_t port);
ATP_PROC_RESULT atp_async_connect(atp_socket * socket, const struct sockaddr * to, socklen_t tolen);
ATP_PROC_RESULT atp_connect(atp_socket * socket, const struct sockaddr * to, socklen_t tolen);
ATP_PROC_RESULT atp_async_accept(atp_socket * socket, const struct sockaddr * to, socklen_t tolen);
ATP_PROC_RESULT atp_accept(atp_socket * socket);
ATP_PROC_RESULT atp_write(atp_socket * socket, void * buf, size_t length);
ATP_PROC_RESULT atp_process_udp(atp_context * context, int sockfd, const char * buf, size_t len, const struct sockaddr * to, socklen_t tolen);
int atp_close(atp_socket * socket);
void atp_set_callback(atp_socket * socket, int callback_type, atp_callback_func * proc);
int atp_eof(atp_socket * socket);


#ifdef __cplusplus
}
#endif