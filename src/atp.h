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

#include <stdint.h>

#include <sys/types.h> // ssize_t
#include "atp_common.h"
// API of ATP

#ifdef __cplusplus
extern "C" {
#endif

enum atp_api_options{
    ATP_API_SACKOPT,
    ATP_API_SOCKID,
};

atp_context * atp_create_server_context();
atp_context * atp_create_context();
atp_socket * atp_create_socket(atp_context * context);
int atp_getfd(atp_socket * socket);
atp_result atp_listen(atp_socket * socket, uint16_t port);
// set callback ATP_CALL_ON_ESTABLISHED before calling
atp_result atp_async_connect(atp_socket * socket, const struct sockaddr * to, socklen_t tolen);
atp_result atp_connect(atp_socket * socket, const struct sockaddr * to, socklen_t tolen);
atp_result atp_async_accept(atp_socket * socket, const struct sockaddr * to, socklen_t tolen);
atp_result atp_accept(atp_socket * socket);
atp_result atp_write(atp_socket * socket, void * buf, size_t length);
atp_result atp_process_udp(atp_context * context, int sockfd, const char * buf, size_t len, const struct sockaddr * to, socklen_t tolen);
atp_result atp_timer_event(atp_context * context, uint64_t interval);
atp_result atp_close(atp_socket * socket);
atp_result atp_async_close(atp_socket * socket);
void atp_set_callback(atp_socket * socket, int callback_type, atp_callback_func * proc);
atp_result atp_eof(atp_socket * socket);
atp_result atp_sending_status(atp_socket * socket);
bool atp_destroyed(atp_socket * socket);
void atp_set_long(atp_socket * socket, size_t option, size_t value);
size_t atp_get_long(atp_socket * socket, size_t option);

#ifdef __cplusplus
}
#endif