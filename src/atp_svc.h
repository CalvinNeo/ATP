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

#include "atp.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ATPBlockedSocket atp_blocked_socket;
typedef struct ATPContextServer atp_context_server;

atp_context * atp_create_context_server();
void atp_start_server(atp_context * context);
void atp_wait_server(atp_context * context);

atp_socket * atp_fork_blocked_socket(atp_socket * origin);
atp_socket * atp_create_blocked_socket(atp_context * context);

atp_result atp_blocked_close(atp_socket * socket);
atp_result atp_blocked_connect(atp_socket * socket, const struct sockaddr * to, socklen_t tolen);
atp_result atp_blocked_accept(atp_socket * socket);
atp_result atp_blocked_read(atp_socket * socket, void * buffer, size_t n);

#ifdef __cplusplus
}
#endif