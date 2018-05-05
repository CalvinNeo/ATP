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
#include "udp_util.h"

sigfunc_t * setup_signal(int signo, sigfunc_t *func)
{
    struct sigaction act, oact;
    act.sa_handler = func;
    sigemptyset(&act.sa_mask);
    act.sa_flags = 0;
    if (sigaction(signo, &act, &oact) < 0)
        return SIG_ERR;
    return(oact.sa_handler);
}

struct sockaddr_in make_socketaddr_in(int family, const char * ipaddr_str, int port){
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof addr);
    addr.sin_family = family;
    addr.sin_port = htons(port);

    if(ipaddr_str == nullptr) {
        addr.sin_addr.s_addr = htonl(INADDR_ANY);
    }
    else {
        int n;
        if ((n = inet_pton(family, ipaddr_str, &addr.sin_addr)) < 0)
            err_sys("inet_pton error -1"); 
        else if (n == 0)
            err_sys("inet_pton error 0"); 
    }

    return addr;
}

inline int make_socket(int family, int type, int protocol) {
    int sockfd;

    if ((sockfd = socket(family, type, protocol)) < 0)
        err_sys("socket error");

    return sockfd;
}