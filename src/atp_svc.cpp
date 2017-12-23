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

#include "atp_impl.h"
#include "udp_util.h"
#include "atp.h"
#include <poll.h>


struct ATPContextSVC{
    ATPContext * context;
    void start_timer(){

    }
    void stop_timer(){

    }
    ATPContextSVC(){
        context = new ATPContext();
        context->init();
    }
};

ATPContextSVC & get_contextsvc(){
    static ATPContextSVC contextsvc;
    return contextsvc;
}

atp_context * atp_create_server_context(){
    return get_contextsvc().context;
}