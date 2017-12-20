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
#include "../atp.h"
#include "../udp_util.h"
#include "../atp_impl.h"
#include <unistd.h>
#include <fcntl.h>
#include <aio.h>

#define sigev_notify_function   _sigev_un._sigev_thread._function
#define sigev_notify_attributes _sigev_un._sigev_thread._attribute
#define sigev_notify_thread_id   _sigev_un._tid

struct sockaddr_in srv_addr; socklen_t srv_len = sizeof(srv_addr);
char textmsg[ATP_MIN_BUFFER_SIZE];


bool closed = false;

// make C happy
std::function<void(sigval_t)> signal_callback;
static void aio_completion_handler(atp_context * context, sigval_t sigval)
{
    struct aiocb * my_aiocb = (struct aiocb *)sigval.sival_ptr;
    const char * msg = my_aiocb->aio_buf;
    int n = my_aiocb->aio_nbytes;
    int sockfd = my_aiocb->aio_fildes;

    if(aio_error(my_aiocb) == 0)
    {
        // if success, get return
        n = aio_return(my_aiocb);
        ATPPacket * pkt = (ATPPacket *)msg;
        ATP_PROC_RESULT result = atp_process_udp(context, sockfd, msg, n, (const SA *)&srv_addr, srv_len);
    }
}

static void signal_alarm_entry(sigval_t sigval){
    signal_callback(sigval);
}

int main(){
    using namespace std::placeholders;
    uint16_t serv_port = 9876;

    int n;
    atp_context * context;
    context = atp_init();
    atp_socket * socket = atp_create_socket(context);
    int sockfd = atp_getfd(socket);

    // aio
    struct aiocb my_aiocb;
    memset(&my_aiocb, 0, sizeof my_aiocb);
    my_aiocb.aio_buf = malloc(ATP_MAX_READ_BUFFER_SIZE);
    my_aiocb.aio_fildes = sockfd;
    my_aiocb.aio_nbytes = ATP_MAX_READ_BUFFER_SIZE - 1;
    my_aiocb.aio_offset = 0;

    my_aiocb.aio_sigevent.sigev_notify = SIGEV_THREAD;
    typedef void (*function_t) (sigval_t);
    signal_callback = std::bind(aio_completion_handler, context, _1);
    my_aiocb.aio_sigevent.sigev_notify_function = signal_alarm_entry;
    my_aiocb.aio_sigevent.sigev_notify_attributes = NULL;
    my_aiocb.aio_sigevent.sigev_value.sival_ptr = &my_aiocb;

    srv_addr = make_socketaddr_in(AF_INET, "127.0.0.1", serv_port);
    atp_async_connect(socket, (const SA *)&srv_addr, sizeof srv_addr);

    while(true){
        aio_read(&my_aiocb);
        if(atp_timer_event(context, 1000) == ATP_PROC_FINISH){
            break;
        }
        if(!closed && fgets(textmsg, ATP_MIN_BUFFER_SIZE, stdin) == NULL){
            if (feof(stdin)){
                atp_async_close(socket);
                closed = true;
                continue;
            }else{
                continue;
            }
        }
        n = strlen(textmsg);
        atp_write(socket, textmsg, n);
        usleep(500 * 1000); // sleep 500ms
    }
    return 0;
};