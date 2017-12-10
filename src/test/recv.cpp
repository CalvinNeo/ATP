#include "../atp.h"
#include "../atp_impl.h"
#include "../udp_util.h"
#include <iostream>

ATP_PROC_RESULT data_arrived(atp_callback_arguments * args){
    atp_socket * socket = args->socket;
    size_t length = args->length; 
    const char * data = args->data;

    printf("data arrived: %.*s\n", length, data);
    return ATP_PROC_OK;
}

int main(){
    uint16_t serv_port = 9876;
    struct sockaddr_in cli_addr; socklen_t cli_len = sizeof(cli_addr);
    struct sockaddr_in srv_addr;

    char msg[ATP_MIN_BUFFER_SIZE];
    char ipaddr_str[INET_ADDRSTRLEN];
    int n;

    atp_context * context = atp_init();
    atp_socket * socket = atp_create_socket(context);
    atp_set_callback(socket, ATP_CALL_ON_RECV, data_arrived);

    srv_addr = make_socketaddr_in(AF_INET, nullptr, serv_port);

    if (bind(socket->sockfd, (SA *) &srv_addr, sizeof srv_addr) < 0)
        err_sys("bind error");

    atp_listen(socket, serv_port);
    atp_accept(socket);

    while (true) {
        sockaddr * pcli_addr = (SA *)&cli_addr;

        if ((n = recvfrom(socket->sockfd, msg, ATP_MIN_BUFFER_SIZE, 0, pcli_addr, &cli_len)) < 0)
            err_sys("recvfrom error");
        ATP_PROC_RESULT result = atp_process_udp(context, socket->sockfd, msg, n, (const SA *)&cli_addr, cli_len);
        if (result == ATP_PROC_FINISH)
        {
            break;
        }
    }
    return 0;
}