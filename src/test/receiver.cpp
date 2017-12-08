#include "../atp.h"
#include "../atp_impl.h"
#include "../udp_util.h"
#include <iostream>

#define MAXLINE 4096

int main(){
    uint16_t serv_port = 9876;
    struct sockaddr_in cli_addr; socklen_t cli_len = sizeof(cli_addr);
    struct sockaddr_in srv_addr;

    char msg[MAXLINE];
    char ipaddr_str[INET_ADDRSTRLEN];
    int n;

    atp_context * context = atp_init();
    atp_socket * socket = atp_create_socket(context);

    srv_addr = make_socketaddr_in(AF_INET, nullptr, serv_port);

    if (bind(socket->sockfd, (SA *) &srv_addr, sizeof srv_addr) < 0)
        err_sys("bind error");

    atp_listen(socket, serv_port);

    while (true) {
        sockaddr * pcli_addr = (SA *)&cli_addr;

        if ((n = recvfrom(socket->sockfd, msg, MAXLINE, 0, pcli_addr, &cli_len)) < 0)
            err_sys("recvfrom error");
        ATPAddrHandle handle((const SA *)&cli_addr);
        sockaddr_in * sai= (sockaddr_in *)pcli_addr;
        // printf("====receive from %s port %d\n", inet_ntop(AF_INET, &(sai->sin_addr), ipaddr_str, INET_ADDRSTRLEN), ntohs(sai->sin_port));
        atp_process_udp(context, socket->sockfd, msg, n, (const SA *)&cli_addr, cli_len);
    }

    return 0;
}