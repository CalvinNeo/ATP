#include "../atp.h"
#include "../atp_impl.h"
#include "../udp_util.h"

#define MAXLINE 4096

int main(){
    uint16_t serv_port = 9876;
    struct sockaddr_in cli_addr;
    struct sockaddr_in srv_addr; socklen_t srv_len = sizeof(srv_addr);

    char msg[MAXLINE];
    char ipaddr_str[INET_ADDRSTRLEN];
    int n;

    atp_context * context = atp_init();
    atp_socket * socket = atp_create_socket(context);

    srv_addr = make_socketaddr_in(AF_INET, "127.0.0.1", serv_port);
    atp_connect(socket, (const SA *)&srv_addr, sizeof srv_addr);

    while (true) {
        sockaddr * psrv_addr = (SA *)&srv_addr;

        if ((n = recvfrom(socket->sockfd, msg, MAXLINE, 0, psrv_addr, &srv_len)) < 0)
            err_sys("recvfrom error");
        ATPAddrHandle handle((const SA *)&srv_addr);
        sockaddr_in * sai = (sockaddr_in *)psrv_addr;
        atp_process_udp(context, socket->sockfd, msg, n, (const SA *)&srv_addr, srv_len);
    }

    return 0;
}