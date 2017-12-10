#include "../atp.h"
#include "../atp_impl.h"
#include "../udp_util.h"
#include <poll.h>


int main(){
    uint16_t serv_port = 9876;
    struct sockaddr_in cli_addr; 
    struct sockaddr_in srv_addr; socklen_t srv_len = sizeof(srv_addr);

    char msg[ATP_MSS_CEILING];
    char ipaddr_str[INET_ADDRSTRLEN];
    int n;

    atp_context * context = atp_init();
    atp_socket * socket = atp_create_socket(context);

    srv_addr = make_socketaddr_in(AF_INET, "127.0.0.1", serv_port);
    atp_connect(socket, (const SA *)&srv_addr, sizeof srv_addr);

    while (fgets(msg, ATP_MSS_CEILING, stdin) != NULL) {
        n = strlen(msg);
        atp_write(socket, msg, n);
        sockaddr * psock_addr = (SA *)&srv_addr;

        if ((n = recvfrom(socket->sockfd, msg, ATP_MSS_CEILING, 0, psock_addr, &srv_len)) < 0)
            err_sys("recvfrom error");
        ATP_PROC_RESULT result = atp_process_udp(context, socket->sockfd, msg, n, (const SA *)&srv_addr, srv_len);
        if (result == ATP_PROC_FINISH)
        {
            break;
        }
    }
    atp_close(socket);
    return 0;
}