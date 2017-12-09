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


    while (fgets(msg, MAXLINE, stdin) != NULL) {
        n = strlen(msg);
        atp_write(socket, msg, n);
    }
    atp_close(socket);
    return 0;
}