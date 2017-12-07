#include "../atp.h"
#include "../atp_impl.h"
#include "../udp_util.h"

int main(){
    atp_context * context = atp_init();
    atp_socket * atp_sock = atp_create_socket(context);

    uint16_t serv_port = 9876;

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_port = htons(serv_port);
    atp_connect(atp_sock, (const SA *)&addr, sizeof addr);
    return 0;
}