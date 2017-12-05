#include "udp_util.h"

Sigfunc * signal(int signo, Sigfunc *func)
{
    struct sigaction act, oact;
    act.sa_handler = func;
    sigemptyset(&act.sa_mask);
    act.sa_flags = 0;
    if (sigaction(signo, &act, &oact) < 0)
        return(SIG_ERR);
    return(oact.sa_handler);
}

int make_socket(int family, int type, int protocol, int port, const char * ipaddr_str) {
    int sockfd;
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof addr);
    addr.sin_family = family;
    addr.sin_port = htons(port);

    if ((sockfd = socket(family, type, protocol)) < 0)
        err_sys("socket error");

    int n;
    if(ipaddr_str == nullptr) {
        addr.sin_addr.s_addr = htonl(INADDR_ANY);
    }
    else {
        if ((n = inet_pton(family, ipaddr_str, &addr.sin_addr)) < 0)
            err_sys("inet_pton error -1"); 
        else if (n == 0)
            err_sys("inet_pton error 0"); 
    }
    return sockfd;
}