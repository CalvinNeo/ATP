# API usages

```
atp_context * context = atp_init(); // initialize atp context
atp_socket * socket = atp_create_socket(context); // create an atp socket

struct sockaddr_in src_addr;
socklen_t addrlen = sizeof(src_addr);
atp_connect(atp_socket * socket, &src_addr, addrlen); // connect socket to address `src_addr`

unsigned char socket_data[4096];
while (true){
    int sockfd;
    size_t len = recvfrom(sockfd, socket_data, sizeof(socket_data), 0, (struct sockaddr *)&src_addr, &addrlen);
    // when an **UDP** datagram arrives with data from peer 
    // call `utp_process_udp` in which the **UDP** datagram is parsed.
    /*
    * IP Header
    * UDP Header
    * ATP Header
    * Data
    */
    utp_process_udp(context, socket_data, len, (struct sockaddr *)&src_addr, addrlen);
}
```