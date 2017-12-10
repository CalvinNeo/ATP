#include "atp_impl.h"
#include "udp_util.h"

atp_context * atp_init(){
    get_context().init();
    return &get_context();
}

static void sys_loop(atp_socket * socket, std::function<int(atp_socket*)> predicate){ 
    while (true) {
        struct sockaddr_in peer_addr; socklen_t peer_len = sizeof(peer_addr);
        sockaddr * ppeer_addr = (SA *)&peer_addr;
        int n = recvfrom(socket->sockfd, socket->sys_cache, SYSCACHE_MAX, 0, ppeer_addr, &peer_len);
        if (n < 0)
            return -1;
        ATPAddrHandle handle_to((const SA *)&peer_addr);
        socket->process(handle_to, socket->sys_cache, n);
        if (predicate(socket) == 0)
        {
            return 0;
        }
    }
    return 0;
}

atp_socket * atp_create_socket(atp_context * context){
    ATPSocket * socket = new ATPSocket(context);
    int sockfd = socket->init(AF_INET, SOCK_DGRAM, 0);
    // now this socket is registered to context
    // but it will not be able to locate until is connected
    // thus it will have a (addr:port), and `register_to_look_up` will be called
    // and the socket will be insert into context->look_up
    context->sockets.push_back(socket);
    return socket;
}

int atp_connect(atp_socket * socket, const struct sockaddr * to, socklen_t tolen){
    ATPAddrHandle handle(to);
    int n;
    socket->connect(to);
    sys_loop(socket, [](atp_socket*socket){
        if (socket->conn_state >= CS_CONNECTED)
        {
            return 0;
        }
        return 1;
    });
    return 0;
}

int atp_listen(atp_socket * socket, uint16_t host_port){
    assert(socket != nullptr);
    return socket->listen(host_port);
}

int atp_accept(atp_socket * socket){
    sys_loop(socket, [](atp_socket*socket){
        if (socket->conn_state >= CS_CONNECTED)
        {
            return 0;
        }
        return 1;
    });
    return 0;
}

int atp_write(atp_socket * socket, void * buf, size_t length){
    assert(socket != nullptr);
    return socket->write(buf, length);
}

ATP_PROC_RESULT atp_process_udp(atp_context * context, int sockfd, const char * buf, size_t len, const struct sockaddr * to, socklen_t tolen){
    assert(context != nullptr);
    ATPAddrHandle handle_to(to);
    if (handle_to.host_port() == 0 && handle_to.host_addr() == 0)
    {
        // error
        #if defined (ATP_LOG_AT_DEBUG)
            log_debug(context, "Can't locate socket:[0.0.0.0:00000]");
        #endif
        return ATP_PROC_ERROR;
    }
    const ATPPacket * pkt = reinterpret_cast<const ATPPacket *>(buf);
    bool is_active_connect = pkt->get_syn() && !(pkt->get_ack());
    if (is_active_connect)
    {
        // find in listen
        sockaddr_in my_sock; socklen_t my_sock_len = sizeof(my_sock);
        getsockname(sockfd, (SA*) &my_sock, &my_sock_len);
        ATPAddrHandle handle_me((SA*) &my_sock);

        std::map<uint16_t, ATPSocket*>::iterator iter = context->listen_sockets.find(handle_me.host_port());
        if(iter != context->listen_sockets.end()){
            ATPSocket * socket = iter->second;
            return socket->process(handle_to, buf, len);
        } else{
            #if defined (ATP_LOG_AT_DEBUG)
                log_debug(context, "Can't locate listening socket:%u %u", handle_me.host_port());
            #endif
            return ATP_PROC_ERROR;
        }
    } else{
        std::string hashing = std::string(ATPSocket::make_hash_code(pkt->peer_sock_id, handle_to));
        std::map<std::string, ATPSocket*>::iterator iter = context->look_up.find(hashing);
        if(iter != context->look_up.end()){
            ATPSocket * socket = iter->second;
            return socket->process(handle_to, buf, len);
        } else{
            // there's no such socket
            #if defined (ATP_LOG_AT_DEBUG)
                std::string ext;
                for(std::map<std::string, ATPSocket*>::value_type & pr : context->look_up)
                {
                    ext += pr.first;
                    ext += '\n';
                }
                log_debug(context, "Can't locate socket:%s, the exsiting %u sockets are: %s\n"
                    , hashing.c_str(), context->look_up.size(), ext.c_str());
            #endif
            return ATP_PROC_ERROR;
        }
    }
}

int atp_close(atp_socket * socket){
    assert(socket != nullptr);
    #if defined (ATP_LOG_AT_DEBUG)
        log_debug(socket, "User called atp_close");
    #endif
    socket->close();
    sys_loop(socket, [](atp_socket*socket){
        if (socket->conn_state == CS_DESTROY)
        {
            return 0;
        }
        return 1;
    });
    return 0;
}

void atp_set_callback(atp_socket * socket, int callback_type, atp_callback_func * proc){
    socket->callbacks[callback_type] = proc;
}

int atp_eof(atp_socket * socket){
    return socket->readable();
}