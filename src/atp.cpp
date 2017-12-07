#include "atp_impl.h"


atp_context * atp_init(){
    get_context().init();
    return &get_context();
}
atp_socket * atp_create_socket(atp_context * context){
    ATPSocket * socket = new ATPSocket(context);
    socket->init(AF_INET, SOCK_DGRAM, 0);
    // now this socket is registered to context
    // but it will not be able to locate until is connected
    // thus it will have a (addr:port), and `register_to_look_up` will be called
    // and the socket will be insert into context->look_up
    context->sockets.push_back(socket);
    return socket;
}
int atp_connect(atp_socket * socket, const struct sockaddr * to, socklen_t tolen){
    ATPAddrHandle handle(to);
    return socket->connect(to);
}
int atp_write(atp_socket * socket, void * buf, size_t length){
    return socket->write(buf, length);
}
int atp_process_udp(atp_context * context, const char * buf, size_t len, const struct sockaddr * to, socklen_t tolen){
    ATPAddrHandle handle(to);
    const ATPPacket * pkt = reinterpret_cast<const ATPPacket *>(buf);
    std::string hashing = std::string(ATPSocket::make_hash_code(pkt->peer_sock_id, handle));
    std::map<std::string, ATPSocket*>::iterator iter = context->look_up.find(hashing);
    if(iter != context->look_up.end()){
        ATPSocket * socket = iter->second;
        ATPAddrHandle to_addr{to};
        return socket->process(to_addr, buf, len);
    } else{
        // there's no such socket
        #if defined (ATP_LOG ) && ATP_LOG >= LOGLEVEL_DEBUG
            log_debug(context, "Can't locate socket:%s", hashing.c_str());
        #endif
        return -1;
    }
}
int atp_close(atp_socket * socket){
    return socket->close();
}