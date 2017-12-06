#include "atp_impl.h"


atp_context * atp_init(){
    get_context().init();
    return &get_context();
}
atp_socket * atp_create_socket(atp_context * context){
    ATPSocket * socket = new ATPSocket(context);
    context->sockets.push_back(socket);
}
int atp_connect(atp_socket * socket, const struct sockaddr * to, socklen_t tolen){

}
int atp_write(atp_socket * socket, void * buf, size_t count){

}
int atp_process_udp(atp_context * context, const char * buf, size_t len, const struct sockaddr * to, socklen_t tolen){
    ATPAddrHandle handle(to);
    std::string hashing = std::string(handle.hash_code());
    std::map<std::string, ATPSocket*>::iterator iter = context->look_up.find(hashing);
    if(iter != context->look_up.end()){
        ATPSocket * socket = iter->second;
        ATPAddrHandle to_addr{to};
        socket->process(to_addr, buf, len);
    } else{
        // there's no such socket
        return -1;
    }
}
void atp_close(atp_socket * socket){

}