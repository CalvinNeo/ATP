#include "atp_impl.h"


atp_context * atp_init(){
    
}
atp_socket * atp_create_socket(atp_context * ctx){

}
int atp_connect(atp_socket * socket, const struct sockaddr * to, socklen_t tolen){

}
ssize_t atp_write(atp_socket * socket, void * buf, size_t count){

}
int	atp_process_udp(atp_socket * context, const char * buf, size_t len, const struct sockaddr * to, socklen_t tolen){

}
void atp_close(atp_socket * socket){

}