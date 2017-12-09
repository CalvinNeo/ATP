#include "atp_impl.h"
#include "udp_util.h"
void init_callbacks(ATPSocket * socket){
    socket->callbacks[ATP_CALL_ON_ERROR] = nullptr; 
    socket->callbacks[ATP_CALL_ON_PEERCLOSE] = [](atp_callback_arguments * args){
        atp_socket * socket = args->socket;
        #if defined (ATP_LOG_AT_DEBUG)
            log_debug(socket, "Finish myself immediately when recv FIN from peer.");
        #endif
        return socket->close();
    };
    socket->callbacks[ATP_CALL_ON_DESTROY] = [](atp_callback_arguments * args){
        atp_socket * socket = args->socket;
        #if defined (ATP_LOG_AT_DEBUG)
            log_debug(socket, "Destroy socket.");
        #endif
        return ATP_PROC_FINISH;
    };
    socket->callbacks[ATP_CALL_ON_STATE_CHANGE] = nullptr;
    socket->callbacks[ATP_CALL_GET_READ_BUFFER_SIZE] = nullptr;
    socket->callbacks[ATP_CALL_GET_RANDOM] = nullptr;
    socket->callbacks[ATP_CALL_LOG] = nullptr;
    socket->callbacks[ATP_CALL_SOCKET] = nullptr;
    socket->callbacks[ATP_CALL_CONNECT] = nullptr;
    socket->callbacks[ATP_CALL_ON_ACCEPT] = nullptr;
    socket->callbacks[ATP_CALL_BIND] = [](atp_callback_arguments * args){
        atp_socket * socket = args->socket;
        const struct sockaddr * sa = args->addr;
        socklen_t len = args->addr_len;
        int n = ::bind(socket->sockfd, sa, len);
        if(n < 0){
            return ATP_PROC_ERROR;
        }else{
            return ATP_PROC_OK;
        }
    };
    socket->callbacks[ATP_CALL_SENDTO] = [](atp_callback_arguments * args){
        atp_socket * socket = args->socket;
        const struct sockaddr * sa = args->addr;
        int n = sendto(socket->sockfd, args->data, args->length, 0, sa, args->addr_len);
        #if defined (ATP_LOG_AT_DEBUG) && defined(ATP_LOG_UDP)
            // const sockaddr_in * sk = (const sockaddr_in *)sa;
            ATPAddrHandle handle(sa);
            log_debug(socket, "Call sendto port:%s .", handle.hash_code());
        #endif
        if(n != args->length){
            return ATP_PROC_ERROR;
        }else{
            return ATP_PROC_OK;
        }
    };
    socket->callbacks[ATP_CALL_ON_RECV] = nullptr;
}

