/*
*   Calvin Neo
*   Copyright (C) 2017  Calvin Neo <calvinneo@calvinneo.com>
*   https://github.com/CalvinNeo/ATP
*
*   This program is free software; you can redistribute it and/or modify
*   it under the terms of the GNU General Public License as published by
*   the Free Software Foundation; either version 2 of the License, or
*   (at your option) any later version.
*
*   This program is distributed in the hope that it will be useful,
*   but WITHOUT ANY WARRANTY; without even the implied warranty of
*   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
*   GNU General Public License for more details.
*
*   You should have received a copy of the GNU General Public License along
*   with this program; if not, write to the Free Software Foundation, Inc.,
*   51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/
#include "atp_impl.h"
#include <sstream>

const char * CONN_STATE_STRS []= {
    "CS_UNINITIALIZED",
    "CS_IDLE",
    "CS_LISTEN",
    "CS_SYN_SENT",
    "CS_SYN_RECV",
    "CS_RESET",
    "CS_CONNECTED",
    "CS_CONNECTED_FULL",
    "CS_FIN_WAIT_1",
    "CS_CLOSE_WAIT",
    "CS_FIN_WAIT_2",
    "CS_LAST_ACK", 
    "CS_TIME_WAIT",
    "CS_DESTROY",
    "CS_STATE_COUNT"
};

std::string tabber(const std::string & src, bool tail_crlf) {
    std::string newline;
    std::string ans = "";
    std::istringstream f(src);
    while (std::getline(f, newline)) {
        ans += '\t';
        ans += newline;
        ans += '\n';
    }
    if (!tail_crlf && ans.back() == '\n')
    {
        return ans.substr(0, ans.size() - 1);
    }
    return ans;
}

static std::string OutgoingPacket::get_flags_str(OutgoingPacket const * out_pkt) {
    ATPPacket * pkt = out_pkt->get_head();
    std::string type;
    if (pkt->get_syn())
    {
        type += "S";
    }
    if (pkt->get_fin())
    {
        type += "F";
    }
    if (pkt->get_ack())
    {
        type += "A";
    }
    if (pkt->get_rst())
    {
        type += "R";
    }
    if (pkt->get_urg())
    {
        type += "U";
    }
    if (pkt->opts_count > 0)
    {
        type += "O";
    }
    if (out_pkt->has_user_data())
    {
        type += "D";
    }
    return type;
}

void ATPContext::clear(){
    for(ATPSocket * socket : sockets){
        delete (socket);
        socket = nullptr;
    }
    sockets.clear();
    look_up.clear();
    listen_sockets.clear();
}
void ATPContext::init(){
    clear();
    start_ms = get_current_ms();
    std::srand(start_ms);
}

uint16_t ATPContext::new_sock_id(){
    uint16_t s = 0;
    while(s == 0){
        s = std::rand();
    }
    return s;
}

void ATPContext::destroy(ATPSocket * socket){
    #if defined (ATP_LOG_AT_DEBUG)
        log_debug(socket, "Context are destroying me. Goodbye. There are %u sockets left in the context including me", sockets.size());
    #endif
    auto iter = std::find(sockets.begin(), sockets.end(), socket);
    sockets.erase(iter);
    auto map_iter1 = look_up.find(socket->hash_code());
    if (map_iter1 != look_up.end())
    {
        look_up.erase(map_iter1);
    }
    auto map_iter2 = listen_sockets.find(socket->get_local_addr().host_port());
    if (map_iter2 != listen_sockets.end())
    {
        listen_sockets.erase(map_iter2);
    }
    delete socket;
}
    
ATP_PROC_RESULT ATPContext::daily_routine(){
    // notify all exsiting sockets
    // trigger1: once a message arrived
    // trigger2: timeout
    ATP_PROC_RESULT result = ATP_PROC_OK;
    for(ATPSocket * socket: this->sockets){
        ATP_PROC_RESULT sub_result = socket->check_timeout();
        if (sub_result == ATP_PROC_ERROR)
        {
            result = ATP_PROC_ERROR;
        }else if (sub_result == ATP_PROC_OK)
        {
            result = ATP_PROC_OK;
        }else if (sub_result == ATP_PROC_FINISH)
        {
            // one socket calling on finish won't finish the context,
            // because other sockets may still be alive
            result = ATP_PROC_OK;
        }else{
            result = ATP_PROC_OK;
        }
    } 
    // clear destroyed sockets
    for(ATPSocket * socket : destroyed_sockets){
        this->destroy(socket);
    }
    destroyed_sockets.clear();
    if (this->sockets.size() == 0 && this->destroyed_sockets.size() == 0)
    {
        #if defined (ATP_LOG_AT_DEBUG)
            log_debug(this, "Context finished.");
        #endif
        // There's no sockets active
        // Case 1: If ATP is built in an user program, user catchs the return value ATP_PROC_FINISH,
        // if he has no other missions, he can destroy the context safely by calling `exit(0)`
        // Case 2: If ATP is a service, user should not handle the return value ATP_PROC_FINISH,
        return ATP_PROC_FINISH;
    }else{
        return result;
    }
}

ATPSocket * ATPContext::find_socket_by_fd(const ATPAddrHandle & handle_to, int sockfd){
    // find in listen
    // find port by sockfd
    if (handle_to.host_port() == 0 && handle_to.host_addr() == 0)
    {
        // error
        #if defined (ATP_LOG_AT_DEBUG)
            log_debug(this, "Can't locate socket by fd %u, port: [0.0.0.0:00000]", sockfd);
        #endif
        return nullptr;
    }
    sockaddr_in my_sock; socklen_t my_sock_len = sizeof(my_sock);
    getsockname(sockfd, reinterpret_cast<SA *>(&my_sock), &my_sock_len);
    ATPAddrHandle handle_me(reinterpret_cast<SA *>(&my_sock));

    std::map<uint16_t, ATPSocket*>::iterator iter = this->listen_sockets.find(handle_me.host_port());
    if(iter != this->listen_sockets.end()){
        ATPSocket * socket = iter->second;
        return socket;
    } else{
        #if defined (ATP_LOG_AT_DEBUG)
            log_debug(this, "Can't locate socket by fd %u, port: %u", sockfd, handle_me.host_port());
        #endif
        return nullptr;
    }
}


ATPSocket * ATPContext::find_socket_by_head(const ATPAddrHandle & handle_to, ATPPacket * pkt){
    // find in look_up
    if (handle_to.host_port() == 0 && handle_to.host_addr() == 0)
    {
        // error
        #if defined (ATP_LOG_AT_DEBUG)
            log_debug(this, "Can't locate socket by packet head:[0.0.0.0:00000]");
        #endif
        return nullptr;
    }
    std::string hashing = std::string(ATPSocket::make_hash_code(pkt->peer_sock_id, handle_to));
    std::map<std::string, ATPSocket*>::iterator iter = this->look_up.find(hashing);
    if(iter != this->look_up.end()){
        ATPSocket * socket = iter->second;
        return socket;
    } else{
        // there's no such socket
        #if defined (ATP_LOG_AT_DEBUG)
            std::string ext;
            for(std::map<std::string, ATPSocket*>::value_type & pr : this->look_up)
            {
                ext += pr.first;
                ext += ' ';
            }
            log_debug(this, "Can't locate socket by packet head:%s, the exsiting %u sockets are: %s\n"
                , hashing.c_str(), this->look_up.size(), tabber(ext).c_str());
        #endif
        return nullptr;
    }
}

