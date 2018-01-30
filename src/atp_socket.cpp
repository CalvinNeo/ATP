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
#include "udp_util.h"
#include <algorithm>
#include <bitset>
#include <iostream>

ATPSocket::ATPSocket(ATPContext * _context) : context(_context){
    assert(context != nullptr);
    sock_id = context->new_sock_id();
    conn_state = CS_UNINITIALIZED;
    memset(hash_str, 0, sizeof hash_str);

    memset(callbacks, 0, sizeof callbacks);
    init_callbacks(this);
}

atp_callback_arguments ATPSocket::make_atp_callback_arguments(int method, OutgoingPacket * out_pkt, const ATPAddrHandle & addr){
    if(out_pkt == nullptr){
        // there's no OutgoingPacket to be sent, so pass `nullptr`
        // out_pkt->length = 0, out_pkt->data = nullptr
        return atp_callback_arguments{
            context,
            this,
            method,
            0, nullptr, 
            conn_state,
            reinterpret_cast<const SA*>(&(addr.sa)),
            sizeof(sockaddr_in)
        };
    }else{
        return atp_callback_arguments{
            context,
            this,
            method,
            out_pkt->length, out_pkt->data, 
            conn_state,
            reinterpret_cast<const SA*>(&(addr.sa)),
            sizeof(sockaddr_in)
        };
    }
}

OutgoingPacket * ATPSocket::basic_send_packet(uint16_t flags){
    // use `{{}}` to make C++14 happy
    ATPPacket pkt = ATPPacket{
        (seq_nr & seq_nr_mask), // seq_nr, updated in send_packet
        (ack_nr & seq_nr_mask), // ack_nr
        peer_sock_id, // peer_sock_id
        0,// opts_count
        flags, // flags
        my_window // my window
    };
    OutgoingPacket * out_pkt = new OutgoingPacket{
        true, // holder
        false, // marked
        false, // selective_acked
        sizeof (ATPPacket), // length, update by `add_data`
        0, // payload, update by `add_data`/`add_option`
        0, // option_len, update by `add_option`
        0, // timestamp, set at `send_packet_noguard`
        0, // transmissions, update by `send_packet_noguard`
        false, // need_resend, update by `send_packet`/`check_unsend_packet`
        seq_nr, // full_seq_nr, updated in send_packet
        reinterpret_cast<char *>(std::calloc(1, sizeof (ATPPacket))) // SYN packet will not contain data
    };
    std::memcpy(out_pkt->data, &pkt, sizeof (ATPPacket));
    return out_pkt;
}

void ATPSocket::register_to_look_up(){
    // if not registered, can't find `ATPSocket *` by (addr:port)
    std::map<uint16_t, ATPSocket*>::iterator iter = context->listen_sockets.find(get_src_addr().host_port());
    if(iter != context->listen_sockets.end()){
        context->listen_sockets.erase(iter);
    }
    (context->look_up)[ATPSocket::make_hash_code(sock_id, dest_addr)] = this;
}


int ATPSocket::init(int family, int type, int protocol){
    conn_state = CS_IDLE;
    sockfd = socket(family, type, protocol);
    get_src_addr().family() = family;
    dest_addr.family() = family;
    #if defined (ATP_LOG_AT_DEBUG) && defined(ATP_LOG_UDP)
        log_debug(this, "UDP Socket init, sockfd %d.", sockfd);
    #endif
    return sockfd;
}

ATP_PROC_RESULT ATPSocket::connect(const ATPAddrHandle & to_addr){
    assert(context != nullptr);
    dest_addr = to_addr;

    assert(conn_state == CS_IDLE);
    conn_state = CS_SYN_SENT;
    register_to_look_up();

    while(seq_nr == 0){
        #if defined (ATP_DEBUG_TEST_OVERFLOW)
            seq_nr = 0xfffd;
        #else
            seq_nr = rand() & seq_nr_mask;
        #endif
    }
    ack_nr = 0;

    OutgoingPacket * out_pkt = basic_send_packet(ATPPacket::create_flags(PACKETFLAG_SYN));
    add_option(out_pkt, ATP_OPT_SOCKID, sizeof(sock_id), reinterpret_cast<char*>(&sock_id));
    if (my_max_sack_count > 0)
    {
        add_option(out_pkt, ATP_OPT_SACKOPT, sizeof(my_max_sack_count), reinterpret_cast<char*>(&my_max_sack_count));
    }
    // before sending packet, users can do something, like call `connect` to their UDP socket.
    atp_callback_arguments arg = make_atp_callback_arguments(ATP_CALL_CONNECT, out_pkt, dest_addr);
    ATP_PROC_RESULT result = invoke_callback(ATP_CALL_CONNECT, &arg);

    #if defined (ATP_LOG_AT_DEBUG) && defined(ATP_LOG_UDP)
        log_debug(this, "UDP socket connect to %s.", dest_addr.to_string());
    #endif
    if (result == ATP_PROC_ERROR){
        #if defined (ATP_LOG_AT_DEBUG)
            log_debug(this, "Connect Failed.");
        #endif
        delete out_pkt;
        out_pkt = nullptr;
    } else{
        result = send_packet(out_pkt);
        #if defined (ATP_LOG_AT_DEBUG)
            log_debug(this, "Sent SYN to peer, seq:%u.", out_pkt->get_head()->seq_nr);
        #endif
    }
    return result;
}


ATP_PROC_RESULT ATPSocket::listen(uint16_t host_port){
    conn_state = CS_LISTEN;
    // register to listen
    get_src_addr().set_port(host_port);
    if (context->listen_sockets.find(host_port) != context->listen_sockets.end())
    {
        context->listen_sockets[host_port] = this;
        #if defined (ATP_LOG_AT_DEBUG)
            log_debug(this, "Listening port %u.", host_port);
        #endif
        return ATP_PROC_OK;
    }else{
        return ATP_PROC_ERROR;
    }
}

ATP_PROC_RESULT ATPSocket::bind(const ATPAddrHandle & to_addr){
    // there's no OutgoingPacket to be sent, so pass `nullptr`
    atp_callback_arguments arg = make_atp_callback_arguments(ATP_CALL_BIND, nullptr, to_addr);
    ATP_PROC_RESULT result = invoke_callback(ATP_CALL_BIND, &arg);
    return result;
}

ATP_PROC_RESULT ATPSocket::accept(const ATPAddrHandle & to_addr, OutgoingPacket * recv_pkt){
    ATP_PROC_RESULT result;
    assert(context != nullptr);

    if (conn_state == CS_LISTEN || conn_state == CS_IDLE)
    {

    }else{
        // In some implementation of TCP protocol, 
        // New connection can establish at TIME_WAIT state,
        // But ATP don't allow that, actually, ATP can have very short TIME_WAIT time
        // Reject!
        // This is possible because this packet maybe a delay-arrived SYN packet

        char * p_opt_sockid = recv_pkt->find_option(ATP_OPT_SOCKID);
        uint16_t _peer_sock_id = *reinterpret_cast<uint16_t*>(p_opt_sockid + 2 * sizeof(uint8_t));
        if (this->peer_sock_id == _peer_sock_id)
        {
            // This packet is from peer
            // Just ignore, don't need ACK, because my SYN-ACK will automaticlly re-send
            return ATP_PROC_OK;
        }else{
            OutgoingPacket * out_pkt = basic_send_packet(ATPPacket::create_flags(PACKETFLAG_RST));
            result = send_packet(out_pkt);
            return ATP_PROC_OK;
        }
    }

    atp_callback_arguments arg = make_atp_callback_arguments(ATP_CALL_BEFORE_ACCEPT, nullptr, to_addr);
    result = invoke_callback(ATP_CALL_BEFORE_ACCEPT, &arg);

    if (result == ATP_PROC_OK)
    {
        // accept this SYN
        dest_addr = to_addr;

        conn_state = CS_SYN_RECV;
        
        register_to_look_up();
        handle_recv_packet_hard(recv_pkt);
        handle_opt(recv_pkt);
        while(seq_nr == 0){
            #if defined (ATP_DEBUG_TEST_OVERFLOW)
                seq_nr = 0xfffd;
            #else
                seq_nr = rand() & seq_nr_mask;
            #endif
        }
        do_ack_packet(recv_pkt);
        
        OutgoingPacket * out_pkt = basic_send_packet(ATPPacket::create_flags(PACKETFLAG_SYN, PACKETFLAG_ACK));
        add_option(out_pkt, ATP_OPT_SOCKID, sizeof(sock_id), reinterpret_cast<char*>(&sock_id));
        if (my_max_sack_count > 0)
        {
            add_option(out_pkt, ATP_OPT_SACKOPT, sizeof(my_max_sack_count), reinterpret_cast<char*>(&my_max_sack_count));
        }
        result = send_packet(out_pkt);

        atp_callback_arguments arg = make_atp_callback_arguments(ATP_CALL_ON_ACCEPT, nullptr, dest_addr);
        result = invoke_callback(ATP_CALL_ON_ACCEPT, &arg);

        #if defined (ATP_LOG_AT_DEBUG)
            log_debug(this, "Accept SYN request from %s by sending SYN+ACK."
                , ATPSocket::make_hash_code(peer_sock_id, dest_addr));
        #endif
    }else if(result == ATP_PROC_REJECT)
    {
        // decline this SYN
        OutgoingPacket * out_pkt = basic_send_packet(ATPPacket::create_flags(PACKETFLAG_RST));
        result = send_packet(out_pkt);
        #if defined (ATP_LOG_AT_DEBUG)
            log_debug(this, "Reject SYN request from %s by sending RST."
                , ATPSocket::make_hash_code(peer_sock_id, dest_addr));
        #endif
    }else{
        #if defined (ATP_LOG_AT_DEBUG)
            log_debug(this, "ERROR.");
        #endif
    }

    return result;
}

ATP_PROC_RESULT ATPSocket::receive(OutgoingPacket * recv_pkt, size_t real_payload_offset){
    if (recv_pkt->get_head()->get_fin())
    {
        // cond2: ignore fin
        // just ignore
        return ATP_PROC_OK;
    }else if(recv_pkt->get_head()->get_syn()){
        // the 2 bytes payload in syn packet are not user data, they carried sock_id
        return ATP_PROC_OK;
    }else if(!recv_pkt->has_user_data()){
        // there is no payload
        // just ignore
        return ATP_PROC_OK;
    }else{
        atp_callback_arguments arg = make_atp_callback_arguments(ATP_CALL_ON_RECV, recv_pkt, dest_addr);
        arg.data = recv_pkt->data + sizeof(ATPPacket) + real_payload_offset;
        arg.length = recv_pkt->payload - real_payload_offset;
        return invoke_callback(ATP_CALL_ON_RECV, &arg);
    }
}

ATP_PROC_RESULT ATPSocket::send_packet_noguard(OutgoingPacket * out_pkt){
    uint64_t current_ms = get_current_ms();
    rto_timeout = current_ms + rto;
    if (out_pkt->transmissions == 0 && out_pkt->is_promised_packet())
    {
        used_window_packets++;
        used_window += out_pkt->payload;
    }
    #if defined (ATP_LOG_AT_DEBUG)
        log_debug(this, "ATPPacket sent. seq:%u size:%u payload:%u.", out_pkt->get_head()->seq_nr, out_pkt->length, out_pkt->payload);
    #endif
    #if defined (ATP_LOG_AT_NOTE)
        // printf("real len %u\n", out_pkt->real_payload());
        if (out_pkt->transmissions == 0)
        {
            print_out(this, out_pkt, "snd");
        }else{
            char b[32];
            sprintf(b, "re-snd[%u]", out_pkt->transmissions);
            print_out(this, out_pkt, b);
        }
    #endif
    out_pkt->timestamp = current_ms;
    out_pkt->transmissions++;
    atp_callback_arguments arg = make_atp_callback_arguments(ATP_CALL_SENDTO, out_pkt, dest_addr);
    if (out_pkt->need_resend)
    {
        out_pkt->need_resend = false;
    }
    ATP_PROC_RESULT result = invoke_callback(ATP_CALL_SENDTO, &arg);
    return result;
}

void ATPSocket::check_unsend_packet(){
    // If delayed ack is enabled, an empty ACK packet is allowed to be sent later,
    // and possibly attached with real data files
    if(outbuf.size() <= 0) {return;} // if there's no cached packets
    int marked_total = 0;
    for(OutgoingPacket * out_pkt : outbuf){
        // check everytime in the for-loop
        if ((out_pkt->transmissions == 0 || out_pkt->need_resend))
        {
            // For most cases, need_resend will not be true, because currently delayed ACK checks before timeout check.
            if (out_pkt->is_empty_ack())
            {
                // mark all empty ACK without data, they will be deleted, after they are sent. 
                // We don't resend any empty ACK packets.
                if(guess_full_seq_nr(out_pkt->get_head()->ack_nr) < ack_nr && !overflow_lock){
                    // We don't send a old empty ACK packet, can only be triggerred by Delayed ACK
                }else{
                    send_packet_noguard(out_pkt);
                }
                out_pkt->marked = true;
                marked_total++;
            }else if(bytes_can_send_one_packet() >= out_pkt->payload){
                send_packet_noguard(out_pkt);
            }
        }
    }
    // delete all marked packet
    #if defined (ATP_LOG_AT_DEBUG)
        log_debug(this, "Marked total:%d.", marked_total);
    #endif
    std::make_heap(outbuf.begin(), outbuf.end(), _cmp_outgoingpacket_marked());
    while(!outbuf.empty()){
        if (outbuf.back()->marked)
        {
            delete outbuf.back();
            outbuf.pop_back();
        }else{
            break;
        }
    }
    std::make_heap(outbuf.begin(), outbuf.end(), _cmp_outgoingpacket_fullseq());
    delay_ack_timeout = 0;
}

ATP_PROC_RESULT ATPSocket::send_packet(OutgoingPacket * out_pkt){
    ATP_PROC_RESULT result = ATP_PROC_OK;
    // setup packets
    // when the package is constructed, update `seq_nr` for the next package
    if (out_pkt->is_promised_packet() > 0 && !out_pkt->need_resend)
    {
        // Only non-repeated packets with real user data(not including options) can have new seq number
        out_pkt->full_seq_nr ++;
        out_pkt->get_head()->seq_nr ++;
        (out_pkt->get_head()->seq_nr) &= seq_nr_mask;
        seq_nr ++;
    }
    if (bytes_can_send_one_packet() >= out_pkt->payload)
    {
        // actually send
        // if payload == 0 and is not FIN, can always send regradless of window
        if (out_pkt->is_empty_ack())
        {
            if(ack_delayed_time != 0 && conn_state != CS_TIME_WAIT){
                // Delay ACK is enabled
                #if defined (ATP_LOG_AT_DEBUG)
                    log_debug(this, "ATPPacket sent CACHED due to delayed ACK. seq:%u size:%u payload:%u."
                        , out_pkt->get_head()->seq_nr, out_pkt->length, out_pkt->payload);
                #endif
                outbuf.push_back(out_pkt);
                std::push_heap(outbuf.begin(), outbuf.end(), _cmp_outgoingpacket_fullseq());
                uint64_t current_ms = get_current_ms();
                if (delay_ack_timeout == 0)
                {
                    delay_ack_timeout = current_ms + ack_delayed_time;
                }
                result = ATP_PROC_OK;
            }else{
                // Delayed ACK is disabled, Send Empty ACK immediately
                // ad-hoc send, don't enqueue
                // if payload == 0(except SYN, FIN), can always delete at once
                result = send_packet_noguard(out_pkt);
                delete out_pkt;
                out_pkt = nullptr;
            }
        }else if(out_pkt->get_head()->get_syn()){
            // SYN Packet will always be sent immediately and pushed into `outbuf`
            result = send_packet_noguard(out_pkt);
            outbuf.push_back(out_pkt);
            std::push_heap(outbuf.begin(), outbuf.end(), _cmp_outgoingpacket_fullseq());
        }else{
            // We don't send immediately packets with userdata
            // enqueue for proper time to send and for potential resend
            outbuf.push_back(out_pkt);
            std::push_heap(outbuf.begin(), outbuf.end(), _cmp_outgoingpacket_fullseq());
            check_unsend_packet();
        }
    }else{
        #if defined (ATP_LOG_AT_DEBUG)
            log_debug(this, "ATPPacket sent CACHED due to window limit. seq:%u size:%u payload:%u."
                , out_pkt->get_head()->seq_nr, out_pkt->length, out_pkt->payload);
        #endif
        result = ATP_PROC_OK;
        outbuf.push_back(out_pkt);
        std::push_heap(outbuf.begin(), outbuf.end(), _cmp_outgoingpacket_fullseq());
    }
    
    return result;
}

ATP_PROC_RESULT ATPSocket::close(){
    int result = ATP_PROC_OK;
    switch(conn_state){
        case CS_UNINITIALIZED:
        case CS_IDLE:
        case CS_SYN_SENT:
        case CS_SYN_RECV:
            #if defined (ATP_LOG_AT_DEBUG)
                log_debug(this, "Close: Connection Error.");
            #endif
            result = ATP_PROC_ERROR;
            break;
        case CS_CONNECTED:
        case CS_CONNECTED_FULL:
        {
            // A
            conn_state = CS_FIN_WAIT_1;
            #if defined (ATP_LOG_AT_DEBUG)
                log_debug(this, "Close: Send FIN Packet.");
            #endif
            OutgoingPacket * out_pkt = basic_send_packet(ATPPacket::create_flags(PACKETFLAG_FIN));
            // FIN must have payload, and it's own seq_nr, otherwise, It will share seq_nr data with a data packet,
            // supposing this data packet is received normally, and FIN lost.
            // I can get a wrong ACK for data packet from peer, and mistaken it as an ack for my FIN packet
            // In this case, we will never re-send our FIN packet, so peer can never know we finished.
            add_data(out_pkt, &sock_id, sizeof(sock_id));
            send_packet(out_pkt);
            result = ATP_PROC_OK;
            break;
        }
        case CS_FIN_WAIT_1:
            #if defined (ATP_LOG_AT_DEBUG)
                log_debug(this, "Close: Already sent FIN, waiting for ACK.");
            #endif
            result = ATP_PROC_ERROR;
            break;
        case CS_CLOSE_WAIT:
        {
            // B
            conn_state = CS_LAST_ACK;
            #if defined (ATP_LOG_AT_DEBUG)
                log_debug(this, "Close: Send FIN Packet to a finished peer.");
            #endif
            OutgoingPacket * out_pkt = basic_send_packet(ATPPacket::create_flags(PACKETFLAG_FIN));
            add_data(out_pkt, &sock_id, sizeof(sock_id));
            send_packet(out_pkt);
            result = ATP_PROC_OK;
            break;
        }
        case CS_FIN_WAIT_2:
        case CS_LAST_ACK:
            #if defined (ATP_LOG_AT_DEBUG)
                log_debug(this, "Close: Connection Error.");
            #endif
            result = ATP_PROC_ERROR;
            break;
        case CS_TIME_WAIT:
            #if defined (ATP_LOG_AT_DEBUG)
                log_debug(this, "Close: Send a repeated last ACK.");
            #endif
            result = ATP_PROC_OK;
            break;
        case CS_RESET:
        case CS_DESTROY:
        default:
            #if defined (ATP_LOG_AT_DEBUG)
                log_debug(this, "Close: Connection Error.");
            #endif
            result = ATP_PROC_ERROR;
            break;
    }
    return result;
}


void ATPSocket::add_data(OutgoingPacket * out_pkt, const void * buf, const size_t len){
    out_pkt->length += len;
    out_pkt->payload += len;
    assert(out_pkt->length == out_pkt->payload + sizeof(ATPPacket));
    out_pkt->data = reinterpret_cast<char *>(std::realloc(out_pkt->data, out_pkt->length));
    memcpy(out_pkt->data + (out_pkt->length - len), buf, len);
}

void ATPSocket::add_option(OutgoingPacket * out_pkt, uint8_t opt_kind, uint8_t opt_data_len, char * opt_data){
    out_pkt->get_head()->opts_count++;
    uint8_t total_opt_len = opt_data_len + sizeof(uint8_t) * 2;
    out_pkt->data = reinterpret_cast<char *>(std::realloc(out_pkt->data, out_pkt->length + total_opt_len));
    *reinterpret_cast<uint8_t *>(out_pkt->data + out_pkt->length) = opt_kind;
    *reinterpret_cast<uint8_t *>(out_pkt->data + out_pkt->length + sizeof(uint8_t)) = opt_data_len;
    memcpy(out_pkt->data + out_pkt->length + sizeof(uint8_t) * 2, opt_data, opt_data_len);
    out_pkt->length += total_opt_len;
    out_pkt->payload += total_opt_len;
    out_pkt->option_len += total_opt_len;
    assert(out_pkt->length == out_pkt->payload + sizeof(ATPPacket));
    #if defined (ATP_LOG_AT_DEBUG)
        // fprintf(stderr, "Add option[%u], kind:%u, data_len:%u, payload:%u\n", out_pkt->get_head()->opts_count
        //     , opt_kind, opt_data_len, out_pkt->payload);
    #endif
}

bool ATPSocket::writable() const{
    // NOTICE: note that even window is 0, this socket is still writable
    switch(conn_state){
        case CS_UNINITIALIZED:
        case CS_IDLE:
        case CS_LISTEN:
        case CS_SYN_SENT:
        case CS_SYN_RECV:
        case CS_RESET:
            // can't write data now
            return false;
        case CS_CONNECTED:
        case CS_CONNECTED_FULL:
            return true;
        case CS_FIN_WAIT_1: // A
            // I closed, I can't write, but peer can
            return false;
        case CS_CLOSE_WAIT: // B
            // I closed, I can't write, but peer can
            return true;
        case CS_FIN_WAIT_2: // A
            // I already closed
            return false;
        case CS_LAST_ACK: // B
            // I finished, peer finished
            return false;
        case CS_TIME_WAIT:
        case CS_DESTROY:
        default:
            return false;
    }
}

bool ATPSocket::readable() const{
    switch(conn_state){
        case CS_UNINITIALIZED:
        case CS_IDLE:
        case CS_SYN_SENT:
        case CS_SYN_RECV:
        case CS_RESET:
            // now connection not yet been established
            return false;
        case CS_CONNECTED:
        case CS_CONNECTED_FULL: // B
            return true;
        case CS_FIN_WAIT_1: // A
            // can still read
            return true;
        case CS_CLOSE_WAIT: // B
            // peer closed, can't read
            return false;
        case CS_FIN_WAIT_2: // A
            // peer not closed, can still read
            return true;
        case CS_LAST_ACK: // B
            return false;
        case CS_TIME_WAIT: // A
            return false;
        case CS_DESTROY:
        default:
            return false;
    }
}

size_t ATPSocket::bytes_can_send_once() const {
    if (cur_window < used_window)
    {
        return 0;
    }
    return std::min(cur_window - used_window, ATP_MAX_WRITE_BUFFER_SIZE);
}
size_t ATPSocket::bytes_can_send_one_packet() const {
    return std::min(bytes_can_send_once(), current_mss);
}

ATP_PROC_RESULT ATPSocket::write(const void * buf, const size_t len){
    if (!writable())
    {
        #if defined (ATP_LOG_AT_DEBUG)
            log_debug(this, "ERROR: This socket can't write.");
        #endif
        return ATP_PROC_ERROR;
    }
    if (len > ATP_MAX_WRITE_BUFFER_SIZE)
    {
        #if defined (ATP_LOG_AT_DEBUG)
            log_debug(this, "ERROR: Package reject because it's too big for ATP's writting buffer.");
        #endif
        return ATP_PROC_ERROR;
    }
    // TODO improve here
    if (len > bytes_can_send_once())
    {   
        #if defined (ATP_LOG_AT_DEBUG)
            // Must because of window restriction
            log_debug(this, "Window restricted, total %u, used %u, will only partially send, cache the rest.", cur_window, used_window);
        #endif
    }
    #if defined (ATP_LOG_AT_DEBUG)
        if (len > bytes_can_send_one_packet())
        {
            log_debug(this, "Must devide into several ATP packets.");
        }
    #endif
    size_t p = 0; int packet_id = 0;
    while(p < len){
        size_t current_packet_payload_limit = bytes_can_send_one_packet();
        OutgoingPacket * out_pkt = basic_send_packet(ATPPacket::create_flags(PACKETFLAG_ACK));
        
        size_t new_length = std::min(current_packet_payload_limit, len - p);
        add_data(out_pkt, buf + p, new_length);
        ATP_PROC_RESULT result = send_packet(out_pkt);
        packet_id++;
        if (result == ATP_PROC_ERROR)
        {
            #if defined (ATP_LOG_AT_DEBUG)
                log_debug(this, "In packet_id:%d, write %u bytes to peer from position %u, seq:%u."
                    , packet_id, out_pkt->payload, p, seq_nr);
            #endif
            return ATP_PROC_ERROR;
        }else{
            p += new_length;
        }
    }
    return ATP_PROC_OK;
}

ATP_PROC_RESULT blocked_write(const void * buf, const size_t len){
    return ATP_PROC_OK;
}

ATP_PROC_RESULT ATPSocket::check_fin(OutgoingPacket * recv_pkt){
    // return >0: OK
    // return -1: error
    uint64_t current_ms = get_current_ms();
    ATP_PROC_RESULT result = ATP_PROC_OK;
    switch(conn_state){
        case CS_UNINITIALIZED:
        case CS_IDLE:
        case CS_SYN_SENT:
        case CS_SYN_RECV:
            #if defined (ATP_LOG_AT_DEBUG)
                log_debug(this, "Connection Error.");
            #endif
            result = ATP_PROC_ERROR;
            break;
        case CS_CONNECTED:
        case CS_CONNECTED_FULL: // B
        {
            conn_state = CS_CLOSE_WAIT;
            #if defined (ATP_LOG_AT_DEBUG)
                log_debug(this, "Recv peer's FIN, Send the last ACK to Peer, Me still alive.");
            #endif
            OutgoingPacket * out_pkt = basic_send_packet(ATPPacket::create_flags(PACKETFLAG_ACK));
            send_packet(out_pkt);

            #if defined (ATP_LOG_AT_DEBUG)
                log_debug(this, "Call ATP_CALL_ON_PEERCLOSE.");
            #endif
            atp_callback_arguments arg = make_atp_callback_arguments(ATP_CALL_ON_PEERCLOSE, recv_pkt, dest_addr);
            result = invoke_callback(ATP_CALL_ON_PEERCLOSE, &arg);
            // half closed, don't send FIN immediately
            break;
        }
        case CS_FIN_WAIT_1: // A
        case CS_CLOSE_WAIT: // B
            #if defined (ATP_LOG_AT_DEBUG)
                log_debug(this, "Connection Error.");
            #endif
            result = ATP_PROC_ERROR;
            break;
        case CS_FIN_WAIT_2: // A
        {
            conn_state = CS_TIME_WAIT;
            uint64_t current_ms = get_current_ms();
            death_timeout = current_ms + std::max(context->min_msl2, rto);
            #if defined (ATP_LOG_AT_DEBUG)
                log_debug(this, "Recv peer's FIN, Send the last ACK to Peer, wait 2MSL from %u to %u.", current_ms, death_timeout);
            #endif

            OutgoingPacket * out_pkt = basic_send_packet(ATPPacket::create_flags(PACKETFLAG_ACK));
            result = send_packet(out_pkt);

            atp_callback_arguments arg;
            // arg = make_atp_callback_arguments(ATP_CALL_ON_PEERCLOSE, recv_pkt, dest_addr);
            // result = context->callbacks[ATP_CALL_ON_PEERCLOSE](&arg);
            break;
        }
        case CS_LAST_ACK: // B
        {
            #if defined (ATP_LOG_AT_DEBUG)
                log_debug(this, "Peer resend FIN, send ack.");
            #endif
            OutgoingPacket * out_pkt = basic_send_packet(ATPPacket::create_flags(PACKETFLAG_ACK));
            result = send_packet(out_pkt);
            break;
        }
        case CS_TIME_WAIT: // A
        {
            #if defined (ATP_LOG_AT_DEBUG)
                log_debug(this, "Peer resend FIN, send ack.");
            #endif
            death_timeout = current_ms + std::max(context->min_msl2, rto);
            OutgoingPacket * out_pkt = basic_send_packet(ATPPacket::create_flags(PACKETFLAG_ACK));
            result = send_packet(out_pkt);
            break;
        }
        case CS_RESET:
        case CS_DESTROY:
        default:
        {
            #if defined (ATP_LOG_AT_DEBUG)
                log_debug(this, "Connection Error.");
            #endif
            result = ATP_PROC_ERROR;
            break;
        }
    }
    return result;
}

uint32_t ATPSocket::guess_full_seq_nr(uint32_t raw_peer_seq){
    uint32_t peer_seq = get_full_seq_nr(raw_peer_seq);
    // But if then we get a packet who somehow comes later, with an un-overflowed seq_nr?
    // e.g. If seq_nr_mask is 0xff = 255, and now our ack_nr is 1025.
    // If we then get a packet of 2, that's obviously correct, and we can update ack_nr to 1026
    // Nut what if we get a packet of 254? how can we judge whether it means 1023 or 1274(=1024+254)?
    // To solve this, we have a 2 assumptions:
    // 1. when handling packet `s`, all packets before `s - (peer_seq_nr_base + 1)` are vanished.
    // 2. packets are handled generally the same rate
    // Now handle this situation, where we got a packet of 254, 
    // The result depends on relationship between the two possible values and ack_nr
    // 1. First of all, we can find out the easiest case, when ack_nr is less than any of the two possible values.
    // For example, if ack_nr is now 250 and greater than both 254 and 510, this is possible because packet 256 can come earlier and overflow.
    // In this case, the true peer_seq should be 254, because according to our assumption, packet 510 can't co-exist with packet 254
    // 2. If ack_nr is between the two possible values.
    // For example, if ack_nr is now 257, and we decide between 254 and 510. 
    // In this case if we choose 254, and then drop it. We can also choose 510, because it's a packet comes much earlier.
    // They are two streategies, a) we choose the most close to ack_nr, because we believe in possibility.
    //                           b) We can always choose the smaller, because we can depend on resend.
    // 3. If ack_nr is greater than the two possible values.
    // For example, if ack_nr is now 555, and we decide between 254 and 510. 
    // This is also easy, we choose 510.
    if (peer_seq > (seq_nr_mask + 1))
    {
        // notice peer_seq > peer_seq_2 is always true
        uint32_t peer_seq_2 = peer_seq - (seq_nr_mask + 1);
        if (peer_seq > ack_nr && peer_seq_2 > ack_nr)
        {
            // not overflow, choose smaller
            peer_seq = peer_seq_2;
        }else if (peer_seq >= ack_nr && peer_seq_2 <= ack_nr)
        {
            if (peer_seq - ack_nr >= ack_nr - peer_seq_2)
            {
                // peer_seq is nearer
                peer_seq = peer_seq_2;
            }
        }else{
            // not overflow, choose bigger
        }
    }
    return peer_seq;
}

ATP_PROC_RESULT ATPSocket::update_myack(OutgoingPacket * recv_pkt){
    if(conn_state < CS_CONNECTED){
        // handles the last hand-shake of connection establishment
        #if defined (ATP_LOG_AT_DEBUG)
            log_debug(this, "Connection established on B's side, handshake completed.");
        #endif
        conn_state = CS_CONNECTED;
    }
    ATP_PROC_RESULT action = ATP_PROC_OK;

    uint32_t raw_peer_seq = recv_pkt->get_head()->seq_nr;

    // When we met a 0, we know that peer's seq_nr wraps.
    // e.g. If our `peer_seq_nr_base` is now 0, and we get a 0 seq_nr
    // I understand the number overflowed. So I update `peer_seq_nr_base` to 256;
    // NOTe that in some former version, code `raw_peer_seq < 5` is not correct.
    // This is because in `handle_recv_packet`, code `!recv_pkt->is_empty_ack() && recv_pkt->get_head()->seq_nr == 0` will reset `overflow_lock` to false.
    // Consider here comes packet 3, we set overflow_lock to true and cache this packet
    // then comes packet 0, and we can ack this packet, and overflow_lock is reset to false
    // then comes packet 1, it will cause another incorrect overflow
    if (raw_peer_seq == 0 && !overflow_lock && new_stage_hitted)
    {
        // peer's seq_nr wraps here
        // new_stage_hitted is used to avoid repeated packet with srq_nr 0, consider:
        //     rcv     2002     AD          0       1462      65534
        // rcv-ack     2002      A          0          0      65534
        //     rcv     2003     AD          1       1462      65534
        //     rcv     2004     AD          2       1462      65534
        //     snd     3002      A      65534          0          2
        //     snd     3002      A      65534          0          2
        uint32_t current_lowbit = ack_nr & seq_nr_mask;
        if (current_lowbit - 0 > seq_nr_mask - current_lowbit)
        {
            peer_seq_nr_base += (seq_nr_mask + 1);
            #if defined (ATP_LOG_AT_DEBUG)
                log_debug(this, "Seq_nr overflow to 0, current base %u(%x).", peer_seq_nr_base, peer_seq_nr_base);
            #endif
            // because there may be several packets which have seq_nr == 0(one with paylod, others don't)
            // only overflow once
            overflow_lock = true;
            new_stage_hitted = false;
        }else{
            // This may be a delayed 0, consider
            //  rcv    98057     AD          0       1462      65534
            //  rcv    98057     AD          1       1462      65534
            // drop   122071     AD          0       1462      65534
        }
    }
    // and then we update peer_seq
    uint32_t peer_seq = guess_full_seq_nr(raw_peer_seq);

    // get peer's window
    cur_window = recv_pkt->get_head()->window_size;

    if (recv_pkt->is_empty_ack())
    {
        // peer don't send data, this packet only tell us ack number, for our `do_ack_packet` function
        // it's seq_nr maybe repeated
        action = ATP_PROC_OK;
        #if defined (ATP_LOG_AT_DEBUG)
            log_debug(this, "This is a empty packet with repeated raw_seq_nr:%u, seq_nr:%u, ack_nr:%u, my ack_nr is:%u."
                , raw_peer_seq, peer_seq, recv_pkt->get_head()->ack_nr, ack_nr);
        #endif
        // WHY DO NOT UPDATE ACK:
        // seq_nr from an empty ack can't be used to update
        // explanation(logs/unfinished-sender.txt)
                
        // Sender:
        // simulated packet loss
        //  re-snd[5]    12008     F      20852          2      19982
        // simulated packet loss
        //        rcv    12009     A      19982          0      20852
        //        rcv    12009     A      19983          0      20852
        //        snd    12009     A      20852          0      19983
     
        // Receiver:
        //        snd    13928     F      19983          2      20852
        // simulated packet loss
        //       drop    13928    AD      20849       1462      19982
        //        snd    13928     A      19983          0      20852
        // simulated packet loss
        //       drop    13928    AD      20850         10      19982
        //        snd    13928     A      19983          0      20852
        //        rcv    13929     A      20852          0      19983
        
        // In this case, instead of recv the lost FIN sent by Receiver,
        // Sender recv a delayed ACK for his re-snd[5] FIN, which has the same seq_nr with Receiver's lost FIN
        // So the Sender acked seq_nr of Receiver's FIN without even recv the packet.
    }else{
        if (peer_seq <= ack_nr){
            // this packet has already been acked, DROP!
            #if defined (ATP_LOG_AT_DEBUG)
                log_debug(this, "This is an old raw_seq_nr:%u, seq_nr:%u, my_ack has already been:%u.", raw_peer_seq, peer_seq, ack_nr);
            #endif
            action = ATP_PROC_DROP;
        } 
        else if(peer_seq == ack_nr + 1){
            #if defined (ATP_LOG_AT_DEBUG)
                log_debug(this, "This is a normal raw_seq_nr:%u, seq_nr:%u, my_ack is:%u.", raw_peer_seq, peer_seq, ack_nr);
            #endif
            ack_nr ++;
            action = ATP_PROC_OK;
        } else{
            // there is at least one packet not acked before this packet, so we can't ack this
            #if defined (ATP_LOG_AT_DEBUG)
                log_debug(this, "This is an pre-arrived raw_seq_nr:%u, seq_nr:%u, my_ack is still:%u.", raw_peer_seq, peer_seq, ack_nr);
            #endif
            action = ATP_PROC_CACHE;
        }
    }
    if (action == ATP_PROC_OK)
    {
        if (raw_peer_seq != 0)
        {
            new_stage_hitted = true;
        }
        switch(conn_state){
            case CS_UNINITIALIZED:
            case CS_IDLE:
            case CS_LISTEN:
                #if defined (ATP_LOG_AT_DEBUG)
                    log_debug(this, "At state CS_UNINITIALIZED/CS_IDLE/CS_LISTEN: Ack is illegal");
                #endif
                action = ATP_PROC_DROP;
                break;
            case CS_SYN_SENT:
                // already handled in `ATPSocket::process`
                #if defined (ATP_LOG_AT_DEBUG)
                    log_debug(this, "At state CS_SYN_SENT: this case is already handled in ATPSocket::process");
                #endif
                action = ATP_PROC_DROP;
                break;
            case CS_SYN_RECV:
                // recv the last handshake, change state to CS_CONNECTED by update_myack automaticlly
                // connection established on side B
                // fallthrough
            case CS_CONNECTED:
            case CS_CONNECTED_FULL:
                break;
            case CS_FIN_WAIT_1: // A
                // state: A's fin is sent to B. this ack must be an ack for A's fin, 
                // if will not be a ack for previous ack, because in this case `action != ATP_PROC_OK`
                // action of ack: 
                conn_state = CS_FIN_WAIT_2;
                #if defined (ATP_LOG_AT_DEBUG)
                    log_debug(this, "Recv the ACK for my FIN from Peer, Me Die, Peer still alive.");
                #endif
                break;
            case CS_CLOSE_WAIT: // B
                // state: this is half closed state. B got A's fin and sent Ack, 
                // Now, B knew A'll not send data, but B can still send data, then A can send ack in response
                // action of ack: check that ack, because it may be an ack for B's data
                break;
            case CS_FIN_WAIT_2: // A
                // state: A is fin now, and B knew A's fin and A can't send any data bt sending Ack
                // A got B's Ack, and already switch from CS_FIN_WAIT_1 to CS_FIN_WAIT_2
                // THis should be B's FIN or B's Data
                // action of ack: discard this ack
                break;
            case CS_LAST_ACK: // B
            {
                // state: B has sent his fin, this ack must be A's response for B's fin
                // action of ack: change state
                conn_state = CS_DESTROY;
                action = ATP_PROC_FINISH;
                #if defined (ATP_LOG_AT_DEBUG)
                    log_debug(this, "Recv the last ACK for my FIN from Peer, All Die, RIP.");
                #endif
                break;
            }
            case CS_TIME_WAIT: 
                // state, A must wait 2 * MSL and then goto CS_DESTROY
                // action of ack: simply drop
                action = ATP_PROC_DROP;
                break;
            case CS_RESET:
            case CS_DESTROY: 
                // the end
                action = ATP_PROC_DROP;
                break;
            default:
                action = ATP_PROC_DROP;
                break;
        }
    }
    return action;
}

size_t ATPSocket::handle_opt(OutgoingPacket * recv_pkt){
    if(recv_pkt->get_head()->opts_count == 0) return ATP_PROC_OK;
    char * p = recv_pkt->data + sizeof(ATPPacket);
    for(auto i = 0; i < recv_pkt->get_head()->opts_count; i++){
        uint8_t kind = *reinterpret_cast<uint8_t*>(p);
        p += sizeof(uint8_t);
        uint8_t len = *reinterpret_cast<uint8_t*>(p);
        p += sizeof(uint8_t);
        // here handle different opts
        char * opt_dat_p = p;
        switch(kind){
            case ATP_OPT_SOCKID:
            {
                peer_sock_id = *reinterpret_cast<uint16_t *>(opt_dat_p);
                break;
            }
            case ATP_OPT_MSS:
            {
                break;
            }
            case ATP_OPT_SACK:
            {
                if(my_max_sack_count > 0){
                    do_selective_ack_packet(opt_dat_p, len);
                }
                break;
            }
            case ATP_OPT_SACKOPT:
            {
                peer_max_sack_count = *reinterpret_cast<uint8_t*>(opt_dat_p);
                #if defined (ATP_LOG_AT_DEBUG) 
                    fprintf(stderr, "peer set SACK window to %u.\n", peer_max_sack_count);
                #endif
                break;
            }
        }
        p += len;
    }
    return (p - recv_pkt->data - sizeof(ATPPacket));
}
ATP_PROC_RESULT ATPSocket::handle_recv_packet_hard(OutgoingPacket * recv_pkt){
    // peer_sock_id = *reinterpret_cast<uint16_t *>(recv_pkt->data + sizeof(ATPPacket));
    // must FORCE set ack_nr, because now ack_nr is still 0
    ack_nr = recv_pkt->get_head()->seq_nr;
    // get peer's window
    cur_window = recv_pkt->get_head()->window_size;
}
ATP_PROC_RESULT ATPSocket::handle_recv_packet(OutgoingPacket * recv_pkt, bool from_cache){
    uint32_t raw_peer_seq = recv_pkt->get_head()->seq_nr;
    ATP_PROC_RESULT action = update_myack(recv_pkt);
    do_ack_packet(recv_pkt);
    uint32_t peer_seq = guess_full_seq_nr(raw_peer_seq);

    if (peer_max_sack_count > 0 && !from_cache && recv_pkt != nullptr)
    {
        // selective ACK peer's paket
        OutgoingPacket * out_pkt = basic_send_packet(ATPPacket::create_flags(PACKETFLAG_ACK));

        // Find all packets
        #ifdef USE_OLD_SACK_FIELD
            size_t size = std::min(static_cast<size_t>(peer_max_sack_count), inbuf.size());
            uint16_t * sack_data = new uint16_t[size] ();
            uint8_t sack_seq_count = 0;
            size_t loop_end = size;
        #else
            // bit-wise size
            size_t size = std::min(static_cast<size_t>(peer_max_sack_count) * 8, inbuf.size());
            // byte-wise size
            size_t byte_size = size % 8 == 0 ? (size / 8): (size / 8 + 1);
            uint8_t * sack_data = new uint8_t[byte_size] ();
            uint8_t sack_seq_count = 0;
            size_t loop_end = inbuf.size();
        #endif
        for(auto i = 0; i < loop_end; i++){
            OutgoingPacket * cached_pkt = inbuf[i];
            uint32_t cached_seq = guess_full_seq_nr(cached_pkt->get_head()->seq_nr);
            #ifdef USE_OLD_SACK_FIELD
                if (cached_seq > ack_nr)
                {
                    sack_data[sack_seq_count] = cached_pkt->get_head()->seq_nr;
                    sack_seq_count++;
                }
                // Only put in `size` seq_nrs
                if (sack_seq_count == size) break;
            #else
                if (cached_seq > ack_nr)
                {
                    uint32_t offset = cached_seq - (ack_nr + 1);
                    if(offset >= size) {continue;}
                    uint32_t byte_offset = offset / 8;
                    uint32_t bit_offset = offset % 8;
                    sack_data[byte_offset] |= (1 << bit_offset);
                    sack_seq_count++;
                }
            #endif
        }
        if (sack_seq_count > 0)
        {
            // If there are some packets to SACK
            #if defined (ATP_LOG_AT_DEBUG)
                fprintf(stdout, "snd-sack[%u] ", sack_seq_count);
                fprintf(stderr, "snd-sack[%u] ", sack_seq_count);
                #ifdef USE_OLD_SACK_FIELD
                    for(uint8_t i = 0; i < sack_seq_count; i++){
                        fprintf(stderr, "%u(%u)", sack_data[i], guess_full_seq_nr(sack_data[i]));
                        fprintf(stdout, "%u(%u)", sack_data[i], guess_full_seq_nr(sack_data[i]));
                    }
                #else
                    for(uint8_t i = 0; i < byte_size; i++){
                        std::bitset<8> bs = sack_data[i];
                        std::cout << bs << " ";
                        std::cerr << bs << " ";
                    }
                #endif
                fprintf(stdout, "\n");
                fprintf(stderr, "\n");
            #endif
            #ifdef USE_OLD_SACK_FIELD
                add_option(out_pkt, ATP_OPT_SACK, static_cast<uint8_t>(sack_seq_count * sizeof(uint16_t))
                    , reinterpret_cast<char*>(sack_data));
            #else
                add_option(out_pkt, ATP_OPT_SACK, static_cast<uint8_t>(byte_size)
                    , reinterpret_cast<char*>(sack_data));
            #endif
            // add_option `memcpy` sack_data
            delete sack_data;
            sack_data = nullptr;
            send_packet(out_pkt);
        }else{
            // If there's no packets to SACK
            // Once appears that sending repeated ACK with the following statement will stop the program from proceeding
            // It seems to be caused by `subprocess.PIPE` deadlock when I switched stdout/stderr to file, it worked again
            #ifdef _ATP_TEST_STOP
                #if defined (ATP_LOG_AT_DEBUG)
                    fprintf(stdout, "empty-sack\n");
                    fprintf(stderr, "empty-sack\n");
                #endif
                send_packet(out_pkt);
            #else
                delete out_pkt;
                out_pkt = nullptr;
            #endif
        }
    }

    if (action == ATP_PROC_DROP)
    {
        #if defined (ATP_LOG_AT_DEBUG)
            if (from_cache)
            {   
                log_debug(this, "Drop packet from cache, my ack_nr:%u, peer_seq:%u.", ack_nr, peer_seq);
            }else{
                log_debug(this, "Drop packet, my ack_nr:%u, peer_seq:%u.", ack_nr, peer_seq);
            }
        #endif
        #if defined (ATP_LOG_AT_NOTE)
            print_out(this, recv_pkt, "drop");
            // printf("Current ack_nr %u guess_full_seq_nr %u raw_peer_seq %u base %u\n",
            //     ack_nr, guess_full_seq_nr(raw_peer_seq), raw_peer_seq, peer_seq_nr_base);
        #endif
        delete recv_pkt;
        recv_pkt = nullptr;
        // maybe peer has not receive my ACK, so it keep re-sending ACK
        OutgoingPacket * out_pkt = basic_send_packet(ATPPacket::create_flags(PACKETFLAG_ACK));
        send_packet(out_pkt);
        if (from_cache)
        {
            std::pop_heap(inbuf.begin(), inbuf.end(), _cmp_outgoingpacket());
            inbuf.pop_back();
        }
    }
    else if (action == ATP_PROC_OK)
    {
        if (!recv_pkt->is_empty_ack() && recv_pkt->get_head()->seq_nr == 0)
        {
            // The last packet before overflows has been acked. 
            // It doesn't means there will be no re-sent packet with seq_nr before overflow
            assert(inbuf.size() == 0 || (from_cache && inbuf.size() == 1));
            #if defined (ATP_LOG_AT_DEBUG)
                fprintf(stdout, "re-cache ");
                fprintf(stderr, "re-cache ");
                for(OutgoingPacket * p : inbuf_cache2){
                    fprintf(stdout, "%u(%u) ", p->full_seq_nr, p->get_head()->seq_nr);
                    fprintf(stderr, "%u(%u) ", p->full_seq_nr, p->get_head()->seq_nr);
                }
                fprintf(stdout, "\n");
                fprintf(stderr, "\n");
            #endif
            std::copy(inbuf_cache2.begin(), inbuf_cache2.end(), std::back_inserter(inbuf));
            std::make_heap(inbuf.begin(), inbuf.end(), _cmp_outgoingpacket());
            inbuf_cache2.clear();
            #if defined (ATP_LOG_AT_DEBUG)
                log_debug(this, "Handled all packets before overflow, inbuf size: %u.", inbuf.size());
            #endif
            overflow_lock = false;
        }
        size_t real_data_offset = handle_opt(recv_pkt);
        if(!recv_pkt->get_head()->get_fin()){
            // Data in SYN/FIN pakcet are not user data
            // SYN packet will be handled in `handle_recv_packet_hard`,
            // but FIN packet will be handled here
            this->receive(recv_pkt, real_data_offset);
        }
        #if defined (ATP_LOG_AT_DEBUG)
            if(from_cache){
                log_debug(this, "Process a cached ATPPacket, peer_seq:%u, my ack_nr:%u.", peer_seq, ack_nr);
            }else{
                log_debug(this, "Process a ATPPacket, peer_seq:%u, my ack_nr:%u.", peer_seq, ack_nr);
            }
        #endif
        #if defined (ATP_LOG_AT_NOTE)
            if (recv_pkt->is_empty_ack())
            {
                print_out(this, recv_pkt, "rcv-ack");
            }else{
                print_out(this, recv_pkt, "rcv");
            }
        #endif
        if (from_cache)
        {
            std::pop_heap(inbuf.begin(), inbuf.end(), _cmp_outgoingpacket());
            inbuf.pop_back();
        }
        // Do not delete, renew `last_handled_pkt` in `ATPSocket::process`
    }
    else if (action == ATP_PROC_CACHE)
    {
        if (!from_cache)
        {
            // printf("peer_seq %u peer_seq_nr_base %u pkt base%u\n", peer_seq, peer_seq_nr_base, (peer_seq & seq_nr_mask));
            if (overflow_lock && (peer_seq & (~seq_nr_mask)) >= peer_seq_nr_base)
            {
                // cache into inbuf_cache2
                auto repeated = std::find_if(inbuf_cache2.begin(), inbuf_cache2.end(), 
                    [=](OutgoingPacket * op){
                        return op->get_head()->seq_nr == recv_pkt->get_head()->seq_nr;
                    }
                );
                if (repeated == inbuf_cache2.end())
                {
                    inbuf_cache2.push_back(recv_pkt);
                    #if defined (ATP_LOG_AT_DEBUG)
                        log_debug(this, "Cached packet to inbuf_cache2, ack:%u raw_peer_seq:%u inbuf_size: %u.", ack_nr, raw_peer_seq, inbuf.size());
                    #endif
                    #if defined (ATP_LOG_AT_NOTE)
                        print_out(this, recv_pkt, "cache-new2");
                    #endif
                }else{
                    #if defined (ATP_LOG_AT_NOTE)
                        print_out(this, recv_pkt, "cache-rep2");
                    #endif
                    delete recv_pkt;
                    recv_pkt = nullptr;
                }
            }else{
                // cache into inbuf
                auto repeated = std::find_if(inbuf.begin(), inbuf.end(), 
                    [=](OutgoingPacket * op){
                        return op->get_head()->seq_nr == recv_pkt->get_head()->seq_nr;
                    }
                );
                if (repeated == inbuf.end())
                {
                    // not repeated
                    inbuf.push_back(recv_pkt);
                    std::push_heap(inbuf.begin(), inbuf.end(), _cmp_outgoingpacket());
                    #if defined (ATP_LOG_AT_DEBUG)
                        log_debug(this, "Cached packet to inbuf, ack:%u raw_peer_seq:%u inbuf_size: %u.", ack_nr, raw_peer_seq, inbuf.size());
                    #endif
                    #if defined (ATP_LOG_AT_NOTE)
                        print_out(this, recv_pkt, "cache-new");
                    #endif
                }else{
                    #if defined (ATP_LOG_AT_NOTE)
                        print_out(this, recv_pkt, "cache-rep");
                    #endif
                    delete recv_pkt;
                    recv_pkt = nullptr;
                }
            }
        }
    }
    else if (action == ATP_PROC_FINISH)
    {
        // handled near the end of this function
    }
    return action;
}

ATP_PROC_RESULT ATPSocket::process(const ATPAddrHandle & addr, const char * buffer, size_t len){
    OutgoingPacket * recv_pkt = new OutgoingPacket();
    // set OutgoingPacket
    // must copy received message from "kernel"
    recv_pkt->data = reinterpret_cast<char *>(std::calloc(1, len));
    std::memcpy(recv_pkt->data, buffer, len);
    ATPPacket * pkt = recv_pkt->get_head();
    recv_pkt->length = len;
    recv_pkt->payload = recv_pkt->length - sizeof(ATPPacket);
    recv_pkt->update_real_payload();
    recv_pkt->timestamp = get_current_ms();

    ATP_PROC_RESULT result = ATP_PROC_OK;
    uint32_t old_ack_nr = ack_nr;
    uint32_t raw_peer_seq = recv_pkt->get_head()->seq_nr;
    #if defined (ATP_LOG_AT_DEBUG)
        log_debug(this, "ATPPacket recv, my_ack:%u raw_peer_seq:%u(base=%u,lock:%s) peer_ack:%u size:%u payload:%u."
            , ack_nr, raw_peer_seq, peer_seq_nr_base, (overflow_lock?"T":"F"), recv_pkt->get_head()->ack_nr, recv_pkt->length, recv_pkt->payload);
    #endif
    // HANDLE IMMEDIATELY, DO NOT CACHE
    // SYN packet need to be handled immediately, and `addr` must register to `dest_addr` by `accept`
    // on the other hand, if we handle SYN from a queue, in `process_packet`
    // then we can't know `socket->dest_addr`
    if(pkt->get_syn() && pkt->get_ack()){
        // recv the second handshake
        // established on side A
        if (conn_state != CS_SYN_SENT)
        {
            // About this code, ref `accept`

            char * p_opt_sockid = recv_pkt->find_option(ATP_OPT_SOCKID);
            uint16_t _peer_sock_id = *reinterpret_cast<uint16_t*>(p_opt_sockid + 2 * sizeof(uint8_t));
            if (this->peer_sock_id == _peer_sock_id)
            {
                // This packet is from peer
                // Just ignore, don't need ACK, because my SYN-ACK will automaticlly re-send
            }else{
                OutgoingPacket * out_pkt = basic_send_packet(ATPPacket::create_flags(PACKETFLAG_RST));
                result = send_packet(out_pkt);
            }

            delete recv_pkt;
            recv_pkt = nullptr;
            return ATP_PROC_OK;
        }
        conn_state = CS_CONNECTED;

        handle_recv_packet_hard(recv_pkt);
        handle_opt(recv_pkt);
        do_ack_packet(recv_pkt);

        #if defined (ATP_LOG_AT_DEBUG)
            log_debug(this, "Connection established on A's side, sending ACK immediately to B to complete handshake.");
        #endif

        #if defined (ATP_LOG_AT_NOTE)
            print_out(this, recv_pkt, "rcv");
        #endif

        atp_callback_arguments arg = make_atp_callback_arguments(ATP_CALL_ON_ESTABLISHED, nullptr, dest_addr);
        result = invoke_callback(ATP_CALL_ON_ESTABLISHED, &arg);

        // send a ack even if there's no data immediately, in order to avoid timeout
        OutgoingPacket * out_pkt = basic_send_packet(ATPPacket::create_flags(PACKETFLAG_ACK));
        send_packet(out_pkt);
        result = ATP_PROC_OK;

        delete recv_pkt;
        recv_pkt = nullptr;
        return result;

    } else if(pkt->get_syn()){
        // recv the first handshake
        // send the second handshake
        #if defined (ATP_LOG_AT_NOTE) 
            print_out(this, recv_pkt, "rcv");
        #endif
        result = this->accept(addr, recv_pkt);

        delete recv_pkt;
        recv_pkt = nullptr;
        return result;
    } 

    OutgoingPacket * last_handled_pkt = nullptr;
    result = handle_recv_packet(recv_pkt, false);
    if (result == ATP_PROC_OK)
    {
        // delete the previous last_handled_pkt
        delete last_handled_pkt;
        last_handled_pkt = recv_pkt;
    }

    #if defined (ATP_LOG_AT_DEBUG)
        log_debug(this, "After handled this packet, there are %u left in inbuf.", inbuf.size());
    #endif
    if (result == ATP_PROC_OK)
    {
        // check if there is any packet which can be acked
        while(!inbuf.empty()){
            OutgoingPacket * top_packet = inbuf[0];
            result = handle_recv_packet(top_packet, true);
            if(result == ATP_PROC_DROP)
            {
                result = ATP_PROC_OK;
                continue;
            }
            else if(result == ATP_PROC_OK)
            {
                // delete the previous last_handled_pkt
                delete last_handled_pkt;
                last_handled_pkt = top_packet;
                result = ATP_PROC_OK;
                continue;
            }
            else if(result == ATP_PROC_CACHE)
            {
                // remain this state;
                result = ATP_PROC_OK;
                // TODO trying to figure out why using goto will not jump out of the loop sometimes
                break;
            }
            else if(result == ATP_PROC_FINISH)
            {
                // handled near the end of this function
                break;
            }
        }
    }

    if (last_handled_pkt != nullptr && last_handled_pkt->get_head()->get_fin())
    {
        result = check_fin(last_handled_pkt);
    }
    else if (ack_nr != old_ack_nr)
    {
        // if ack_nr is updated, which means I read some packets from peer
        // remember: ACks are not acked, only data is acked.
        // send an ack packet immediately.
        OutgoingPacket * out_pkt = basic_send_packet(ATPPacket::create_flags(PACKETFLAG_ACK));
        send_packet(out_pkt);
    }
    if (result == ATP_PROC_FINISH)
    {
        if (conn_state == CS_DESTROY)
        {
            // destroy immediately
            this->destroy();
        }
    } 
    delete last_handled_pkt;
    return result;
}

ATP_PROC_RESULT ATPSocket::invoke_callback(int callback_type, atp_callback_arguments * args){
    if (callbacks[callback_type] != nullptr)
    {
        return callbacks[callback_type](args);
    }
    #if defined (ATP_LOG_AT_DEBUG)
        log_debug(this, "An empty callback");
    #endif
    return ATP_PROC_OK;
}

uint32_t ATPSocket::guess_full_ack_nr(uint32_t raw_peer_ack){
    uint32_t lowbit_mask = ~(seq_nr_mask);
    uint32_t my_seq_acked_by_peer_base = lowbit_mask & my_seq_acked_by_peer;
    uint32_t my_seq_acked_by_peer_masked = my_seq_acked_by_peer & seq_nr_mask;
    uint32_t calculated_peer_ack = 0;
    if (my_seq_acked_by_peer_base + raw_peer_ack >= my_seq_acked_by_peer)
    {
        if (my_seq_acked_by_peer_base + raw_peer_ack > seq_nr)
        {
            // Assume that we won't send seq_nr_mask at once
            // So this is a packet from before overflow
            // e.g. raw_peer_ack = 65534 and my_seq_acked_by_peer = 65537, 
            // though 65535 + 65534 > 65537, the actual packet ack_nr is 65535
            calculated_peer_ack = my_seq_acked_by_peer_base + raw_peer_ack - (seq_nr_mask + 1);
        }else{
            // No overflow happened
            // should use `my_seq_acked_by_peer_base + raw_peer_ack` directly.
            calculated_peer_ack = my_seq_acked_by_peer_base + raw_peer_ack;
        }
    }else{
        // Overflowed, because peer will not ack a early acked packet.
        // e.g. Current my_seq_acked_by_peer is 65534, raw_peer_ack = 1, it must actually be 65536
        calculated_peer_ack = my_seq_acked_by_peer_base + raw_peer_ack + (seq_nr_mask + 1);
    }
    #if defined (ATP_LOG_AT_DEBUG)
        log_debug(this, "Compute actual ACK, raw_peer_ack:%u, lowbit_mask:%x, my_seq_acked_by_peer_base:%u, calculated_peer_ack:%u, my_seq_acked_by_peer: %u."
            , raw_peer_ack, lowbit_mask, my_seq_acked_by_peer_base, calculated_peer_ack, my_seq_acked_by_peer );
    #endif
    return calculated_peer_ack;
}

ATP_PROC_RESULT ATPSocket::do_selective_ack_packet(char * peer_sack_data, uint8_t peer_sack_data_size){
    // `peer_sack_data` is directly from ATPPacket SACK option field
    // SACK infomation are generated by function `handle_recv_packet` of peer.
    #if defined (ATP_LOG_AT_DEBUG)
        fprintf(stdout, "rcv-sack[%u] ", peer_sack_data_size);
        fprintf(stderr, "rcv-sack[%u] ", peer_sack_data_size);
    #endif
    #ifdef USE_OLD_SACK_FIELD
    uint16_t * peer_sack_seq_nrs = reinterpret_cast<uint16_t *>(peer_sack_data);
    uint8_t count = peer_sack_data_size / sizeof(uint16_t);
    for(uint8_t i = 0; i < count; i++){
        uint16_t ack = peer_sack_seq_nrs[i];
    #else
    size_t count = peer_sack_data_size * 8;
    uint8_t * peer_sack_seq_bits = reinterpret_cast<uint8_t *>(peer_sack_data);
    for(size_t i = 0; i < count; i++){
        size_t byte_offset = i / 8;
        size_t bit_offset = i % 8;
        bool bit_data = peer_sack_seq_bits[byte_offset] & (1 << bit_offset);
        if(!bit_data) continue; // don't need to be sacked because this bit is `0`
        size_t ack = i;
    #endif
        // TODO performance can possibly be improved
        auto pkt_iter = std::find_if(outbuf.begin(), outbuf.end(), 
            [=](OutgoingPacket * op){
                return op->get_head()->seq_nr == ack;
            }
        );
        #if defined (ATP_LOG_AT_DEBUG)
            char op_sgn = ' ';
        #endif
        OutgoingPacket * cur_pkt = *pkt_iter;
        if (pkt_iter != outbuf.end())
        {
            assert(cur_pkt != nullptr);
            // do not update rto, because already updated in previous called `do_ack_packet`
            cur_pkt->marked = true;
            if (cur_pkt->selective_acked)
            {
                // This packet is already ACKed by SACK, don't need to handle repeatedly
                #if defined (ATP_LOG_AT_DEBUG)
                    op_sgn = 'R';
                #endif
            }else{
                if(cur_pkt->transmissions > 0 && cur_pkt->is_promised_packet()){
                    // This is very important, ref `do_ack_packet`
                    #if defined (ATP_LOG_AT_DEBUG)
                        size_t pl = cur_pkt->payload;
                        assert(used_window >= pl);
                    #endif
                    used_window_packets --;
                    used_window -= cur_pkt->payload;
                }
                #if defined (ATP_LOG_AT_DEBUG)
                    op_sgn = 'Y';
                #endif
            }
            (*pkt_iter)->selective_acked = true;
            #if defined (ATP_LOG_AT_DEBUG)
                fprintf(stdout, "[%c]%u(%u) ", op_sgn, cur_pkt->full_seq_nr, ack);
                fprintf(stderr, "[%c]%u(%u) ", op_sgn, cur_pkt->full_seq_nr, ack);
            #endif
        }else{
            #if defined (ATP_LOG_AT_DEBUG)
                op_sgn = 'N';
            #endif
            #if defined (ATP_LOG_AT_DEBUG)
                fprintf(stdout, "[%c](%u) ", op_sgn, ack);
                fprintf(stderr, "[%c(%u) ", op_sgn, ack);
            #endif
        }
    }
    #if defined (ATP_LOG_AT_DEBUG)
        fprintf(stdout, "\n");
        fprintf(stderr, "\n");
    #endif
    std::make_heap(outbuf.begin(), outbuf.end(), _cmp_outgoingpacket_marked());
    #if defined (ATP_LOG_AT_DEBUG)
        fprintf(stdout, "del: ");
        for(int i = 0; i < outbuf.size(); i++){
            fprintf(stdout, "[%s]%u(%u)", (outbuf[i]->marked? "Y": "N"), outbuf[i]->full_seq_nr, outbuf[i]->get_head()->seq_nr);
        }
        fprintf(stdout, "\n");
    #endif
    // Remove all acked packets from `outbuf`
    // Notice that there's no "Reneging" problems, once a packet is SACKed by peer, 
    // Peer promises to eventually process that packet and never discard that.
    while(!outbuf.empty()){
        if (outbuf.back()->marked)
        {
            delete outbuf.back();
            outbuf.pop_back();
        }else{
            break;
        }
    }
    std::make_heap(outbuf.begin(), outbuf.end(), _cmp_outgoingpacket_fullseq());
    return ATP_PROC_OK;
}

ATP_PROC_RESULT ATPSocket::do_ack_packet(OutgoingPacket * recv_pkt){
    // ack n means ack [0..n]
    uint32_t raw_peer_ack = recv_pkt->get_head()->ack_nr;
    uint32_t calculated_peer_ack = guess_full_ack_nr(raw_peer_ack);
    if (calculated_peer_ack > my_seq_acked_by_peer)
    {
        // update my_seq_acked_by_peer
        my_seq_acked_by_peer = calculated_peer_ack;
        if (atp_frr_retries != 0){
            frr_counter = 0;
        }
    }else if (calculated_peer_ack == my_seq_acked_by_peer){
        if (atp_frr_retries != 0){
            if(atp_frr_retries == frr_counter){

            } else{
                frr_counter++;
            }
        }
    }
    // remove successfully sent packets from out buffer
    while(!outbuf.empty()){
        OutgoingPacket * out_pkt = outbuf[0]; 
        ATPPacket * pkt = out_pkt->get_head();
        if (out_pkt->full_seq_nr <= my_seq_acked_by_peer)
        {
            // Ack all seq_nr below my_seq_acked_by_peer
            #if defined (ATP_LOG_AT_DEBUG)
                log_debug(this, "Removing ATPPackct seq_nr:%u(%u) ack_nr:%u from outbuf, peer_ack:%u, %u packet remain(including me)."
                    , out_pkt->full_seq_nr, pkt->seq_nr, pkt->ack_nr, my_seq_acked_by_peer, outbuf.size());
            #endif
            update_rto(out_pkt);
            std::pop_heap(outbuf.begin(), outbuf.end(), _cmp_outgoingpacket_fullseq());
            outbuf.pop_back();
            if (out_pkt->selective_acked)
            {
                
            }else{
                if(out_pkt->transmissions > 0 && out_pkt->is_promised_packet()){
                    // This is very important, because due to delayed ACK, 
                    // some packets in outbuf haven't yet been sent(by send_packet_noguard).
                    // used_window is increased in function send_packet_noguard

                    // If a packet is not is_promised_packet, it will never be ACKed by peer.
                    // In fact we don't count a **pure** ACK with options into window.
                    // However if there is user data, then the option field will be counted as window size.
                    #if defined (ATP_LOG_AT_DEBUG)
                        assert(used_window >= out_pkt->payload);
                    #endif
                    used_window_packets --;
                    used_window -= out_pkt->payload;
                }
            }
            delete out_pkt;
            out_pkt = nullptr;
        }else{
            break;
        }
    }
}

void ATPSocket::update_rto(OutgoingPacket * recv_pkt){
    if (recv_pkt->transmissions > 0)
    {
        static constexpr double alpha = 0.9;
        uint64_t new_rtt = get_current_ms() - recv_pkt->timestamp;
        this->rtt = static_cast<uint32_t>(alpha * rtt + (1 - alpha) * new_rtt);
        uint32_t computed_rto = static_cast<uint32_t>(2 * this->rtt);
        this->rto = computed_rto;
        this->rto = std::max(this->rto, static_cast<uint32_t>(ATP_RTO_MIN));
        this->rto = std::min(this->rto, static_cast<uint32_t>(ATP_RTO_MAX));
        #if defined (ATP_LOG_AT_DEBUG)
            log_debug(this, "Computed new rtt:%u, rto:%u, choose rto:%u.", this->rtt, computed_rto, this->rto);
        #endif
    }
}

void ATPSocket::destroy(){
    // wait 2MSL to destroy
    atp_callback_arguments arg;
    arg = make_atp_callback_arguments(ATP_CALL_ON_DESTROY, nullptr, dest_addr);
    ATP_PROC_RESULT result = invoke_callback(ATP_CALL_ON_DESTROY, &arg);
    // notify context
    context->destroyed_sockets.push_back(this);
}

ATP_PROC_RESULT ATPSocket::check_timeout(){
    uint64_t current_ms = get_current_ms();
    if (!outbuf.empty())
    {
        // check delayed timeout
        if (delay_ack_timeout != 0 && (int64_t)(current_ms - delay_ack_timeout) > 0)
        {
            check_unsend_packet();
        }
        // check persist timeout
        if (persist_timeout != 0 && (int64_t)(current_ms - persist_timeout) > 0)
        {
            // probing whether peer's window is still zero
        }
        // check resend timeout
        if (rto_timeout != 0 && (int64_t)(current_ms - rto_timeout) > 0)
        {
            this->rto *= 2;
            this->rto = std::min(this->rto, static_cast<uint32_t>(ATP_RTO_MAX));
            #if defined (ATP_LOG_AT_DEBUG)
                log_debug(this, "Retransmit all %u un-acked packet.", outbuf.size());
            #endif
            bool close_flag = false;
            for(OutgoingPacket * out_pkt : outbuf){
                if (out_pkt->is_promised_packet() && !out_pkt->selective_acked)
                {
                    // do not resend empty ACK packet
                    if (out_pkt->transmissions > atp_retries2)
                    {
                        // give up this connection immediately
                        out_pkt->need_resend = true;
                        close_flag = true;
                    }else if(out_pkt->get_head()->get_syn() && out_pkt->transmissions > atp_syn_retries1){
                        out_pkt->need_resend = true;
                    }else if((!out_pkt->get_head()->get_syn()) && out_pkt->transmissions > atp_retries1){
                        out_pkt->need_resend = true;
                    }else{
                        out_pkt->need_resend = true;
                    }
                }
            }
            for(OutgoingPacket * out_pkt : outbuf){
                if (out_pkt->need_resend)
                {
                    send_packet_noguard(out_pkt);
                }
            }
            if (close_flag)
            {
                #if defined (ATP_LOG_AT_DEBUG)
                    log_debug(this, "Connection lost, destroy socket.", outbuf.size());
                #endif
                // peer lost, just destroy(not close, close is not necessary)
                conn_state = CS_DESTROY;
                this->destroy();
                return ATP_PROC_FINISH;
            }
        }
    }
    if (conn_state == CS_TIME_WAIT)
    {
        if ((int64_t)(current_ms - death_timeout) > 0 && death_timeout != 0)
        {
            #if defined (ATP_LOG_AT_DEBUG)
                log_debug(this, "Death timeouted at %u %u .", death_timeout, current_ms);
            #endif
            conn_state = CS_DESTROY;
            this->destroy();
            return ATP_PROC_FINISH;
        }
    }
    return ATP_PROC_OK;
}
