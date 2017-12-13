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
    ATPPacket pkt = ATPPacket{
        (seq_nr & seq_nr_mask), // seq_nr, updatede in send_packet
        (ack_nr & seq_nr_mask), // ack_nr
        peer_sock_id, // peer_sock_id
        flags, // flags
        my_window // my window
    };
    OutgoingPacket * out_pkt = new OutgoingPacket{
        true,
        sizeof (ATPPacket), // length, update by `add_data`
        0, // payload, update by `add_data`
        0, // timestamp, set at `send_packet`
        0, // transmissions, update by `send_packet`
        false, // need_resend, update by `send_packet`
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
        seq_nr = rand() & seq_nr_mask;
    }
    ack_nr = 0;

    OutgoingPacket * out_pkt = basic_send_packet(ATPPacket::create_flags(PACKETFLAG_SYN));
    add_data(out_pkt, &sock_id, sizeof(sock_id));

    // before sending packet, users can do something, like call `connect` to their UDP socket.
    atp_callback_arguments arg = make_atp_callback_arguments(ATP_CALL_CONNECT, out_pkt, dest_addr);
    ATP_PROC_RESULT result = invoke_callback(ATP_CALL_CONNECT, &arg);

    #if defined (ATP_LOG_AT_DEBUG) && defined(ATP_LOG_UDP)
        log_debug(this, "UDP socket connect to %s.", dest_addr.to_string());
    #endif
    if (result == ATP_PROC_ERROR){

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
    dest_addr = to_addr;

    assert(conn_state == CS_IDLE || conn_state == CS_LISTEN);
    conn_state = CS_SYN_RECV;

    register_to_look_up();
    peer_sock_id = *reinterpret_cast<uint16_t*>(recv_pkt->data + sizeof(ATPPacket));
    while(seq_nr == 0){
        seq_nr = rand() & seq_nr_mask;
    }

    // must FORCE set ack_nr, because now ack_nr is still 0
    ack_nr = recv_pkt->get_head()->seq_nr;
    // get peer's window
    cur_window = recv_pkt->get_head()->window_size;

    atp_callback_arguments arg = make_atp_callback_arguments(ATP_CALL_BEFORE_ACCEPT, nullptr, dest_addr);
    result = invoke_callback(ATP_CALL_BEFORE_ACCEPT, &arg);

    if (result == ATP_PROC_OK)
    {
        OutgoingPacket * out_pkt = basic_send_packet(ATPPacket::create_flags(PACKETFLAG_SYN, PACKETFLAG_ACK));
        add_data(out_pkt, &sock_id, sizeof(sock_id));
        result = send_packet(out_pkt);

        atp_callback_arguments arg = make_atp_callback_arguments(ATP_CALL_ON_ACCEPT, nullptr, dest_addr);
        result = invoke_callback(ATP_CALL_ON_ACCEPT, &arg);

        #if defined (ATP_LOG_AT_DEBUG)
            log_debug(this, "Accept SYN request from %s by sending SYN+ACK."
                , ATPSocket::make_hash_code(peer_sock_id, dest_addr));
        #endif
    }else if(result == ATP_PROC_REJECT)
    {
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

ATP_PROC_RESULT ATPSocket::receive(OutgoingPacket * recv_pkt){
    if (recv_pkt->get_head()->get_fin())
    {
        // cond2: ignore fin
        // just ignore
        return ATP_PROC_OK;
    }else if(recv_pkt->get_head()->get_syn()){
        // the 2 bytes payload in syn packet are not user data, they carried sock_id
        return ATP_PROC_OK;
    }else if(recv_pkt->payload == 0){
        // there is payload
        // just ignore
        return ATP_PROC_OK;
    }else{
        atp_callback_arguments arg = make_atp_callback_arguments(ATP_CALL_ON_RECV, recv_pkt, dest_addr);
        arg.data = recv_pkt->data + sizeof(ATPPacket);
        arg.length = recv_pkt->payload;
        return invoke_callback(ATP_CALL_ON_RECV, &arg);
    }
}

ATP_PROC_RESULT ATPSocket::send_packet_unchecked(OutgoingPacket * out_pkt){
    uint64_t current_ms = get_current_ms();
    rto_timeout = current_ms + rto;
    used_window_packets++;
    used_window += out_pkt->payload;
    #if defined (ATP_LOG_AT_DEBUG)
        log_debug(this, "ATPPacket sent. seq:%u size:%u payload:%u", out_pkt->get_head()->seq_nr, out_pkt->length, out_pkt->payload);
    #endif
    #if defined (ATP_LOG_AT_NOTE)
        if (out_pkt->transmissions == 0)
        {
            print_out(this, out_pkt, "snd");
        }else{
            print_out(this, out_pkt, "re-snd");
        }
    #endif
    out_pkt->timestamp = get_current_ms();
    out_pkt->transmissions++;
    atp_callback_arguments arg = make_atp_callback_arguments(ATP_CALL_SENDTO, out_pkt, dest_addr);
    if (out_pkt->need_resend)
    {
        out_pkt->need_resend = false;
    }
    return invoke_callback(ATP_CALL_SENDTO, &arg);
}

void ATPSocket::check_unsend_packet(){
    for(OutgoingPacket * out_pkt : outbuf){
        // check everytime in the for-loop
        if (bytes_can_send_one_packet() >= out_pkt->payload)
        {
            // never cache
            if (out_pkt->transmissions == 0 || out_pkt->need_resend)
            {
                send_packet_unchecked(out_pkt);
            }
        }
    }
}

ATP_PROC_RESULT ATPSocket::send_packet(OutgoingPacket * out_pkt){
    check_unsend_packet();
    ATP_PROC_RESULT result = ATP_PROC_OK;
    // setup packets
    // when the package is constructed, update `seq_nr` for the next package
    if (out_pkt->payload > 0 && !out_pkt->need_resend)
    {
        out_pkt->get_head()->seq_nr ++;
        (out_pkt->get_head()->seq_nr) &= seq_nr_mask;
        seq_nr ++;
    }
    if (bytes_can_send_one_packet() >= out_pkt->payload)
    {
        // actually send
        // if payload == 0(ACK, FIN), can always send at once
        result = send_packet_unchecked(out_pkt);
    }else{
        #if defined (ATP_LOG_AT_DEBUG)
            log_debug(this, "ATPPacket sent CACHED due to window limit. seq:%u size:%u payload:%u"
                , out_pkt->get_head()->seq_nr, out_pkt->length, out_pkt->payload);
        #endif
        result = ATP_PROC_OK;
    }
    
    if (out_pkt->payload == 0 && !(out_pkt->get_head()->get_syn() || out_pkt->get_head()->get_fin()) )
    {
        // ad-hoc send, don't enqueue
        // if payload == 0(except SYN, FIN), can always delete at once
        delete out_pkt;
    }else{
        // enqueue for potential resend
        outbuf.push_back(out_pkt);
        std::push_heap(outbuf.begin(), outbuf.end(), _cmp_outgoingpacket());
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
            log_debug(this, "Window restricted, will only partially send, cache the rest.");
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

            OutgoingPacket *  out_pkt = basic_send_packet(ATPPacket::create_flags(PACKETFLAG_ACK));
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
    if (raw_peer_seq == 0 && !zero_lock)
    {
        // peer's seq_nr wraps here
        peer_seq_nr_base += (seq_nr_mask + 1);
        #if defined (ATP_LOG_AT_DEBUG)
            log_debug(this, "Seq_nr overflow to 0, current base %u(%x).", peer_seq_nr_base, peer_seq_nr_base);
        #endif
        // because there may be several packets which have seq_nr == 0(one with paylod, others don't)
        // only overflow once
        zero_lock = true;
    } else if(raw_peer_seq != 0){
        zero_lock = false;
    }
    // and then we update peer_seq
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
    // get peer's window
    cur_window = recv_pkt->get_head()->window_size;
    if (recv_pkt->payload == 0)
    {
        // peer don't send data, this packet only tell us ack number, for our `do_ack_packet` function
        // it's seq_nr maybe repeated
        action = ATP_PROC_OK;
        #if defined (ATP_LOG_AT_DEBUG)
            log_debug(this, "This is a empty packet with repeated raw_seq_nr:%u, seq_nr:%u, ack_nr:%u, my ack is:%u."
                , raw_peer_seq, peer_seq, recv_pkt->get_head()->ack_nr, ack_nr);
        #endif
        #if defined (ATP_LOG_AT_NOTE)
            print_out(this, recv_pkt, "rcv");
        #endif
        ack_nr = peer_seq;
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
            #if defined (ATP_LOG_AT_NOTE)
                print_out(this, recv_pkt, "rcv");
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

ATP_PROC_RESULT ATPSocket::process(const ATPAddrHandle & addr, const char * buffer, size_t len){
    OutgoingPacket * recv_pkt = new OutgoingPacket();
    // set OutgoingPacket
    // must copy received message from "kernel"
    recv_pkt->data = reinterpret_cast<char *>(std::calloc(1, len));
    std::memcpy(recv_pkt->data, buffer, len);
    recv_pkt->timestamp = get_current_ms();
    ATPPacket * pkt = recv_pkt->get_head();
    recv_pkt->length = len;
    recv_pkt->payload = recv_pkt->length - sizeof(ATPPacket);

    ATP_PROC_RESULT result = ATP_PROC_OK;

    uint32_t raw_peer_seq = recv_pkt->get_head()->seq_nr;
    #if defined (ATP_LOG_AT_DEBUG)
        log_debug(this, "ATPPacket recv, my_ack:%u raw_peer_seq:%u(base%u) peer_ack:%u size:%u payload:%u."
            , ack_nr, raw_peer_seq, peer_seq_nr_base,recv_pkt->get_head()->ack_nr, recv_pkt->length, recv_pkt->payload);
    #endif
    // HANDLE IMMEDIATELY
    // SYN packet need to be handled immediately, and `addr` must register to `dest_addr` by `accept`
    // on the other hand, if we handle SYN from a queue, in `process_packet`
    // then we can't know `socket->dest_addr`
    if(pkt->get_syn() && pkt->get_ack()){
        // recv the second handshake
        // established on side A
        if (conn_state != CS_SYN_SENT)
        {
            OutgoingPacket * out_pkt = basic_send_packet(ATPPacket::create_flags(PACKETFLAG_RST));
            result = send_packet(out_pkt);
        }
        conn_state = CS_CONNECTED;

        peer_sock_id = *reinterpret_cast<uint16_t *>(recv_pkt->data + sizeof(ATPPacket));
        // must FORCE set ack_nr, because now ack_nr is still 0
        ack_nr = recv_pkt->get_head()->seq_nr;
        // get peer's window
        cur_window = recv_pkt->get_head()->window_size;
        // MUST ack my previous SYN Packet, or it will be re-sent
        do_ack_packet(recv_pkt);

        #if defined (ATP_LOG_AT_DEBUG)
            log_debug(this, "Connection established on A's side, sending ACK immediately to B to complete handshake.");
        #endif

        #if defined (ATP_LOG_AT_NOTE)
            print_out(this, recv_pkt, "rcv");
        #endif
        // send a ack even if there's no data immediately, in order to avoid timeout
        OutgoingPacket * out_pkt = basic_send_packet(ATPPacket::create_flags(PACKETFLAG_ACK));
        send_packet(out_pkt);
        result = ATP_PROC_OK;
        return result;

    } else if(pkt->get_syn()){
        // recv the first handshake
        // send the second handshake
        #if defined (ATP_LOG_AT_NOTE) 
            print_out(this, recv_pkt, "rcv");
        #endif
        this->accept(addr, recv_pkt);
        result = ATP_PROC_OK;
        return result;
    } 

    uint32_t old_ack_nr = ack_nr;
    int action = update_myack(recv_pkt);
    do_ack_packet(recv_pkt);
    switch(action){
        case ATP_PROC_DROP:
        {
            #if defined (ATP_LOG_AT_DEBUG)
                log_debug(this, "Drop packet, raw_peer_seq:%u, my ack:%u", raw_peer_seq, ack_nr);
            #endif
            #if defined (ATP_LOG_AT_NOTE)
                print_out(this, recv_pkt, "drop");
            #endif
            delete recv_pkt;
            recv_pkt = nullptr;
            // maybe peer has not receive my ACK, so it keep re-sending
            OutgoingPacket * out_pkt = basic_send_packet(ATPPacket::create_flags(PACKETFLAG_ACK));
            send_packet(out_pkt);
            result = ATP_PROC_OK;
            break;
        }
        case ATP_PROC_OK:
            result = this->receive(recv_pkt);
            break;
        case ATP_PROC_CACHE:
            #if defined (ATP_LOG_AT_DEBUG)
                log_debug(this, "Cached packet, ack:%u raw_peer_seq:%u inbuf_size: %u", ack_nr, raw_peer_seq, inbuf.size());
            #endif
            inbuf.push(recv_pkt);
            result = ATP_PROC_OK;
            break;
        case ATP_PROC_FINISH:
            // handled near the end of this function
            break;
    }
    #if defined (ATP_LOG_AT_DEBUG)
        log_debug(this, "After handled this packet, there are %u left in inbuf.", inbuf.size());
    #endif
    if (action == ATP_PROC_OK)
    {
        // check if there is any packet which can be acked
        while(!inbuf.empty()){
            OutgoingPacket * top_packet = inbuf.top();
            action = update_myack(top_packet);
            uint32_t peer_seq = get_full_seq_nr(recv_pkt->get_head()->seq_nr);
            switch(action){
                case ATP_PROC_DROP:
                    #if defined (ATP_LOG_AT_DEBUG)
                        log_debug(this, "Drop packet from cache, ack:%u peer_seq:%u", ack_nr, peer_seq);
                    #endif
                    #if defined (ATP_LOG_AT_NOTE)
                        print_out(this, top_packet, "drop");
                    #endif
                    delete top_packet;
                    top_packet = nullptr;
                    result = ATP_PROC_OK;
                    break;
                case ATP_PROC_OK:
                    inbuf.pop();
                    #if defined (ATP_LOG_AT_DEBUG)
                        log_debug(this, "Process a cached ATPPacket, peer_seq:%u, my ack:%u", peer_seq, ack_nr);
                    #endif
                    result = this->receive(recv_pkt);
                    break;
                case ATP_PROC_CACHE:
                    // remain this state;
                    goto OUT_THE_LOOP;
                    result = ATP_PROC_OK;
                    break;
                case ATP_PROC_FINISH:
                    // handled near the end of this function
                    break;
            }
        }
        OUT_THE_LOOP:
            int aaa = 1;
    }
    if (ack_nr != old_ack_nr)
    {
        // if ack_nr is updated, which means I read some packets from peer
        // send an ack packet immediately
        OutgoingPacket * out_pkt = basic_send_packet(ATPPacket::create_flags(PACKETFLAG_ACK));
        send_packet(out_pkt);
    }
    if (action == ATP_PROC_FINISH)
    {
        if (conn_state == CS_DESTROY)
        {
            // destroy immediately
            this->destroy();
        }
        result = action;
    } 
    else if (pkt->get_fin())
    {
        result = check_fin(recv_pkt);
    }
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

ATP_PROC_RESULT ATPSocket::do_ack_packet(OutgoingPacket * recv_pkt){
    // ack n means ack [0..n]
    uint32_t raw_peer_ack = recv_pkt->get_head()->ack_nr;
    uint32_t lowbit_mask = ~(seq_nr_mask);
    uint32_t my_seq_acked_by_peer_start = lowbit_mask & my_seq_acked_by_peer;
    uint32_t calculated_peer_ack = 0;
    uint32_t ack_delta = 0;
    if (my_seq_acked_by_peer_start + raw_peer_ack >= my_seq_acked_by_peer)
    {
        // it's stupid to ack a previous ack
        ack_delta = 0;
    }else{
        ack_delta = (seq_nr_mask + 1);
    }
    calculated_peer_ack = my_seq_acked_by_peer_start + ack_delta + raw_peer_ack;
        // log_debug(this, "Compute actual ACK, ack_delta:%u, raw_peer_ack:%u, lowbit_mask:%u, my_seq_acked_by_peer_start:%u, calculated_peer_ack:%u, my_seq_acked_by_peer: %u."
        //     , ack_delta , raw_peer_ack, lowbit_mask, my_seq_acked_by_peer_start, calculated_peer_ack, my_seq_acked_by_peer );
    #if defined (ATP_LOG_AT_DEBUG)
        log_debug(this, "Compute actual ACK, ack_delta:%u, raw_peer_ack:%u, lowbit_mask:%u, my_seq_acked_by_peer_start:%u, calculated_peer_ack:%u, my_seq_acked_by_peer: %u."
            , ack_delta , raw_peer_ack, lowbit_mask, my_seq_acked_by_peer_start, calculated_peer_ack, my_seq_acked_by_peer );
    #endif
    my_seq_acked_by_peer = std::max(calculated_peer_ack, my_seq_acked_by_peer);
    while(!outbuf.empty()){
        OutgoingPacket * out_pkt = outbuf[0]; 
        ATPPacket * pkt = out_pkt->get_head();
        if ((pkt->seq_nr) + ack_delta + my_seq_acked_by_peer_start <= my_seq_acked_by_peer)
        {
            #if defined (ATP_LOG_AT_DEBUG)
                log_debug(this, "Removing ATPPackct seq_nr:%u from buffer, peer_ack:%u, %u packet remain(including me)."
                    , (pkt->seq_nr) + ack_delta + my_seq_acked_by_peer_start, my_seq_acked_by_peer, outbuf.size());
            #endif
            update_rto(out_pkt);
            std::pop_heap(outbuf.begin(), outbuf.end(), _cmp_outgoingpacket());
            outbuf.pop_back();
            used_window_packets --;
            used_window -= out_pkt->payload;
            delete out_pkt;
            out_pkt = nullptr;
        }else{
            break;
        }
    }
}

void ATPSocket::update_rto(OutgoingPacket * recv_pkt){
    if (recv_pkt->transmissions == 1)
    {
        static constexpr double alpha = 0.9;
        uint64_t new_rtt = get_current_ms() - recv_pkt->timestamp;
        this->rtt = static_cast<uint32_t>(alpha * rtt + (1 - alpha) * new_rtt);
        uint32_t computed_rto = static_cast<uint32_t>(2 * this->rtt);
        this->rto = computed_rto;
        this->rto = std::max(this->rto, static_cast<uint32_t>(ATP_RTO_MIN));
        this->rto = std::min(this->rto, static_cast<uint32_t>(ATP_RTO_MAX));
        #if defined (ATP_LOG_AT_DEBUG)
            log_debug(this, "Computed new rtt:%u rto:%u, choose rto:%u.", this->rtt, computed_rto, this->rto);
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
        // check resend timeout
        if ((int64_t)(current_ms - rto_timeout) > 0 && rto_timeout != 0)
        {
            rto *= 2;
            #if defined (ATP_LOG_AT_DEBUG)
                log_debug(this, "Retransmit all %u un-acked packet", outbuf.size());
            #endif
            for(OutgoingPacket * out_pkt : outbuf){
                out_pkt->need_resend = true;
            }
            for(OutgoingPacket * out_pkt : outbuf){
                if (out_pkt->need_resend)
                {
                    send_packet_unchecked(out_pkt);
                }
            }
        }
        // check persist timeout
        if ((int64_t)(current_ms - persist_timeout) > 0 && persist_timeout != 0)
        {

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
