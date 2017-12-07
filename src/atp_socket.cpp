#include "atp_impl.h"
#include <queue>

ATPSocket::ATPSocket(ATPContext * _context) : context(_context){
    assert(context != nullptr);
    sock_id = context->new_sock_id();
    conn_state = CS_UNINITIALIZED;
    memset(hash_str, 0, sizeof hash_str);
}

void ATPSocket::register_to_look_up(){
    // if not registered, can't find `ATPSocket *` by (addr:port)
    (context->look_up)[dest_addr.hash_code()] = this;
}

int ATPSocket::connect(const ATPAddrHandle & to_addr){
    assert(context != nullptr);
    dest_addr = to_addr;

    assert(conn_state == CS_IDLE);
    conn_state = CS_SYN_SENT;
    register_to_look_up();

    seq_nr = rand();
    ack_nr = 0;
    #if defined (ATP_LOG) && ATP_LOG >= LOGLEVEL_DEBUG
        log_debug(this, "Connect sent SYN. seq:%u", seq_nr);
    #endif

    OutgoingPacket * out_pkt = basic_send_packet(ATPPacket::create_flags(PACKETFLAG_SYN));
    // before sending packet, users can do something, like call `connect` to their UDP socket.
    atp_callback_arguments arg = make_atp_callback_arguments(ATP_CALL_CONNECT, out_pkt, dest_addr);
    int result = context->callbacks[ATP_CALL_CONNECT](&arg);
    send_packet(out_pkt);
    return 0;
}

int ATPSocket::bind(const ATPAddrHandle & to_addr){
    // there's no OutgoingPacket to be sent, so pass `nullptr`
    atp_callback_arguments arg = make_atp_callback_arguments(ATP_CALL_BIND, nullptr, to_addr);
    int result = context->callbacks[ATP_CALL_BIND](&arg);
    return result;
}

int ATPSocket::accept(const ATPAddrHandle & to_addr, OutgoingPacket * recv_pkt){
    assert(context != nullptr);
    dest_addr = to_addr;

    assert(conn_state == CS_IDLE);
    conn_state = CS_SYN_RECV;
    register_to_look_up();

    seq_nr = rand();
    ack_nr = recv_pkt->get_head()->seq_nr;

    #if defined (ATP_LOG) && ATP_LOG >= LOGLEVEL_DEBUG
        log_debug(this, "Accept request [%05u]%s", recv_pkt->get_head()->peer_sock_id, dest_addr.hash_code());
    #endif

    OutgoingPacket * out_pkt = basic_send_packet(ATPPacket::create_flags(PACKETFLAG_SYN, PACKETFLAG_ACK));
    send_packet(out_pkt);
    return 0;
}

int ATPSocket::update_ack(OutgoingPacket * recv_pkt){
    if(conn_state < CS_CONNECTED){
        // handles the last hand-shake of connection establishment
        conn_state = CS_CONNECTED;
    }
    uint16_t peer_seq = recv_pkt->get_head()->seq_nr;
    if (peer_seq <= ack_nr){
        // this packet has already been acked, DROP!
        #if defined (ATP_LOG) && ATP_LOG >= LOGLEVEL_DEBUG
            log_debug(this, "Ack repeated and drop. my ack:%u", ack_nr);
        #endif
        return perf_drop;
    } else if(peer_seq == ack_nr + 1){
        #if defined (ATP_LOG) && ATP_LOG >= LOGLEVEL_DEBUG
            log_debug(this, "Ack normally. my ack:%u", ack_nr);
        #endif
        ack_nr ++;
        return perf_norm;
    } else{
        // there is at least one packet not acked before this packet
        // so we can't ack this
        #if defined (ATP_LOG) && ATP_LOG >= LOGLEVEL_DEBUG
            log_debug(this, "Peer sent seq:%u. But my ack:%u", peer_seq, ack_nr);
        #endif
        // TODO: put this into inbuf
        return perf_cache;
    }
}

int ATPSocket::send_packet(OutgoingPacket * out_pkt){
    uint64_t current_ms = get_current_ms();
    rto_timeout = current_ms + rto;

    outbuf.ensure_size(cur_window_packets);
    outbuf.put(seq_nr, out_pkt);
    // when the package is constructed, update `seq_nr` for the next package
    seq_nr++;
    cur_window_packets++;

    out_pkt->timestamp = get_current_ms();
    out_pkt->transmissions++;

    #if defined (ATP_LOG) && ATP_LOG >= LOGLEVEL_DEBUG
        log_debug(this, "ATPPacket sent. seq:%u size:%u payload:%u", out_pkt->get_head()->seq_nr, out_pkt->length, out_pkt->payload);
    #endif

    // udp send
    atp_callback_arguments arg = make_atp_callback_arguments(ATP_CALL_SENDTO, out_pkt, dest_addr);
    int result = context->callbacks[ATP_CALL_SENDTO](&arg);
    if (result != out_pkt->length){
        #if defined (ATP_LOG) && ATP_LOG >= LOGLEVEL_DEBUG
            log_debug(this, "Send %u faild.", out_pkt->get_head()->seq_nr);
        #endif
    } else{
        #if defined (ATP_LOG) && ATP_LOG >= LOGLEVEL_DEBUG
            log_debug(this, "Send %u success.", out_pkt->get_head()->seq_nr);
        #endif
    }
    return result;
}

int ATPSocket::close(){
    switch(conn_state){
        case CS_UNINITIALIZED:
        case CS_IDLE:
        case CS_SYN_SENT:
        case CS_SYN_RECV:
            err_sys("conn_state error");
            break;
        case CS_CONNECTED:
        case CS_CONNECTED_FULL:
            // A
            break;
        case CS_FIN_WAIT_1:
            err_sys("conn_state error");
            break;
        case CS_CLOSE_WAIT:
            // B
            break;
        case CS_FIN_WAIT_2:
        case CS_LAST_ACK:
        case CS_TIME_WAIT:
        case CS_RESET:
        case CS_DESTROY:
            err_sys("conn_state error");
            break;
        default:
            break;
    }
    return 0;
}

void ATPSocket::add_data(OutgoingPacket * out_pkt, const void * buf, const size_t len){
    out_pkt->length += len;
    out_pkt->payload += len;

    out_pkt->data = reinterpret_cast<char *>(std::realloc(out_pkt->data, out_pkt->length));
    memcpy(out_pkt->data, out_pkt->data + out_pkt->length - len, len);
}

int ATPSocket::write(const void * buf, const size_t len){
    OutgoingPacket * out_pkt = basic_send_packet(ATPPacket::create_flags(PACKETFLAG_ACK));
    add_data(out_pkt, buf, len);

    #if defined (ATP_LOG) && ATP_LOG >= LOGLEVEL_DEBUG
        log_debug(this, "write %u bytes to peer. seq:%u", out_pkt->payload, seq_nr);
    #endif

    return send_packet(out_pkt);
}

int ATPSocket::process_packet(OutgoingPacket * recv_pkt){
    ATPPacket * pkt = recv_pkt->get_head();
    int action = perf_norm;
    if(pkt->get_ack()){
        switch(conn_state){
            case CS_UNINITIALIZED:
            case CS_IDLE:
            case CS_SYN_SENT:
                err_sys("conn_state error");
                break;
            case CS_SYN_RECV:
                // recv the last handshake, change state to CS_CONNECTED by update_ack automaticlly
                // connection established on side B
                // goto case CS_CONNECTED; // fallthrough
            case CS_CONNECTED:
            case CS_CONNECTED_FULL:
                action = this->update_ack(recv_pkt);
                break;
            case CS_FIN_WAIT_1: // A
                // A's fin is acked by B
                action = this->update_ack(recv_pkt);
                conn_state = CS_FIN_WAIT_2;
                break;
            case CS_CLOSE_WAIT: // B
                // this is half cloded state. B knows A is fin, and will not send data.
                // But B can still send data, then A can send ack in response
                // this ack should be proceeded
                action = this->update_ack(recv_pkt);
                break;
            case CS_FIN_WAIT_2: // A
                // A is fin now, which means A can't send data
                // so B's ack is useless
                action = perf_drop; 
            case CS_LAST_ACK: // B
                // now B has sent his fin, it get ack from A. his life ends, RIP.
                conn_state = CS_DESTROY;
            case CS_TIME_WAIT: 
                // in this state, A must wait 2 * MSL and then goto CS_DESTROY
                action = perf_drop; 
                break;
            case CS_RESET:
            case CS_DESTROY: 
                // the end
                break;
            default:
                break;
        }
    }

    if (recv_pkt->payload > 0)
    {
        // if there's payload
        this->receive(recv_pkt->data, recv_pkt->length);
    }
    return 0;
}

int ATPSocket::process(const ATPAddrHandle & addr, const char * buffer, size_t len){
    OutgoingPacket recv_pkt;
    // set OutgoingPacket
    // must copy received message from "kernel"
    recv_pkt.data = reinterpret_cast<char *>(std::calloc(1, len));
    std::memcpy(recv_pkt.data, buffer, len);
    recv_pkt.timestamp = get_current_ms();
    ATPPacket * pkt = recv_pkt.get_head();
    recv_pkt.length = len;
    recv_pkt.payload = recv_pkt.length - sizeof(ATPPacket);

    #if defined (ATP_LOG) && ATP_LOG >= LOGLEVEL_DEBUG
        log_debug(this, "ATPPacket recv. ack:%u peer seq:%u peer ack:%u size:%u payload:%u"
            , ack_nr, recv_pkt.get_head()->seq_nr, recv_pkt.get_head()->ack_nr, recv_pkt.length, recv_pkt.payload);
    #endif

    // SYN packet need to be handled immediately, and `addr` must register to `dest_addr` by `accept`
    // on the other hand, if we handle SYN from a queue, in `process_packet`
    // then we can't know `socket->dest_addr`
    if(pkt->get_syn() && pkt->get_ack()){
        // recv the second handshake
        // established on side A
        assert(conn_state == CS_SYN_SENT);
        conn_state = CS_CONNECTED;
        // TODO: send a ack even if there's no data immediately, in order to avoid timeout

    } else if(pkt->get_syn()){
        assert(conn_state == CS_IDLE);
        // recv the first handshake
        // send the second handshake
        this->accept(addr, &recv_pkt);
    }

    process_packet(&recv_pkt);
    return 0;
}

