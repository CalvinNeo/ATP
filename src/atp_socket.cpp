#include "atp_impl.h"
#include "udp_util.h"

ATPSocket::ATPSocket(ATPContext * _context) : context(_context){
    assert(context != nullptr);
    sock_id = context->new_sock_id();
    conn_state = CS_UNINITIALIZED;
    memset(hash_str, 0, sizeof hash_str);
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
    #if defined (ATP_LOG) && ATP_LOG >= LOGLEVEL_DEBUG
        log_debug(this, "UDP Socket init, sockfd %d.", sockfd);
    #endif
    return sockfd;
}

int ATPSocket::connect(const ATPAddrHandle & to_addr){
    assert(context != nullptr);
    dest_addr = to_addr;

    assert(conn_state == CS_IDLE);
    conn_state = CS_SYN_SENT;
    register_to_look_up();

    seq_nr = rand() & 0xffff;
    ack_nr = 0;

    OutgoingPacket * out_pkt = basic_send_packet(ATPPacket::create_flags(PACKETFLAG_SYN));
    add_data(out_pkt, &sock_id, sizeof(sock_id));

    // before sending packet, users can do something, like call `connect` to their UDP socket.
    atp_callback_arguments arg = make_atp_callback_arguments(ATP_CALL_CONNECT, out_pkt, dest_addr);

    int result = context->callbacks[ATP_CALL_CONNECT](&arg);

    #if defined (ATP_LOG) && ATP_LOG >= LOGLEVEL_DEBUG
        log_debug(this, "UDP socket connect to %s. Abort sending SYN.", dest_addr.to_string());
    #endif
    if (result != 0){

    } else{
        result = send_packet(out_pkt);
        #if defined (ATP_LOG) && ATP_LOG >= LOGLEVEL_DEBUG
            log_debug(this, "Sent SYN to peer, seq:%u.", out_pkt -> get_head() -> seq_nr);
        #endif
    }
    return result;
}


int ATPSocket::listen(uint16_t host_port){
    conn_state = CS_LISTEN;
    // register to listen
    get_src_addr().set_port(host_port);
    context->listen_sockets[host_port] = this;
    #if defined (ATP_LOG) && ATP_LOG >= LOGLEVEL_DEBUG
        log_debug(this, "Listening port %u.", host_port);
    #endif
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

    assert(conn_state == CS_IDLE || conn_state == CS_LISTEN);
    conn_state = CS_SYN_RECV;
    register_to_look_up();
    peer_sock_id = *reinterpret_cast<uint16_t*>(recv_pkt->data + sizeof(ATPPacket));
    seq_nr = rand() & 0xffff;
    // must set ack_nr, because now ack_nr is still 0
    ack_nr = recv_pkt->get_head()->seq_nr;

    OutgoingPacket * out_pkt = basic_send_packet(ATPPacket::create_flags(PACKETFLAG_SYN, PACKETFLAG_ACK));
    add_data(out_pkt, &sock_id, sizeof(sock_id));
    int result = send_packet(out_pkt);

    #if defined (ATP_LOG) && ATP_LOG >= LOGLEVEL_DEBUG
        log_debug(this, "Accept SYN request from %s by sending SYN+ACK."
            , ATPSocket::make_hash_code(peer_sock_id, dest_addr));
    #endif

    return result;
}

int ATPSocket::update_ack(OutgoingPacket * recv_pkt){
    if(conn_state < CS_CONNECTED){
        // handles the last hand-shake of connection establishment

        #if defined (ATP_LOG) && ATP_LOG >= LOGLEVEL_DEBUG
            log_debug(this, "Connection established on B's side, handshake completed.");
        #endif
        conn_state = CS_CONNECTED;
    }
    int action = perf_norm;
    uint16_t peer_seq = recv_pkt->get_head()->seq_nr;
    if (peer_seq <= ack_nr){
        // this packet has already been acked, DROP!
        #if defined (ATP_LOG) && ATP_LOG >= LOGLEVEL_DEBUG
            log_debug(this, "Ack repeated and drop, my ack:%u.", ack_nr);
        #endif
        action = perf_drop;
    } else if(peer_seq == ack_nr + 1){
        #if defined (ATP_LOG) && ATP_LOG >= LOGLEVEL_DEBUG
            log_debug(this, "Ack normally, my ack:%u.", ack_nr);
        #endif
        ack_nr ++;
        action = perf_norm;
    } else{
        // there is at least one packet not acked before this packet, so we can't ack this
        #if defined (ATP_LOG) && ATP_LOG >= LOGLEVEL_DEBUG
            log_debug(this, "Peer sent seq:%u, But my ack:%u.", peer_seq, ack_nr);
        #endif
        action = perf_cache;
    }
    if (action == perf_norm)
    {
        switch(conn_state){
            case CS_UNINITIALIZED:
            case CS_IDLE:
                err_sys("conn_state error");
                goto ERROR;
            case CS_SYN_SENT:
                // altrady handled in `ATPSocket::process`
                err_sys("conn_state error");
                goto ERROR;
            case CS_SYN_RECV:
                // recv the last handshake, change state to CS_CONNECTED by update_ack automaticlly
                // connection established on side B
                // fallthrough
            case CS_CONNECTED:
            case CS_CONNECTED_FULL:
                goto CHECK;
            case CS_FIN_WAIT_1: // A
                // state: A's fin is sent to B. this ack must be an ack for A's fin, 
                // if will not be a ack for previous ack, because in this case `action != perf_norm`
                // action of ack: 
                conn_state = CS_FIN_WAIT_2;
                goto CHECK;
            case CS_CLOSE_WAIT: // B
                // state: this is half cloded state. B got A's fin, and knew A'll not send data.
                // But B can still send data, then A can send ack in response
                // action of ack: check that ack, because it may be an ack for B's data
                goto CHECK;
            case CS_FIN_WAIT_2: // A
                // state: A is fin now, and B knew A's fin. A can't send any data.
                // action of ack: discard this ack
                goto DISCARD; 
            case CS_LAST_ACK: // B
                // state: B has sent his fin, this ack must be A's response for B's fin
                // action of ack: change state
                conn_state = CS_DESTROY;
                goto CHECK;
            case CS_TIME_WAIT: 
                // state, A must wait 2 * MSL and then goto CS_DESTROY
                // action of ack: simply drop
                goto DISCARD; 
            case CS_RESET:
            case CS_DESTROY: 
                // the end
                goto DISCARD; 
            default:
                goto DISCARD; 
        }
    }
CHECK:
    return action;
ERROR:
    return perf_drop;
DISCARD:
    return perf_drop;
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

    log_debug(this, "UDP Send %u bytes.", result);
    if (result != out_pkt->length){

    } else{

    }
    return result;
}

int ATPSocket::close(){
    int result = 0;
    OutgoingPacket * out_pkt;
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
            out_pkt = basic_send_packet(ATPPacket::create_flags(PACKETFLAG_FIN));
            result = send_packet(out_pkt);
            break;
        case CS_FIN_WAIT_1:
            err_sys("conn_state error");
            break;
        case CS_CLOSE_WAIT:
            // B
            out_pkt = basic_send_packet(ATPPacket::create_flags(PACKETFLAG_FIN));
            result = send_packet(out_pkt);
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
    return result;
}

void ATPSocket::add_data(OutgoingPacket * out_pkt, const void * buf, const size_t len){
    out_pkt->length += len;
    out_pkt->payload += len;

    out_pkt->data = reinterpret_cast<char *>(std::realloc(out_pkt->data, out_pkt->length));
    memcpy(out_pkt->data + out_pkt->length - len, buf, len);
}

int ATPSocket::write(const void * buf, const size_t len){
    OutgoingPacket * out_pkt = basic_send_packet(ATPPacket::create_flags(PACKETFLAG_ACK));
    add_data(out_pkt, buf, len);

    #if defined (ATP_LOG) && ATP_LOG >= LOGLEVEL_DEBUG
        log_debug(this, "Write %u bytes to peer, seq:%u.", out_pkt->payload, seq_nr);
    #endif

    return send_packet(out_pkt);
}

int ATPSocket::process_packet(OutgoingPacket * recv_pkt){
    ATPPacket * pkt = recv_pkt->get_head();
    if(pkt->get_ack()){
        // already handled
    }
    if (pkt->get_fin())
    {
        switch(conn_state){
            case CS_UNINITIALIZED:
            case CS_IDLE:
            case CS_SYN_SENT:
            case CS_SYN_RECV:
                err_sys("conn_state error");
                break;
            case CS_CONNECTED:
            case CS_CONNECTED_FULL:
                conn_state = CS_CLOSE_WAIT;
                // half connect, don't send FIN immediately
                break;
            case CS_FIN_WAIT_1: // A
            case CS_CLOSE_WAIT: // B
                err_sys("conn_state error");
                break;
            case CS_FIN_WAIT_2: // A
                conn_state = CS_TIME_WAIT;
                break;
            case CS_LAST_ACK: // B
            case CS_TIME_WAIT: // A
            case CS_RESET:
            case CS_DESTROY:
                err_sys("conn_state error");
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
    OutgoingPacket * recv_pkt = new OutgoingPacket();
    // set OutgoingPacket
    // must copy received message from "kernel"
    recv_pkt->data = reinterpret_cast<char *>(std::calloc(1, len));
    std::memcpy(recv_pkt->data, buffer, len);
    recv_pkt->timestamp = get_current_ms();
    ATPPacket * pkt = recv_pkt->get_head();
    recv_pkt->length = len;
    recv_pkt->payload = recv_pkt->length - sizeof(ATPPacket);

    #if defined (ATP_LOG) && ATP_LOG >= LOGLEVEL_DEBUG
        log_debug(this, "ATPPacket recv, my_ack:%u peer_seq:%u peer_ack:%u size:%u payload:%u."
            , ack_nr, recv_pkt->get_head()->seq_nr, recv_pkt->get_head()->ack_nr, recv_pkt->length, recv_pkt->payload);
    #endif

    // SYN packet need to be handled immediately, and `addr` must register to `dest_addr` by `accept`
    // on the other hand, if we handle SYN from a queue, in `process_packet`
    // then we can't know `socket->dest_addr`
    if(pkt->get_syn() && pkt->get_ack()){
        // recv the second handshake
        // established on side A
        assert(conn_state == CS_SYN_SENT);
        conn_state = CS_CONNECTED;

        peer_sock_id = *reinterpret_cast<uint16_t *>(recv_pkt->data + sizeof(ATPPacket));
        // must set ack_nr, because now ack_nr is still 0
        ack_nr = recv_pkt->get_head()->seq_nr;
        #if defined (ATP_LOG) && ATP_LOG >= LOGLEVEL_DEBUG
            log_debug(this, "Connection established on A's side, sending ACK immediately to B to complete handshake.");
        #endif
        process_packet(recv_pkt);
        // send a ack even if there's no data immediately, in order to avoid timeout
        OutgoingPacket * out_pkt = basic_send_packet(ATPPacket::create_flags(PACKETFLAG_ACK));
        return send_packet(out_pkt);

    } else if(pkt->get_syn()){
        // recv the first handshake
        // send the second handshake
        this->accept(addr, recv_pkt);
        return process_packet(recv_pkt);
    }
    int action = update_ack(recv_pkt);
    switch(action){
        case perf_drop:
            #if defined (ATP_LOG) && ATP_LOG >= LOGLEVEL_DEBUG
                log_debug(this, "Drop packet, ack:%u peer_seq:%u", ack_nr, recv_pkt->get_head()->seq_nr);
            #endif
            delete recv_pkt;
            break;
        case perf_norm:
            return process_packet(recv_pkt);
            break;
        case perf_cache:
            #if defined (ATP_LOG) && ATP_LOG >= LOGLEVEL_DEBUG
                log_debug(this, "Cached packet, ack:%u peer seq:%u inbuf size: %u", ack_nr, recv_pkt->get_head()->seq_nr, inbuf.size());
            #endif
            inbuf.push(recv_pkt);
            break;
    }
    if (action == perf_norm)
    {
        // check if there is any packet which can be acked
        while(!inbuf.empty()){
            OutgoingPacket * top_packet = inbuf.top();
            action = update_ack(top_packet);
            switch(action){
                case perf_drop:
                    delete top_packet;
                    break;
                case perf_norm:
                    inbuf.pop();
                    return process_packet(recv_pkt);
                    break;
                case perf_cache:
                    // remain this state;
                    goto OUT_THE_LOOP;
                    break;
            }
        }
        OUT_THE_LOOP:
            int aaa = 1;
    }
    return 0;
}

