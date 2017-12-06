#include "atp_impl.h"


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
    #if defined (ATP_LOG ) && ATP_LOG >= LOGLEVEL_DEBUG
        log_debug(this, "Connect sent. seq:%d", seq_nr);
    #endif

    OutgoingPacket * out_pkt = basic_send_packet(ATPPacket::create_flags(PACKETFLAG_SYN));
    // before sending packet, users can do something, like call `connect`
    // to their UDP socket.
    atp_callback_arguments arg = atp_callback_arguments{
        context,
        this,
        ATP_CALL_CONNECT,
        out_pkt->length, out_pkt->data, 
        (const SA*)&(dest_addr.sa)
    };
    int result = context->callbacks[ATP_CALL_CONNECT](&arg);
    send_packet(out_pkt);
    return 0;
}

void ATPSocket::send_packet(OutgoingPacket * out_pkt){
    uint64_t current_ms = get_current_ms();
    rto_timeout = current_ms + rto;

    outbuf.ensure_size(cur_window_packets);
    outbuf.put(seq_nr, out_pkt);
    seq_nr++;
    cur_window_packets++;

    out_pkt->time_sent = get_current_ms();
    out_pkt->transmissions++;

    // udp send
    atp_callback_arguments arg = atp_callback_arguments{
        context,
        this,
        ATP_CALL_SENDTO,
        out_pkt->length, out_pkt->data, 
        (const SA*)&(dest_addr.sa)
    };
    int result = context->callbacks[ATP_CALL_SENDTO](&arg);
    if (result != out_pkt->length){

    } else{

    }
}

int ATPSocket::process(const ATPAddrHandle & addr, const char * buffer, size_t len){
    OutgoingPacket out_pkt;
    // must copy received message from "kernel"
    out_pkt.data = reinterpret_cast<char *>(std::calloc(1, len));
    std::memcpy(out_pkt.data, buffer, len);

    ATPPacket * pkt = out_pkt.get_head();

    out_pkt.length = len;
    out_pkt.payload = out_pkt.length - pkt->head_size;

    if(pkt->get_syn() && pkt->get_ack()){
        assert(conn_state == CS_SYN_SENT);
        conn_state = CS_CONNECTED;
    } else if(pkt->get_syn()){
        assert(conn_state == CS_IDLE);
        this->accept(addr, &out_pkt);
    } else if(pkt->get_ack()){
        switch(conn_state){
            case CS_UNINITIALIZED:
            case CS_IDLE:
            case CS_SYN_SENT:
                err_sys("conn_state error");
                break;
            case CS_SYN_RECV:
            case CS_CONNECTED:
            case CS_CONNECTED_FULL:
                this->update_ack();
                break;
            case CS_FIN_WAIT_1:
            case CS_CLOSE_WAIT:
            case CS_FIN_WAIT_2:
            case CS_LAST_ACK:
            case CS_TIME_WAIT:
            case CS_RESET:
            case CS_DESTROY:
                break;
            default:
                break;
        }
    } else if(pkt->get_fin()){

    } 
    if (out_pkt.payload > 0)
    {
        this->receive(buffer, len);
    }
}


static void _log_doit(ATPSocket * socket, int level, char const *fmt, va_list va){
    char new_fmt[2048];
    std::snprintf(new_fmt, 2048, "[%s] %s\n", socket->to_string(), fmt);

    char buf[8192];
    memset(buf, 0, sizeof buf);

    std::fprintf(stderr, new_fmt, va);
}

void log_fatal(ATPSocket * socket, char const *fmt, ...){
    va_list va;
    va_start(va, fmt);
    _log_doit(socket, LOGLEVEL_FATAL, fmt, va);
    va_end(va);
    exit(1);
}
void log_debug(ATPSocket * socket, char const *fmt, ...){
    va_list va;
    va_start(va, fmt);
    _log_doit(socket, LOGLEVEL_DEBUG, fmt, va);
    va_end(va);
}
void log_note(ATPSocket * socket, char const *fmt, ...){
    va_list va;
    va_start(va, fmt);
    _log_doit(socket, LOGLEVEL_NOTE, fmt, va);
    va_end(va);
}