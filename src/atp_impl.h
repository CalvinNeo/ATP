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
#pragma once

#include "error.h"
#include "scaffold.h"
#include "atp_common.h"
#include <cstdio>
#include <string>
#include <map>
#include <tuple>
#include <array>
#include <cstdlib>
#include <algorithm>
#include <functional>
#include <queue>
#include <type_traits>

#define LOGLEVEL_FATAL 1
#define LOGLEVEL_NOTE 2
#define LOGLEVEL_DEBUG 3
// Define this macro to enable basic logging
// #define ATP_LOG_AT_NOTE
// Define this macro to enable detailed logging message
// #define ATP_LOG_AT_DEBUG
// Define this macro to show debuging message at UDP level
// #define ATP_LOG_UDP
// Define this macro to force a seq_nr overflowing situation
// #define ATP_DEBUG_TEST_OVERFLOW

// #define ATP_SHUTDOWN_SYN

#define _log_doit _log_doit1
void _log_doit1(ATPSocket * socket, char const* func_name, int line, int level, char const * fmt, va_list va);
void _log_doit1(ATPContext * context, char const* func_name, int line, int level, char const * fmt, va_list va);
struct _log_doit2 {
    operator std::function<void(ATPSocket *, char const *, va_list)> () const {
        return [&](ATPSocket * x, char const * fmt, va_list va) {
            _log_doit1(x, func_name, line, level, fmt, va);
        };
    }
    operator std::function<void(ATPContext *, char const *, va_list)> () const {
        return [&](ATPContext * x, char const * fmt, va_list va) {
            _log_doit1(x, func_name, line, level, fmt, va);
        };
    }
    _log_doit2(const char* f, int line_no, int l) : func_name(f), level(l), line(line_no) {

    }
    const char* func_name;
    int line;
    int level;
};
void log_fatal1(ATPSocket * socket, char const *fmt, ...);
void log_debug1(ATPSocket * socket, char const *fmt, ...);
void log_note1(ATPSocket * socket, char const *fmt, ...);
void log_fatal1(ATPContext * context, char const *fmt, ...);
void log_debug1(ATPContext * context, char const *fmt, ...);
void log_note1(ATPContext * context, char const *fmt, ...);
void log_fatal2(std::function<void(ATPSocket *, char const *, va_list)> f, ATPSocket * socket, char const *fmt, ...);
void log_debug2(std::function<void(ATPSocket *, char const *, va_list)> f, ATPSocket * socket, char const *fmt, ...);
void log_note2(std::function<void(ATPSocket *, char const *, va_list)> f, ATPSocket * socket, char const *fmt, ...);
void log_fatal2(std::function<void(ATPContext *, char const *, va_list)> f, ATPContext * context, char const *fmt, ...);
void log_debug2(std::function<void(ATPContext *, char const *, va_list)> f, ATPContext * context, char const *fmt, ...);
void log_note2(std::function<void(ATPContext *, char const *, va_list)> f, ATPContext * context, char const *fmt, ...);
#define _log_fatal2(s, f, ...) log_fatal2(_log_doit2(__FUNCTION__, __LINE__, LOGLEVEL_FATAL), s, f, ##__VA_ARGS__)
#define _log_debug2(s, f,...) log_debug2(_log_doit2(__FUNCTION__, __LINE__, LOGLEVEL_DEBUG), s, f, ##__VA_ARGS__)
#define _log_note2(s, f, ...) log_note2(_log_doit2(__FUNCTION__, __LINE__, LOGLEVEL_NOTE), s, f, ##__VA_ARGS__)
// #define _log_fatal2(...) log_fatal2(_log_doit2(__FUNCTION__, LOGLEVEL_FATAL), __VA_ARGS__)
// #define _log_debug2(...) log_debug2(_log_doit2(__FUNCTION__, LOGLEVEL_DEBUG), __VA_ARGS__)
// #define _log_note2(...) log_note2(_log_doit2(__FUNCTION__, LOGLEVEL_NOTE), __VA_ARGS__)
#define USE_DARK_MAGIC
#if defined USE_DARK_MAGIC
#define log_fatal _log_fatal2
#define log_debug _log_debug2
#define log_note _log_note2
#else
#define log_fatal log_fatal1
#define log_debug log_debug1
#define log_note log_note1
#endif

#define SA struct sockaddr

#define PACKETFLAG_FIN 0b00000001
#define PACKETFLAG_SYN 0b00000010
#define PACKETFLAG_RST 0b00000100
#define PACKETFLAG_PSH 0b00001000
#define PACKETFLAG_ACK 0b00010000
#define PACKETFLAG_URG 0b00100000
#define PACKETFLAG_MASK 0xff

enum ATP_OPTION_TYPE {
    ATP_OPT_SOCKID = 0,
    ATP_OPT_MSS,
    ATP_OPT_SACK,
    ATP_OPT_SACKOPT,
    ATP_OPT_TIMESTAMP
};

struct PACKED_ATTRIBUTE ATPPacket : public CATPPacket {
    // apt packet layout, trivial

#define MAKE_FLAGS_GETTER_SETTER(fn, mn) void set_##fn(uint8_t v){ \
        if(v) flags |= mn; else flags &= (~mn); flags &= PACKETFLAG_MASK; } \
    uint8_t get_##fn() const{ return (flags & mn) == 0 ? 0 : 1;}

    MAKE_FLAGS_GETTER_SETTER(fin, PACKETFLAG_FIN);
    MAKE_FLAGS_GETTER_SETTER(syn, PACKETFLAG_SYN);
    MAKE_FLAGS_GETTER_SETTER(rst, PACKETFLAG_RST);
    MAKE_FLAGS_GETTER_SETTER(psh, PACKETFLAG_PSH);
    MAKE_FLAGS_GETTER_SETTER(ack, PACKETFLAG_ACK);
    MAKE_FLAGS_GETTER_SETTER(urg, PACKETFLAG_URG);

    template <typename ... Args>
    static uint16_t create_flags(Args&& ... args) {
        uint16_t f = ( ... | args) & PACKETFLAG_MASK;
        return f;
    }

    bool has(uint8_t f) const {
        return (flags & f) == 0 ? 0 : 1;
    }

    template <typename ... Args>
    static bool any(Args&& ... args) {
        std::array<uint16_t, sizeof...(Args)> value = { args... };
        for (const auto & s : value) {
            if (has(s)) {
                return true;
            }
        }
        return false;
    }
    template <typename ... Args>
    static bool all(Args&& ... args) {
        std::array<uint16_t, sizeof...(Args)> value = { args... };
        for (const auto & s : value) {
            if (!has(s)) {
                return false;
            }
        }
        return true;
    }

    uint32_t get_full_seq_nr(ATPSocket * socket) const;
};

static_assert(std::is_trivial<ATPPacket>::value, "ATPPacket is not trivial");
static_assert(std::is_pod<ATPPacket>::value, "ATPPacket is not pod");
static_assert(std::is_aggregate<ATPPacket>::value, "ATPPacket is not aggregate");
static_assert(sizeof(ATPPacket) == 10, "ATPPacket's size is not equal to 10");

extern const char * CONN_STATE_STRS [];

struct ATPAddrHandle {
    ATPAddrHandle() {
        std::memset(&sa, 0, sizeof sa);
    }
    ATPAddrHandle(const struct sockaddr * _sa) {
        sa = *(reinterpret_cast<const sockaddr_in *>(_sa));
    }
    ATPAddrHandle & operator=(const ATPAddrHandle & rhs) {
        if (this == &rhs) {
            return *this;
        }
        sa = rhs.sa;
        return *this;
    }
    ATPAddrHandle & operator=(const sockaddr_in & rhs) {
        sa = rhs;
        return *this;
    }
    inline bool operator==(const ATPAddrHandle & rhs) const {
        if (this == &rhs) {
            return true;
        }
        return (port() == rhs.port() && addr() == rhs.addr());
    }
    inline bool operator!=(const ATPAddrHandle & rhs) const {
        return !(*this == rhs);
    }
    inline void from_string(const char * _ipaddstr, int _port) {
        int n;
        if ((n = ::inet_pton(sa.sin_family, _ipaddstr, &(sa.sin_addr.s_addr))) < 0)
            err_sys("inet_pton error -1");
        else if (n == 0)
            err_sys("inet_pton error 0");
        set_port(_port);
    }
    inline const char * to_string() const {
        ::inet_ntop(sa.sin_family, &addr(), fmt, INET_ADDRSTRLEN);
        return const_cast<const char *>(fmt);
    }
    inline const char * hash_code() const {
        std::sprintf(fmt, "%s:%05u", to_string(), host_port());
        return const_cast<const char *>(fmt);
    }
    inline void set_port(in_port_t _port) {
        sa.sin_port = htons(_port);
    }
    inline void set_addr(in_addr_t _addr) {
        sa.sin_addr.s_addr = htonl(_addr);
    }
    inline in_port_t & port() {
        return sa.sin_port;
    }
    inline in_addr_t & addr() {
        return sa.sin_addr.s_addr;
    }
    inline const in_port_t & port() const {
        return sa.sin_port;
    }
    inline const in_addr_t & addr() const {
        return sa.sin_addr.s_addr;
    }
    inline uint16_t host_port() const {
        return ntohs(sa.sin_port);
    }
    inline uint32_t host_addr() const {
        return ntohl(sa.sin_addr.s_addr);
    }
    inline decltype(sockaddr_in::sin_family) & family() {
        return sa.sin_family;
    }
    inline size_t length() const {
        return sizeof sa;
    }
    struct sockaddr_in sa;
private:
    mutable char fmt[INET_ADDRSTRLEN];
};

struct PACKED_ATTRIBUTE TimeDelayOption {
    // Our local time when we receive a time delay probing packet from peer
    uint64_t receive_timestamp;
    // Our local time when we reply to peer our time delay infos
    uint64_t reply_timestamp;
};

struct OutgoingPacket {
    ~OutgoingPacket() {
        if (!observer)
            destroy();
    }

    // Don't directly call `new OutgoingPacket` to for a new OutgoingPacket. Because:
    // 1. In former/later version, some fields should be initialized with non-zero value.
    // 2. `OutgoingPacket` should be aggregate constructible.
    uint8_t observer: 1, marked: 1, selective_acked: 1, ahead_handled: 1, need_resend: 1;
    size_t length = 0; // length of the whole
    size_t payload = 0;
    size_t option_len = 0;
    uint64_t timestamp; // microseconds
    uint32_t transmissions = 0; // total number of transmissions
    uint32_t full_seq_nr;
    // IMPORTANT: `data` is allocated by malloc/free, not new/delete
    char * data; // = head + data

    void destroy() {
        // TODO now manually managing memory, swith to smart pointers later

#if defined (ATP_LOG_AT_DEBUG)
        if (data)
            fprintf(stderr, "Packet destructed with seq %u.\n", get_head()->seq_nr);
        else
            fprintf(stderr, "Packet destructed.\n");
#endif
        std::free(data);
        data = nullptr;
    }
    char * find_option(uint8_t opt_kind) {
        char * p = data + sizeof(ATPPacket);
        for (uint8_t i = 0; i < get_head()->opts_count; i++) {
            uint8_t k = *reinterpret_cast<uint8_t*>(p);
            uint8_t l = *reinterpret_cast<uint8_t*>(p + sizeof(uint8_t));
            if (k == opt_kind) {
                return p;
            }
            p += 2 * sizeof(uint8_t);
            p += l;
        }
        return nullptr;
    }

    size_t update_real_payload() {
        // This function is used to calculate a received packet.
        // For sent packet, `add_option` update `option_len` automatically.
        option_len = 0;
        char * p = data + sizeof(ATPPacket);
        for (uint8_t i = 0; i < get_head()->opts_count; i++) {
            uint8_t l = *reinterpret_cast<uint8_t*>(p + sizeof(uint8_t));
            option_len += 2 * sizeof(uint8_t);
            option_len += l;
            p += 2 * sizeof(uint8_t);
            p += l;
        }
        assert(payload >= option_len);
        return payload - option_len;
    }

    size_t real_payload() const {
        // payload without options
        return payload - option_len;
    }

    bool is_empty_ack() const {
        return !is_promised_packet();
    }

    bool is_promised_packet() const {
        // A promised packet will be resend if not got ACK from peer.
        // Only promised packet increases `seq_nr`.
        if (get_head()->get_syn() || get_head()->get_fin()) {
            // Notice that SYN/FIN are promised, though they have no user data
            return true;
        }
        if (payload == 0)
        {
            // An `payload` == 0 packet must be ACK packet, otherwise it should not be sent.
            assert(get_head()->get_ack());
            return false;
        } else if (get_head()->opts_count > 0 && real_payload() == 0) {
            // With option
            return false;
        }
        return true;
    }

    bool has_user_data() const {
        if (get_head()->get_syn() || get_head()->get_fin()) {
            return false;
        }
        if (payload == 0)
        {
            return false;
        } else if (get_head()->opts_count > 0 && real_payload() == 0)
        {
            return false;
        }
        return true;
    }
    ATPPacket * get_head() {
        return reinterpret_cast<ATPPacket *>(data);
    }
    const ATPPacket * get_head() const {
        return reinterpret_cast<ATPPacket *>(data);
    }

    static std::string get_flags_str(OutgoingPacket const * out_pkt);
};

template<class T, typename... Args>
inline decltype(void(T{std::declval<Args>()...}), std::true_type()) _is_braces_constructible_test(int);
template<class T, typename... Args>
inline std::false_type _is_braces_constructible_test(...);
template<class T, typename... Args>
struct is_braces_constructible : decltype(_is_braces_constructible_test<T, Args...>(0)) {};

static_assert(is_braces_constructible<OutgoingPacket,
              uint8_t, uint8_t, uint8_t, uint8_t, uint8_t,
              size_t, size_t, size_t,
              uint64_t,
              uint32_t, uint32_t,
              char *>::value,
              "OutgoingPacket is not trivially constructible");

struct ATPSocket {
    ATPContext * context = nullptr;
    // `sock_id` function as an extra "port", it helps when
    // 1. Migrate underlying layers.
    // 2. Fork a connection.
    // 3. Reduce 2MSL time.
    uint16_t sock_id;
    // peer sock id is set by ATP_OPT_SOCKID at connection establishing stage
    uint16_t peer_sock_id = 0;

    mutable ATPAddrHandle local_addr;
    inline ATPAddrHandle & get_local_addr() const {
        if (conn_state == CS_UNINITIALIZED)
        {
            return local_addr;
        } else {
            if (local_addr.host_port() == 0 && local_addr.host_addr() == 0)
            {
            }
            socklen_t my_sock_len = sizeof(local_addr.sa);
            getsockname(sockfd, reinterpret_cast<SA*> (&local_addr.sa), &my_sock_len);
            return local_addr;
        }
    }
    ATPAddrHandle dest_addr;
    int family; int type; int protocol;
    int sockfd;

    CONN_STATE_ENUM conn_state;

    // Used in outbuf
    struct _cmp_outgoingpacket_fullseq {
        bool operator()(OutgoingPacket * left, OutgoingPacket * right) {
            if (left->full_seq_nr == right->full_seq_nr)  return left > right;
            return left->full_seq_nr > right->full_seq_nr;
        }
    };
    // Used in inbuf
    struct _cmp_outgoingpacket {
        bool operator()(OutgoingPacket * left, OutgoingPacket * right) {
            if (left->get_head()->seq_nr == right->get_head()->seq_nr)  return left > right;
            return left->get_head()->seq_nr > right->get_head()->seq_nr;
        }
    };
    struct _cmp_outgoingpacket_marked {
        bool operator()(OutgoingPacket * left, OutgoingPacket * right) {
            if (left->marked == right->marked)  return left > right;
            // false | false | ... | true
            return left->marked == false ? true : false;
        }
    };
#define SWITCHTO_FULLSEQ(BUF) std::make_heap(BUF.begin(), BUF.end(), _cmp_outgoingpacket_fullseq());
#define SWITCHTO_MARKED(BUF) std::make_heap(BUF.begin(), BUF.end(), _cmp_outgoingpacket_marked());

#define _ATP_NEW_BUFFER
#if !defined(_ATP_NEW_BUFFER)
    std::vector<OutgoingPacket*> outbuf;
#define PUSH_OUTBUF(out_pkt) outbuf.push_back(out_pkt); std::push_heap(outbuf.begin(), outbuf.end(), _cmp_outgoingpacket_fullseq());
#define POP_OUTBUF() std::pop_heap(outbuf.begin(), outbuf.end(), _cmp_outgoingpacket_fullseq()); outbuf.pop_back();
#else
    TBuffer<OutgoingPacket> outbuf;
#define PUSH_OUTBUF(out_pkt) outbuf.put(out_pkt->full_seq_nr, out_pkt);
#define POP_OUTBUF() outbuf.pop_front();
#endif

    std::vector<OutgoingPacket*> inbuf;
    std::vector<OutgoingPacket*> inbuf_cache2;

    // My seq number
    uint32_t seq_nr = 0;
    // Peer's seq number acked by me
    uint32_t ack_nr = 0;
    bool overflow_lock = false;
    bool new_stage_hitted = false;
    static const uint32_t seq_nr_mask = 0xffff;
    // When peer's seq_nr wrap to 0, peer_seq_nr_base += std::numeric_limits<T>::max()
    uint32_t peer_seq_nr_base = 0;
    // My seq number acked by peer
    uint32_t my_seq_acked_by_peer = 0;

    // Re-send config
    uint32_t rtt = 0;
    uint32_t rtt_var = 800; // Default 800
    uint32_t rto = 2000; // Default 3000, recommend no less than timer event interval
    uint32_t ack_delayed_time = 200; // default 200, set 0 to disable delayed ACK

    // These are time point, don't modify
    uint64_t delay_ack_timeout = 0; // At this exact timepoint will this socket send delayed ACK, set 0 to cancel a due scheduled ACK
    uint64_t rto_timeout = 0; // At this exact timepoint(ms) will this socket timeout
    uint64_t death_timeout = 0; // At this exact timepoint change from TIME_WAIT to DESTROY
    uint64_t persist_timeout = 0; // At this exact timepoint will this socket send probing packet for peer's window

    // A global counter for transmissions may be worth used
    uint8_t transmission_counter = 0;
    uint8_t atp_retries1 = 3; // TCP RFC recommends 3
    uint8_t atp_retries2 = 8; // TCP RFC recommends 15
    uint8_t atp_syn_retries1 = 5;
    uint8_t atp_frr_retries = 0; // Trigger fast retransmit when frr_counter equals to atp_frr_retries
    uint8_t frr_counter = 0; // Fast retransmit counter, keep track of repeated ACK.
    uint16_t reorder_count = 0; // Reorder couter, keep track of reordered packets.

    // Window by Packets
    // NOTICE that type must be `int` rather than any unsigned
    static const int window_packets_unlimited = -1;
    // Set `cur_window_packets` and enable Nagle's stop-and-wait strategy
    // When set to `window_packets_unlimited` there is no limitation
    uint32_t cur_window_packets = window_packets_unlimited;
    // The number of packets in the send queue, including unsend and un-acked packets.
    // The oldest un-acked packet in the send queue is seq_nr - used_window_packets == my_seq_acked_by_peer
    uint32_t used_window_packets = 0;
    bool enable_cork = false;

    // Window by Bytes
    // This is byte-wise, set by peer
    static const size_t window_unlimited = -1;
    // By default = ATP_MAX_WRITE_BUFFER_SIZE
    size_t cur_window = window_packets_unlimited;
    // This is byte-wise, payload of in-flight packets + payload of needing to be re-sent packets
    size_t used_window = 0;
    // This is the maximum bytes of data per packet peer's buffer can handle
    size_t peer_window = window_packets_unlimited;
    // This is the maximum bytes of data per packet our buffer can handle, will be attached with our packets to peer
    size_t my_window = window_packets_unlimited;

    // MSS and MTU probing
    size_t current_mss = ATP_MSS_CEILING;


    // SACK
    // If `peer_max_sack_count != 0` then SACK is enabled by peer, they we can SACK peer's packets
    // `my_max_sack_count` will be sent to peer, with `ATP_OPT_SACKOPT` option to change peer's `peer_max_sack_count` field
#ifdef USE_OLD_SACK_FIELD
    // An old solution directly log sequence numbers of all packets need to be SACKed
    // `peer_max_sack_count` means how many sequence numbers should be attached
    uint8_t peer_max_sack_count = 0;
    uint8_t my_max_sack_count = 5;
#else
    // New solution use a byte array to represent all sent packets after index `ack_nr`,
    // An `1` at bit `i` means SACK the packet with `seq_nr == ack_nr + i + 1`.
    // Currently, it means how many bytes should be used to log SACK informations.
    uint8_t peer_max_sack_count = 0;
    uint8_t my_max_sack_count = 4;
#endif

    // Callbacks
    // typedef atp_result atp_callback_func(atp_callback_arguments *);
    std::function<atp_result(atp_callback_arguments *)> callbacks[ATP_CALLBACK_SIZE];

    // Options
    bool reuse_port_flag = false;
    bool on_listen_port = false;
    // When we reset a socket to listening port, we set re_listen = true
    bool re_listen = false;

    struct DelaySample {
        // All timepoints are updated if re-transmission occurs
        // T1: Originate Timestamp, timepoint when A send packet P1
        // T2: Receive Timestamp, timepoint when B received P1
        // T3: Transmit Timestamp, timepoint when B send ACK packet
        // T4: Destination Timestamp, timepoint when A receive B's ACK packet
        uint64_t t1;
        uint64_t t2;
        uint64_t t3;
        uint64_t t4;

        int64_t get_drift() const {
            return (int64_t(t2 - t1) + int64_t(t3 - t4)) / 2;
        }
        int64_t get_network_delay() const {
            return (int64_t(t2 - t1) + int64_t(t4 - t3)) / 2;
        }
    };

    uint64_t last_receive_timestamp = 0;
    uint64_t last_send_timestamp = 0;
    DelaySample make_delay_sample(TimeDelayOption time_delay) {
        return DelaySample{0, time_delay.receive_timestamp, time_delay.reply_timestamp, 0};
    }

    ~ATPSocket() {
#if defined (ATP_LOG_AT_DEBUG)
        log_debug(this, "Socket destructed.");
#endif
        clear();
    }
    ATPSocket(ATPContext * _context);
    // HELPERS
    void register_to_look_up(bool remove_listen);
    atp_callback_arguments make_atp_callback_arguments(ATP_CALLBACKTYPE_ENUM method, OutgoingPacket * out_pkt, const ATPAddrHandle & addr);
    OutgoingPacket * basic_send_packet(uint16_t flags);
    OutgoingPacket * construct_packet_from_buffer(const char * buffer, size_t len);

    // APIS
    void clear();
#ifdef _ATP_CLEAR_STATE_FUNC
    void clear_state();
#endif
    // Called by atp_create_socket, returns sockfd
    int init(int family, int type, int protocol);
    int init_fork(ATPSocket * origin);
    virtual ATPSocket * fork_me();
    ATPSocket * fork_basic();
    ATP_PROC_RESULT connect(const ATPAddrHandle & to_addr);
    ATP_PROC_RESULT listen(uint16_t host_port);
    ATP_PROC_RESULT bind(const ATPAddrHandle & to_addr);
    ATP_PROC_RESULT accept(const ATPAddrHandle & to_addr, OutgoingPacket * recv_pkt);
    ATP_PROC_RESULT receive(OutgoingPacket * recv_pkt, size_t real_payload_offset);
    // `send_packet_noguard` is function who actually sends packets
    ATP_PROC_RESULT send_packet_noguard(OutgoingPacket * out_pkt, bool adhoc = false);
    // `send_packet` will take over possession of `out_pkt`
    ATP_PROC_RESULT send_packet(OutgoingPacket * out_pkt, bool flush_packets = true, bool adhoc = false);
    // `check_unsend_packet` will send all packets which are allowed to be sent but haven't yet been sent.
    void check_unsend_packet();
    ATP_PROC_RESULT close();
    bool writable() const;
    bool readable() const;
    bool eof() const;
    void add_option(OutgoingPacket * out_pkt, uint8_t opt_kind, uint8_t opt_data_len, char * opt_data);
    void add_data(OutgoingPacket * out_pkt, const void * buf, const size_t len);
    size_t bytes_can_send_once() const;
    size_t bytes_can_send_one_packet(OutgoingPacket * particular_packet = nullptr) const;
    bool is_full(size_t with_extra = 0) const {
        // This function test whether a packet of `with_extra` bytes will reduce window to 0
        if (with_extra == 0) {
            return bytes_can_send_once() == 0 && used_window_packets > cur_window_packets;
        } else {
            return bytes_can_send_once() < with_extra && used_window_packets + 1 > cur_window_packets;
        }
    }
    // This function returns immediately after the packet is sent(whether succeed or fail)
    ATP_PROC_RESULT write(const void * buf, const size_t len);
    ATP_PROC_RESULT write_oob(const void * buf, const size_t len, uint32_t timeout);
    // This function returns only when got ack from peer
    // ATP_PROC_RESULT blocked_write(const void * buf, const size_t len);

    // Handles FIN
    ATP_PROC_RESULT check_fin(OutgoingPacket * recv_pkt);
    // Handles ACK, when a ack packet comes, update ack_nr
    ATP_PROC_RESULT update_myack(OutgoingPacket * recv_pkt);
    // Used in restricted situations, such as SYN
    ATP_PROC_RESULT handle_recv_packet_hard(OutgoingPacket * recv_pkt);
    ATP_PROC_RESULT handle_recv_packet(OutgoingPacket * recv_pkt, bool from_cache);
    size_t handle_opt(OutgoingPacket * recv_pkt);
    void init_connection(OutgoingPacket * recv_pkt, bool active);
    ATP_PROC_RESULT process(const ATPAddrHandle & addr, const char * buffer, size_t len);
    ATP_PROC_RESULT invoke_callback(int callback_type, atp_callback_arguments * args);
    // Update my_seq_acked_by_peer
    ATP_PROC_RESULT do_ack_packet(OutgoingPacket * recv_pkt);
    ATP_PROC_RESULT do_selective_ack_packet(char * peer_ack_nrs, uint8_t count);
    // TODO Following 2 functions are used to reuse packets with no user data to carry user data
    // Find the an empty packet with no payload or only option payload
    OutgoingPacket * find_no_data_packet();
    // Fill data in a packet, return how many bytes are inserted.
    // Write -> fill_packet -> add_data
    size_t fill_packet(OutgoingPacket * out_pkt, const char * buffer, size_t len);
    // S->R
    void compute_clock_skew();
    // R->S
    void compute_clock_skew(const TimeDelayOption & delay_option);
    // Get full sequence number according to **current** base
    uint32_t get_full_seq_nr(uint32_t raw_peer_seq_nr) {
        return raw_peer_seq_nr + peer_seq_nr_base;
    }
    // Guess which base
    uint32_t guess_full_seq_nr(uint32_t raw_peer_seq);
    uint32_t guess_full_ack_nr(uint32_t raw_peer_ack);
    // Update cur_window according to new `peer_window`
    void update_window(uint16_t new_peer_window);
    void update_rto(OutgoingPacket * recv_pkt);
    void schedule_ack();
    void destroy();
    void destroy_hard();
    virtual void switch_state(CONN_STATE_ENUM new_state);
    ATP_PROC_RESULT check_timeout();
    const char * hash_code() const {
        return ATPSocket::make_hash_code(sock_id, dest_addr);
    }
    const char * to_string() const {
        sprintf(hash_str, "[%05u](%s:%05u)->(%s:%05u) fd:%d", sock_id, this->get_local_addr().to_string(), this->get_local_addr().host_port()
                , dest_addr.to_string(), dest_addr.host_port(), sockfd);
        return const_cast<const char *>(hash_str);
    }
    static const char * make_hash_code(uint16_t sock_id, const ATPAddrHandle & dest_addr) {
        static char hash_str[INET_ADDRSTRLEN * 2 + 5 * 2 + 10 * 3];
        sprintf(hash_str, "[%05u]%s", sock_id, dest_addr.hash_code());
        return const_cast<const char *>(hash_str);
    }
private:
    // 2 * %s + 3 * %05u + 11 of symbols(such as [) + 20 of fd
    mutable char hash_str[INET_ADDRSTRLEN * 2 + 5 * 3 + 11 + 20];
};


struct ATPContext {
    void clear();
    void init();

    ATPContext() {
        init();
    }
    ~ATPContext() {
#if defined (ATP_LOG_AT_DEBUG)
        fprintf(stderr, "Context destroyed.\n");
#endif
        clear();
    }

    // Because we have peer_sock_id in ATPPacket,
    // we don't need to wait actually 2msl,
    // waiting for `rto` time is enough.
    // But you can still set a minimum TIME_WAIT.
    uint32_t min_msl2 = 6000;

    std::vector<ATPSocket *> sockets;
    // `look_up` marks every socket's dest_addr and sock_id,
    // so local socket can be located by an in-coming packet
    std::map<std::string, ATPSocket *> look_up;
    // All UDP ports this context owns, with a dominant ATPSocket
    std::map<uint16_t, ATPSocket *> listen_sockets;
    std::vector<ATPSocket *> destroyed_sockets;
    uint64_t start_ms;

    uint16_t new_sock_id();
    void destroy_socket(ATPSocket * socket);
    virtual ATP_PROC_RESULT daily_routine();
    ATPSocket * find_socket_by_fd(const ATPAddrHandle & handle_to, int sockfd);
    ATPSocket * find_socket_by_head(const ATPAddrHandle & handle_to, const ATPPacket * pkt);
    bool finished() const {
        return this->sockets.empty() && this->destroyed_sockets.empty();
    }

    virtual ATP_PROC_RESULT register_listen_port(ATPSocket * socket, uint16_t host_port) {
        if (listen_sockets.find(host_port) == listen_sockets.end())
        {
            listen_sockets[host_port] = socket;
            return ATP_PROC_OK;
        } else {
            return ATP_PROC_ERROR;
        }
    }

    virtual void deregister_listen_port(uint16_t host_port) {
        std::map<uint16_t, ATPSocket *>::iterator iter = listen_sockets.find(host_port);
        if (iter != listen_sockets.end()) {
#if defined (ATP_LOG_AT_DEBUG)
            log_debug(this, "Remove socket from listening.");
#endif
            listen_sockets.erase(iter);
        } else {
#if defined (ATP_LOG_AT_DEBUG)
            log_debug(this, "Remove socket from listening failed because we couldn't find.");
#endif
        }
    }

    void register_to_look_up(ATPSocket * socket) {
        // If socket's not registered, context can't find `ATPSocket *` by (addr:port)
        look_up[ATPSocket::make_hash_code(socket->sock_id, socket->dest_addr)] = socket;
    }
};


void print_out(ATPSocket * socket, OutgoingPacket * out_pkt, const char * method, FILE * stream = nullptr);
void init_callbacks(ATPSocket * socket);
std::string tabber(const std::string & src, bool tail_crlf = true);
