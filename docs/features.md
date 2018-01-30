# Acknowledge
ATP uses the `ACK` flag to acknowledge packets with **user data** from peer.

## Delayed ACK


# Re-send
Use function `OutgoingPacket::is_promised_packet` to check whether a packet can be re-sent. Basicly, ATP only resend the following packets:

1. Packets with SYN/FIN flags

	SYN and FIN are important control message thus they should always been re-sent until acknowledged.

2. Packets with user data

	In order to reduce network cost, a packet with no user data(even if it contains payload of option) will not be re-sent.


## computing RTO

# SACK
When `my_max_sack_count` is set to non-zero, a `ATP_OPT_SACKOPT` option will be attached to the SYN packets at the connection establishing stage. When handling the `ATP_OPT_SACKOPT` option, `my_max_sack_count` will be updated. 

# Reuse address
Every ATP socket has a distinct sock\_id, multiple ATP sockets can read/write bi-directionally through the same UDP socket. Thus when a ATP Socket is destructed, it will not wait very short TIME\_WAIT time.

# Fast Retransmit

# Handle SEQ/ACK number overflowing situation

# Stop-and-Wait
Nagle's algorithm inhibit the sending of new TCP segments when new outgoing data arrives from the user if any previously transmitted data on the connection remains unacknowledged.
ATP use `ATPSocket::cur_window_packets` to control numbers of the in-flight packets which haven't been acknowledged. Nagle's algorithm is enabled when `cur_window_packets = 1`.

# Traffic control
a Sliding Window Protocol implementation is provided in ATP.