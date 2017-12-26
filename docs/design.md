# Re-send
ATP only resend the following packets:

1. Packets with SYN/FIN
2. Packets with user data

	In order to reduce network cost, a packet with no user data(even if it contains payload of option) will not be re-sent.

	Function `OutgoingPacket::is_promised_packet` can be used to judge whether this packet will be re-sent.

# Delayed ACK



# SACK