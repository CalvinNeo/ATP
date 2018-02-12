# struct ATPContext

# struct ATPSocket

## Locate socket
When an ATP packet is arrived, it should be delivered to it endpoint ATP socket. The endpoint ATP socket will be located by `dest_addr` and `sock_id`, which are peer's address(obtained from upper layer protocol such as UDP) and our local `sock_id`(obtained directly from the ATP packet).

## Destroy socket
An invalid packet from a destroyed socket can be delivered to its destination port, due to reasons such as packets cached by routers, or a immediate re-connection afther shutdown with the same Sequence number. However, because there's very low possibility that a socket is created immediately with the same `sock_id` at the same port, so even a packet is sent to the corresponding port, it's basiclly impossible the packet be dilivered successfully to a valid socket. In light of this, the `TIME_WAIT` stage of ATP can be much shorter than 2MSL, and is now relevant with RTO and max retries.