# ATP
Rather than TCP, which is a flow-oriented protocol, ATP is based on sending and acknowledging packets.

# Layout of the ATP packet
An ATP packet can be wrapped within a UDP packet

    IP Header
    UDP Header
    ATP Header
    Payload(including ATP options and user data)

An ATP packet as a byte array can be re-interpreted as a POD struct `ATPPacket`. In ATP sockets, ATP packets are managed by class `OutgoingPacket` which takes ownship of an `ATPPacket` to provide a whole lifetime management.

## ATP header

The ATP Header(10 bytes):
    
    0       7 8       f
    +........+........+
    +       seq       +
    +........+........+
    +       ack       +
    +........+........+
    +     sock_id     +
    +........+........+
    +  opts  +  flags +
    +........+........+
    +      window     +
    +........+........+

The flags are

    0       7 8       f
    +........+........+
    +        +  UAPRSF+
    +  opts  +  RCSSYI+
    +        +  GKHTNN+
    +........+........+

## seq and ack
Both `seq` and `ack` are packet-indexed rather than bit-indexed(as TCP does).

## sock_id
ATP allows multiple connections established through one port. The `sock_id` field is used to distiguish ATP packets sent to the same port.

## flags

The `SYN`/`FIN` flags work similarly with TCP.

The `ACK` flag acknowledges sequence number of the last processed in-coming package(which may be buffered for a while) with **user data**. For example, if ATP processed a packet whose `real_payload() > 0` and `seq_nr == n`, then it will update `ack_nr` to `n` and create an packet with ACK number equal to **n**(not n + 1). However if the packet has `real_payload() == 0`, then `ack_nr` will not be updated and no ACK packet will be created, because actually reused `seq_nr` of the previous packet.

The `PSH` flag works differently from TCP's. Notice that all in-coming data in UDP are buffered and signaled one packet by one packet, so all packets are handled without deferring and packet splicing problems.

The `URG` flag works differently from TCP's. An `URG` flag marks an OOB packet which will be sent immediately and handled as soon as possible, regardless any of the window restrictions. `URG` packets share sequence number with normal packets. `URG` packets are promised to be acknowledged from peer within a given interval. Otherwise user will be notified by a callback.

The `RST` flags work similarly with TCP's.

## options

When opts is set not equal to 0, there are **opts** number of options at the beginning of payload. Notice that the option fields are part of payload, so use `real_payload()` instead of `payload` to check if there's user data.

An option has layout as following
    
    0       7 8       f
    +........+........+
    +  kind  + length +
    +........+........+
    +      data       +
    +........+........+


# Features of ATP
ref [/docs/features.md](/docs/features.md)

# The ATP socket
ref [/docs/socket.md](/docs/socket.md)

# API usages

# Debug
## Debug Macros
Enable detailed logging by opening the following macros: `ATP_LOG_AT_NOTE`, `ATP_LOG_UDP`
