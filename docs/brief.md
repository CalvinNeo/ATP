# Design of ATP
Rather than TCP, which is a flow-oriented protocol, ATP is based on sending and acknowledging packets.

## ATPPacket

    IP Header
    UDP Header
    ATP Header
    Payload

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
    
When opts is set not equal to 0, there are **opts** number of options at the beginning of payload.

The option fields are part of payload:
    
    0       7 8       f
    +........+........+
    +  kind  + length +
    +........+........+
    +      data       +
    +........+........+


# Design
ref [/docs/design.md](/docs/design.md)

# API usages

# Debug


