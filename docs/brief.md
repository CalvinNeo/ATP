# Design of ATP
Rather than TCP, which is a flow-oriented protocol, ATP is based on sending and acknowledging packets.

## ATPPacket

    IP Header
    UDP Header
    ATP Header
    Data

The ATP Header(10 bytes):
    
    0       7 8      15
    +........+........+
    +       seq       +
    +........+........+
    +       ack       +
    +........+........+
    +     sock_id     +
    +........+........+
    +      flags      +
    +........+........+
    +      window     +
    +........+........+

# Design of ATP Socket


# API usages

# Debug


