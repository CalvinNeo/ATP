# ATP

ATP is a message-oriented reliable transport protocol implementation.

[![Build Status](https://travis-ci.org/CalvinNeo/ATP.svg?branch=master)](https://travis-ci.org/CalvinNeo/ATP)  [![Coverage Status](https://coveralls.io/repos/github/CalvinNeo/ATP/badge.svg?branch=master)](https://coveralls.io/github/CalvinNeo/ATP?branch=master)

# Overview
1. ATP provides reliable transportation of data as well as a series of TCP's features.
2. ATP has a small sized head.
3. ATP allows time critical data transmission by urgent mechanism and clock drift probing.
4. ATP allows multiple connections established over the same port. 
5. ATP has a lightweight connecting/disconnecting mechanism. You can "fork" an established connection in ATP without extra 3-way handshake. You will endure shorter TIME\_WAIT stage than TCP.
6. ATP provides a framework as well as a service.

# Build
## Requirements
1. C++17 standard(e.g. g++7.2)

## Build
Make the project by command

    make lib

Run test on demos by command
    
    make run_test

## APIs
All APIs are available in [/src/atp.h](/src/atp.h), and is compatible with C89


# ATP as a framework(ASAF)
When ATP is used as a framework, it provides with a flexible underlying control. In this case, You must handle incoming UDP packets and maintain a timer outside the ATP framework. You must interact with the ATP context through two APIs:
1. `atp_process_udp`
    When there's an incoming UDP packet, you must inform ATP context to parse the raw UDP packet by calling `atp_process_udp`, the context will then dispatch the packets to correct ATP sockets. 
2. `atp_timer_event`
    You must also maintain a timer, and call `atp_timer_event` to generate timer signals for the context. 

ASAF is not thread safe.

## Demos
Most of these demos use healper `atp_standalone_` APIs provided in [/src/atp_standalone.h](/src/atp_standalone.h). These APIs help you from coding the connect/disconnect procedure yourself.

You can build all following tests by
    
    make demos

1. sendfile/recvfile

    The demo includes two separated programs: the sender and the receiver. A File will be sent from the sender to the receiver. In this demo, both sides set their UDP Socket to be nonblock, because there will be no multi-threading or multiplexing.
    You can set loss rate by modifying function `simulate_packet_loss_sendto` in [/src/atp_callback.cpp](/src/atp_callback.cpp).

    Build this demo by

        make test TARGET=demo_file

2. send/recv

    This demo is similar to sendfile/recvfile, instead of sending file, send/recv use stdin/stdout now. You can run with argument `-s` to simulate a ATPPacket by commands with certain format. This demo provides a convenient test method.
    Build this demo by

        make test TARGET=demo_cmd

3. send_poll

    This demo implements the sendfile's part with `poll`.

    Build this demo by

        make test TARGET=demo_poll

4. send_aio

    This demo implements the sendfile's part with aio.

    Build this demo by
    
        make test TARGET=send_aio

# ATP as a service
## Demos

# Docs
[/docs/brief.md](/docs/brief.md)

# License
The whole project is opened under GNU GENERAL PUBLIC LICENSE Version 2.

                        GNU GENERAL PUBLIC LICENSE
                           Version 2, June 1991

    Calvin Neo
    Copyright (C) 2017  Calvin Neo

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

