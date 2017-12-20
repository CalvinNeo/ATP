# ATP

ATP is a naive TCP implementation based on UDP

[![Build Status](https://travis-ci.org/CalvinNeo/ATP.svg?branch=master)](https://travis-ci.org/CalvinNeo/ATP)  [![Coverage Status](https://coveralls.io/repos/github/CalvinNeo/ATP/badge.svg?branch=master)](https://coveralls.io/github/CalvinNeo/ATP?branch=master)

# Usage
## Requirements
1. C++17 standard(e.g. g++7.2)

## Build
Make the project by command

    make lib

## APIs
All APIs are available in [/src/atp.h](/src/atp.h), and is compatible with C89


# Demo
There are several demos:

1. sender/receiver
The demo includes two separated programs: the sender and the receiver. A File will be sent from the sender to the receiver.
You can 
2. send/recv
This demo is similar to sender/receiver, send gets its input from stdin now.
3. send_poll
4. send_aio


    make demo

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

