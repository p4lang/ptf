#!/usr/bin/env python

# Copyright 2013 Barefoot Networks, Inc.
# SPDX-License-Identifier: Apache-2.0

#
# Antonin Bas (antonin@barefootnetworks.com)
#
#

import pynng
import struct
import argparse

parser = argparse.ArgumentParser(description="PTF Nanomsg tester 1")
parser.add_argument("--socket", type=str, dest="socket")
parser.add_argument("--receive", dest="receive", action="store_true", default=False)
args = parser.parse_args()

MSG_TYPE_PORT_ADD = 0
MSG_TYPE_PORT_REMOVE = 1
MSG_TYPE_PORT_SET_STATUS = 2
MSG_TYPE_PACKET_IN = 3
MSG_TYPE_PACKET_OUT = 4


def receive(socket):
    while True:
        msg = socket.recv()
        fmt = "<iii"
        msg_type, port_number, length = struct.unpack_from(fmt, msg)
        hdr_size = struct.calcsize(fmt)
        msg = msg[hdr_size:]
        assert msg_type == MSG_TYPE_PACKET_OUT
        assert len(msg) == length
        print("Received:", msg)


def main():
    socket = pynng.Pair0()
    socket.dial(args.socket)
    if args.receive:
        receive(socket)
    else:  # send one
        p = b"ab" * 20
        port = 1
        msg = struct.pack("<iii{}s".format(len(p)), MSG_TYPE_PACKET_IN, port, len(p), p)
        socket.send(msg)


if __name__ == "__main__":
    main()
