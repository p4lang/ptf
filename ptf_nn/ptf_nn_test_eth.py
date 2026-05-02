#!/usr/bin/env python

# Copyright 2013 Barefoot Networks, Inc.
# SPDX-License-Identifier: Apache-2.0

#
# Antonin Bas (antonin@barefootnetworks.com)
#
#

import argparse
import scapy.all as sc

parser = argparse.ArgumentParser(description="PTF Nanomsg tester 2")
parser.add_argument("--interface", type=str, dest="interface")
parser.add_argument("--receive", dest="receive", action="store_true", default=False)
args = parser.parse_args()


def receive(interface):
    def printp(p):
        print("Received:", p)

    sc.sniff(iface=interface, prn=lambda x: printp(x))


def main():
    if args.receive:
        receive(args.interface)
    else:  # send one
        p = "ab" * 20
        sc.sendp(p, iface=args.interface, verbose=0)


if __name__ == "__main__":
    main()
