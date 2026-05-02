#!/usr/bin/env python

# Copyright 2013 Barefoot Networks, Inc.
# SPDX-License-Identifier: Apache-2.0

#
# Antonin Bas (antonin@barefootnetworks.com)
#
#

import argparse
import threading
import scapy.all as sc
import time

parser = argparse.ArgumentParser(description="PTF Nanomsg tester bridge")
parser.add_argument("-ifrom", type=str)
parser.add_argument("-ito", type=str)
args = parser.parse_args()

forwarders = {}


class Forwarder(threading.Thread):
    def __init__(self, iface_name, other):
        threading.Thread.__init__(self)
        self.daemon = True
        self.iface_name = iface_name
        self.other = other
        forwarders[iface_name] = self

    def forward(self, p):
        print("forwarding", p, "---", self.other, "->", self.iface_name)
        sc.sendp(p, iface=self.iface_name, verbose=0)

    def run(self):
        other_fwd = forwarders[self.other]
        sc.sniff(iface=self.iface_name, prn=lambda x: other_fwd.forward(x))


def main():
    f1 = Forwarder(args.ifrom, args.ito)
    f2 = Forwarder(args.ito, args.ifrom)
    time.sleep(2)
    f1.start()
    print("READY")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        return


if __name__ == "__main__":
    main()
