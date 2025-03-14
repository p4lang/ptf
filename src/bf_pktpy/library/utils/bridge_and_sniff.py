#!/usr/bin/env python


# Copyright (c) 2021 Intel Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

###############################################################################
""" BridgeSniff module """
import socket
import time
import threading
from bf_pktpy.library.utils.sniff import Sniffer, timer, listen


# =============================================================================
def generate_default_prn(peers, xfrms):
    """Generate default prn function"""

    def func(pkt):
        try:
            sock = peers[pkt.sniffed_on]
        except Exception:
            return

        proc = xfrms.get(pkt.sniffed_on)
        if not proc:
            return
        try:
            new_pkt = proc(pkt)
        except Exception:
            raise RuntimeError("Transforming pkt using %r failed" % proc.__name__)

        if new_pkt is True:
            # if True, will forward packet as is
            new_pkt = pkt
        elif new_pkt is False:
            # the packet is discarded
            return
        else:
            # forward modified packet ('else' here is for clarity)
            pass

        try:
            if new_pkt.proto in (6, 17):
                result = sock.sendto(new_pkt.pack(), (new_pkt.dst, new_pkt.body.dport))
            else:
                result = sock.sendto(new_pkt.pack(), (new_pkt.dst, 0))
            if result == 0:
                raise IOError("Cannot forward packet ..")
        except Exception:
            raise IOError("Unable to send successfully")

    return func


def generate_prn(prn, peers, xfrms):
    """Generate prn function"""

    def func(pkt):
        generate_default_prn(peers, xfrms)
        return prn(pkt)

    return func


class BridgeSniff(Sniffer):
    """BridgeSniff class
    Examples:
        |
    """

    @staticmethod
    def bind_socket(iface):
        """Bind interace to socket"""
        try:
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
        except socket.error:
            print("ERROR- Cannot create a socket")
            raise
        sock.bind((iface, 0))
        return sock

    def __init__(self, if1, if2, *args, **kwargs):
        # NOTE(sborkows): Sniffer is in old-class style
        Sniffer.__init__(self, *args, **kwargs)

        self.if1 = if1
        self.if2 = if2
        if not isinstance(if1, str):
            raise ValueError("Expect for interface name, but got %r" % if1)
        sock1 = BridgeSniff.bind_socket(if1)

        if not isinstance(if2, str):
            raise ValueError("Expect for interface name, but got %r" % if2)
        sock2 = BridgeSniff.bind_socket(if2)

        self.peers = {if1: sock2, if2: sock1}
        self.xfrms = {}
        xfrm12 = kwargs.pop("xfrm12", None)
        xfrm21 = kwargs.pop("xfrm21", None)
        if xfrm12:
            self.xfrms.update({if1: xfrm12})
        if xfrm21:
            self.xfrms.update({if1: xfrm21})

    def start(self):
        """Start sniffing"""
        while self._SIG:
            # clean up previous signal
            self._SIG.pop()

        count, filter_ = self.count, self.filter

        if self.prn is None:
            prn_send = generate_default_prn(self.peers, self.xfrms)
        else:
            prn_send = generate_prn(self.prn, self.peers, self.xfrms)

        # bind to first interface
        try:
            sock1 = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
        except socket.error:
            raise
        sock1.bind((self.if1, 0))
        thread1 = threading.Thread(
            target=listen,
            args=(sock1, self._QUEUE, self._SIG, count, prn_send, filter_),
        )
        thread1.start()

        # bind to second interface
        try:
            sock2 = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
        except socket.error:
            raise
        sock2.bind((self.if2, 0))
        thread2 = threading.Thread(
            target=listen,
            args=(sock2, self._QUEUE, self._SIG, count, prn_send, filter_),
        )
        thread2.start()

        # start timer if needed
        expire_time = 0
        if self.timeout > 0:
            expire_time = int(time.time()) + self.timeout
            if self._SIG and self._SIG[0] == "quit":
                return
            thread = threading.Thread(target=timer, args=(self._SIG, expire_time))
            thread.start()


# =============================================================================
