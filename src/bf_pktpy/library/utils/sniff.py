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
""" Sniffer module """
import binascii
from six.moves import queue
import socket
import threading
import time
import types

from bf_pktpy.library.utils import Decoder


# =============================================================================
class Received(list):
    """Received class
    Examples:
        |
    """

    def __iter__(self):
        for each in self[:]:
            yield each

    def is_empty(self):
        """Check if container is empty or not"""
        return False if self[:] else True

    def summary(self):
        """get summary"""
        for pkt in self:
            print("%s" % pkt.brief())


def listen(socket, queue_, sig_, count, prn, filter_="ip", bufsize=1024):
    """Listen worker
    Args:
        socket           (obj): socket object
        queue_           (obj): queue to stored received pkts
        sig_             (obj): signal queue to stop thread
        count            (int): number of packets to capture, 0: infinity
        prn              (obj): function to apply to each packet
        filter_          (str): protocol name to look for
        bufsize          (int): buffer size
    Returns:
        None
    Examples:
        | listen(<socket>, ..)
        |
    """

    while True:
        if sig_ and sig_[0] == "quit":
            return
        data = socket.recv(bufsize)
        raw = str(binascii.hexlify(data))
        decoded = Decoder(raw[2:-1])
        if decoded.is_protocol(filter_):
            if isinstance(prn, types.FunctionType):
                prn(decoded)
            queue_.put(decoded)
            if count > 0 and count == queue_.qsize():
                sig_.append("quit")


def timer(sig_, expire_time):
    """Send quit signal when time is expired
    Args:
        expire_time      (int): stop at given time, 0: no expire
    """

    while True:
        if sig_ and sig_[0] == "quit":
            return
        if expire_time <= int(time.time()):
            sig_.append("quit")
        time.sleep(1)


class Sniffer:
    """Sniffer class
    Examples:
        |

    Note: this class is a parent of BridgeSniff. Change here can affect
          the behavior of derived class
    """

    def __init__(self, *args, **kwargs):
        self._QUEUE = queue.Queue()
        self._SIG = []
        self.filter = kwargs.pop("filter", "ip")  # BPF filter to apply
        iface = kwargs.pop("iface", [])  # 1 or more interfaces
        if iface and isinstance(iface, str):
            iface = [iface]
        if not isinstance(iface, (list, tuple, dict)):
            raise ValueError("Unsupported type for iface %r" % type(iface))
        self.interfaces = iface

        # function applied to each pkt
        self.prn = kwargs.pop("prn", None)
        self.count = kwargs.pop("count", 0)  # 0 means infinity
        self.timeout = kwargs.pop("timeout", 0)  # expire time
        self.store = kwargs.pop("store", True)  # store or discard pkts

    def start(self):
        """Start sniffing"""
        while self._SIG:
            # clean up previous signal
            self._SIG.pop()

        count, prn, filter_ = self.count, self.prn, self.filter
        # bind to one or more interfaces
        for iface in self.interfaces:
            try:
                sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
            except socket.error:
                raise
            sock.bind((iface, 0))
            thread = threading.Thread(
                target=listen, args=(sock, self._QUEUE, self._SIG, count, prn, filter_)
            )
            thread.start()

        # start timer if needed
        expire_time = 0
        if self.timeout > 0:
            expire_time = int(time.time()) + self.timeout
            if self._SIG and self._SIG[0] == "quit":
                return
            thread = threading.Thread(target=timer, args=(self._SIG, expire_time))
            thread.start()

    def is_completed(self):
        """Check if sniff packets is done"""
        if self._SIG and self._SIG[0] == "quit":
            return True
        return False

    def stop(self):
        """Stop sniffing"""
        self._SIG.append("quit")

    def received(self):
        """Get received packets"""
        packets = []
        while self._QUEUE.qsize():
            packets.append(self._QUEUE.get())
        self._SIG.append("quit")
        return packets


# =============================================================================
