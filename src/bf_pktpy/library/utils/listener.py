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
""" Listener module """
import binascii
import socket
import threading

try:
    import queue
except ImportError:
    # for Python 2 support
    import Queue as queue


# =============================================================================
def listen(socket, queue_, sig_, bufsize=1024):
    """Listen worker

    Args:
        socket           (obj): socket object
        queue_           (obj): queue to stored received pkts
        sig_             (obj): signal queue to stop thread
        bufsize          (int): buffer size
    Returns:
        str: received data
    Examples:
        | data = listen(<socket>, ...)
        |
    """

    while True:
        if sig_.qsize():
            signal = sig_.get()
            if signal == "quit":
                break
        data = socket.recv(bufsize)
        temp = str(binascii.hexlify(data))
        queue_.put(temp[2:-1])


class Listener:
    """Listener class

    Examples:
        |
    """

    _QUEUE = queue.Queue()
    _SIG = queue.Queue()

    def __init__(self, interface, **kwargs):
        """
        Args:
            interface        (obj): interface object
        Returns:
            stream: stream object
        Examples:
            | listener = Listener(**kwargs)
            |
        """
        self.interface = interface
        self.timeout = kwargs.pop("timeout", 0)
        self.inter = kwargs.pop("inter", 0)
        self.verbose = kwargs.pop("verbose", False)

    def start(self, count=1):
        """Start listening"""

        try:
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
        except socket.error:
            raise
        sock.bind((self.interface, 0))

        thread = threading.Thread(
            target=listen, args=(sock, Listener._QUEUE, Listener._SIG)
        )
        thread.start()

    @staticmethod
    def received():
        """Get received packets"""

        packets = []
        while Listener._QUEUE.qsize():
            packets.append(Listener._QUEUE.get())
        Listener._SIG.put("quit")
        return packets


# =============================================================================
