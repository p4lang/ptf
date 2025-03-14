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
""" Stream module """
import time

from bf_pktpy.library.utils.interface import Interface


# =============================================================================
class Stream:
    """Stream class

    Examples:
        | stream = Stream(packets, interface, layer)
    """

    def __init__(self, packets, interface):
        """
        Args:
            packets         (list): a list of packet objects
            interface        (obj): interface object
        Returns:
            stream: stream object
        Examples:
            | stream = Stream(packets, interface)
        """
        self.packets = packets
        self.interface = interface
        self.layer = 2
        intf = None
        for packet in self.packets:
            if intf is None:
                intf = Interface.get_interface(interface)
            # needed by bridge_and_sniff function
            packet.sniffed_on = intf
            if hasattr(packet, "name") and packet.name in ("IP", "IPv6"):
                # layer 3
                self.layer = 3
                packet.src = intf.address
                # check if TCP
                if hasattr(packet.body, "name") and packet.body.name == "TCP":
                    # if flags field is not provided, then set SYN bit on
                    tcp = packet.body
                    if tcp.flags == 0:
                        # set TCP SYN bit on like scapy
                        tcp.flags = 2
                # recalculate l4 checksum
                packet.update_l4_checksum()
            else:
                # layer 2
                if hasattr(packet.body, "name"):
                    body = packet.body
                    if body.name == "IP" or body.name == "IPv6":
                        # create layer2 if not existed
                        type_ = 0x0800
                        if packet.body.name == "IPv6":
                            type_ = 0x86DD
                        gateway = Interface.get_gateway(interface)
                        packet.src = intf.mac
                        packet.dst = gateway.mac
                        packet.type = type_
                    if not packet.body.src:
                        # fill src ip if not provided
                        packet.body.src = intf.address
                        # recalculate l4 checksum
                        packet.update_l4_checksum()

    def __repr__(self):
        string = ""
        for packet in self.packets:
            string = packet.__repr__() + "\n"
        return string.strip()

    def send(self, sock, **kwargs):
        """Send stream out of a socket

        Args:
            sock             (obj): socket object
            inter            (int): time in sec between 2 packets (def: 0)
            loop             (int): send packet indefinetly (default 0)
            count            (int): number of packets to send (default -1)
            verbose          (int): verbose mode
            realtime         (int): check pkt was sent before send next one
            return_packets  (bool): return the sent packets
        Returns:
            bool: true if success
        Examples:
            | result = self.send(sock)
        """
        inter = kwargs.pop("inter", 0)
        loop = kwargs.pop("loop", 0)
        count = kwargs.pop("count", -1)
        verbose = kwargs.pop("verbose", False)

        # Not implement realtime for now
        _ = kwargs.pop("realtime", None)

        result = None
        try:
            # 'count' takes precedence over 'loop'
            if count == -1:
                if loop:
                    count, loop = 1, 1
                else:
                    count, loop = 1, 0
            else:
                loop = 0
            while count > 0:
                if verbose:
                    print("Sending packet")
                if self.layer == 3:
                    for packet in self.packets:
                        if packet.proto in (6, 17):
                            result = sock.sendto(
                                packet.pack(), (packet.dst, packet.body.dport)
                            )
                        else:
                            result = sock.sendto(packet.pack(), (packet.dst, 0))
                        # returns the number of bytes sent
                        if result == 0:
                            raise IOError("Unable to send successfully")
                else:
                    # layer-2
                    for packet in self.packets:
                        result = sock.sendall(packet.pack())
                        # None is returned on success
                        if result is not None:
                            raise IOError("Unable to send successfully")
                time.sleep(inter)
                count = count + loop - 1
        except KeyboardInterrupt:
            print("KeyboardInterrupt")

        if kwargs.get("return_packets"):
            return result
        return None


# =============================================================================
