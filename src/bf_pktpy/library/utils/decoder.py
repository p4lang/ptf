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
""" Decoder module """
from bf_pktpy.library.specs.templates.ethernet import Ether
from bf_pktpy.library.specs.templates.ipv4 import IP
from bf_pktpy.library.specs.templates.icmp import ICMP
from bf_pktpy.library.specs.templates.tcp import TCP
from bf_pktpy.library.specs.templates.udp import UDP


# =============================================================================
class Decoder:
    """Decoder class"""

    def __init__(self, hex_str):
        self.hex_str = hex_str
        self.decoded = None
        self._stack = ""
        self.layer3 = None
        self.layer4 = None
        if len(self.hex_str) > 28:
            self.decoded = Ether.from_hex(self.hex_str[:28])
            if self.decoded and isinstance(self.decoded, Ether):
                self._stack = "Ether"
                if self.decoded.type_name == "IPv4":
                    self._stack += " / IPv4"
                    self.layer3 = IP.from_hex(self.hex_str[28:])
                    self.decoded = self.decoded / self.layer3
                    offset = self.layer3.ihl * 4 * 2
                    if offset % 8:
                        offset += 8 - offset % 8  # add length of padding
                    payload = self.hex_str[28 + offset :]
                    if self.layer3.proto_name == "ICMP":
                        self._stack += " / ICMP"
                        self.layer4 = ICMP.from_hex(payload)
                        self.decoded = self.decoded / self.layer4
                    elif self.layer3.proto_name == "TCP":
                        self._stack += " / TCP"
                        self.layer4 = TCP.from_hex(payload)
                        self.decoded = self.decoded / self.layer4
                    elif self.layer3.proto_name == "UDP":
                        self._stack += " / UDP"
                        self.layer4 = UDP.from_hex(payload)
                        self.decoded = self.decoded / self.layer4
                    else:
                        # add more protocol as needed
                        pass

    def __call__(self):
        return self.decoded

    def hex(self):
        """To hex"""
        if self.decoded:
            return self.decoded.hex()
        return ""

    def bin(self):
        """To binary"""
        if self.decoded:
            return self.decoded.bin()
        return ""

    def is_protocol(self, protocol):
        """Check if hex string is ethernet type"""
        if protocol.lower() in self._stack.lower():
            return True
        return False

    def brief(self):
        """Short description of the packet"""
        descr = self._stack[8:] + " "
        if "IPv4" in self._stack or "IPv6" in self._stack:
            descr += "%s > %s" % (self.layer3.src, self.layer3.dst)
        return descr


# =============================================================================
