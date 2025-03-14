#!/usr/bin/env python


# Copyright (c) 2022 Intel Corporation.
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
""" GRE template """
from bf_pktpy.library.helpers.bin import to_bin
from bf_pktpy.library.helpers.chksum import checksum
from bf_pktpy.library.helpers.ether_types import ETYPES
from bf_pktpy.library.specs.packet import Packet
from bf_pktpy.library.fields import (
    BitField,
    ConditionalField,
    XShortField,
    XIntField,
    XShortEnumField,
)


def gre_checksum(packet):
    """Calculate GRE checksum"""
    # noinspection PyProtectedMember
    members = packet._members(chksum=0)
    binary = ""
    for _, value, size in members[packet.name]:
        binary += to_bin(value, size)
    if len(binary) % 16 > 0:
        binary += "00000000"
    return checksum(binary)


class GRE(Packet):
    name = "GRE"
    fields_desc = [
        BitField("chksum_present", 0, 1),
        BitField("routing_present", 0, 1),
        BitField("key_present", 0, 1),
        BitField("seqnum_present", 0, 1),
        BitField("strict_route_source", 0, 1),
        BitField("recursion_control", 0, 3),
        BitField("flags", 0, 5),
        BitField("version", 0, 3),
        XShortEnumField("proto", 0x0000, ETYPES),
        ConditionalField(
            XShortField("chksum", gre_checksum),
            lambda pkt: pkt.chksum_present == 1 or pkt.routing_present == 1,
        ),
        ConditionalField(
            XShortField("offset", 0),
            lambda pkt: pkt.chksum_present == 1 or pkt.routing_present == 1,
        ),
        ConditionalField(XIntField("key", 0), lambda pkt: pkt.key_present == 1),
        ConditionalField(
            XIntField("sequence_number", 0), lambda pkt: pkt.seqnum_present == 1
        ),
    ]

    def _combine(self, body_copy):
        if body_copy.name == "Ether":
            self.proto = 0x6558
            self._body = body_copy
            return self
        if body_copy.name == "Dot1AD":
            self.proto = 0x88A8
            self._body = body_copy
            return self
        if body_copy.name == "Dot1Q":
            self.proto = 0x8100
            self._body = body_copy
            return self
        if body_copy.name == "IPv6":
            self.proto = 0x86DD
            self._body = body_copy
            return self
        if body_copy.name == "IP":
            self.proto = 0x0800
            self._body = body_copy
            return self
        if body_copy.name == "MPLS":
            self.proto = 0x8847
            self._body = body_copy
            return self
        if body_copy.name == "ERSPAN":
            self.proto = 0x88BE
            self._body = body_copy
            return self
        if body_copy.name in ("ERSPAN", "ERSPAN_II"):
            self.proto = 0x88BE
            self._body = body_copy
            self.seqnum_present = 1
            return self
        if body_copy.name == "ERSPAN_III":
            self.proto = 0x22EB
            self._body = body_copy
            return self

        raise ValueError("Unsupported binding")

    @property
    def type_name(self):
        """Provides human-readable 'proto' value of the subsequent header.

        :return: human-readable type of packet
        :rtype: str
        """
        return ETYPES.get(hex(self.proto)[2:].zfill(4))
