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
""" Ether template """
from bf_pktpy.library.helpers.ether_types import ETYPES
from bf_pktpy.library.specs.packet import Packet
from bf_pktpy.library.fields import SourceMACField, DestMACField, XShortEnumField


class Ether(Packet):
    """Ether class

    Definition:
        Ether
            src                     (str)
            dst                     (str)
            type                    (int)

        Examples:
            | + create
            |     ethernet = Ether(src=.., dst=.., type=..)
            | + make change
            |     ethernet.src = <value>
            |     ethernet.dst = <value>
            |     ethernet.type = <value>
    """

    name = "Ether"
    fields_desc = [
        DestMACField("dst"),
        SourceMACField("src"),
        XShortEnumField("type", 0x9000, ETYPES),
    ]

    @property
    def type_name(self):
        """Provides human-readable type of packet based on raw value.

        :return: human-readable type of packet
        :rtype: str
        """
        return ETYPES.get(hex(self.type)[2:].zfill(4))

    def _combine(self, body_copy):
        if body_copy.name == "Dot1AD":
            self._body = body_copy
            self.type = 0x88A8
            return self
        if body_copy.name == "Dot1Q":
            self._body = body_copy
            self.type = 0x8100
            return self
        if body_copy.name == "ARP":
            self._body = body_copy
            self.type = 0x0806
            return self
        if body_copy.name == "IP":
            self._body = body_copy
            self.type = 0x0800
            return self
        if body_copy.name == "IPv6":
            self._body = body_copy
            self.type = 0x86DD
            return self
        if body_copy.name == "MPLS":
            self._body = body_copy
            self.type = 0x8847
            return self
        if body_copy.name == "ERSPAN_III":
            self._body = body_copy
            if not body_copy.alternative:
                self._body.o = 0
            return self
        if body_copy.name == "FabricHeader":
            self._body = body_copy
            self.type = 0x9000
            return self
        if body_copy.name == "SimpleL3SwitchCpuHeader":
            self._body = body_copy
            self.type = 0xBF01
            return self
        if body_copy.name == "MACControlClassBasedFlowControl":
            self._body = body_copy
            self.type = 0x8808
            return self

        raise ValueError("Unsupported binding")

    @classmethod
    def from_hex(cls, hex_tr):
        """Create object from hex value"""
        if ETYPES.get(hex_tr[24:28]):
            dst = ":".join(hex_tr[i : i + 2] for i in range(0, 12, 2))
            src = ":".join(hex_tr[i : i + 2] for i in range(12, 24, 2))
            type_ = int(hex_tr[24:28], 16)
            return Ether(dst=dst, src=src, type=type_)
        return None
