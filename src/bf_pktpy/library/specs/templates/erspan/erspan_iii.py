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
""" ERSPAN_III template """
from bf_pktpy.library.specs.packet import Packet
from bf_pktpy.library.fields import BitField, XIntField, XShortField, BitEnumField

# =============================================================================


class ERSPAN_III(Packet):
    """
    ERSPAN_III class

        ERSPAN_III
            ver         (int)
            vlan        (int)
            cos         (int)
            bso         (int)
            t           (int)
            session_id  (int)
            timestamp   (int)
            sgt_other   (int)
            p           (int)
            ft          (int)
            hw          (int)
            d           (int)
            gra         (int)
            o           (int)

        Examples:
            | + create
            |     erspan_iii = ERSPAN_III(ver=.., vlan=.., ..)
            | + make change
            |     erspan_iii.ver = <value>
            |     erspan_iii.vlan = <value>
            |     ...
    """

    name = "ERSPAN_III"
    fields_desc = [
        BitField("ver", 2, 4),
        BitField("vlan", 0, 12),
        BitField("cos", 0, 3),
        BitField("bso", 0, 2),
        BitField("t", 0, 1),
        BitField("session_id", 0, 10),
        XIntField("timestamp", 0x00000000),
        XShortField("sgt_other", 0x00000000),
        BitField("p", 0, 1),
        BitEnumField("ft", 0, 5, {0: "Ethernet", 2: "IP"}),
        BitField("hw", 0, 6),
        BitField("d", 0, 1),
        BitEnumField("gra", 0, 2, {0: "100us", 1: "100ns", 2: "IEEE 1588"}),
        BitField("o", 0, 1),
    ]

    def _combine(self, body_copy):
        if body_copy.name == "Ether":
            self.o = 0
            self._body = body_copy
            return self
        if body_copy.name == "ERSPAN_PlatformSpecific":
            self.o = 1
            self._body = body_copy
            return self

        raise ValueError("Unsupported binding")


# =============================================================================
