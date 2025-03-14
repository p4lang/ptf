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
""" ERSPAN_II template """
from bf_pktpy.library.specs.packet import Packet
from bf_pktpy.library.fields import BitField

# =============================================================================


class ERSPAN_II(Packet):
    """
    ERSPAN_II class

        ERSPAN_II
            ver         (int)
            vlan        (int)
            cos         (int)
            en          (int)
            t           (int)
            session_id  (int)
            reserved    (int)
            index       (int)

        Examples:
            | + create
            |     erspan_ii = ERSPAN_II(ver=.., vlan=.., ..)
            | + make change
            |     erspan_ii.ver = <value>
            |     erspan_ii.vlan = <value>
            |     ...
    """

    name = "ERSPAN_II"
    fields_desc = [
        BitField("ver", 1, 4),
        BitField("vlan", 0, 12),
        BitField("cos", 0, 3),
        BitField("en", 0, 2),
        BitField("t", 0, 1),
        BitField("session_id", 0, 10),
        BitField("reserved", 0, 12),
        BitField("index", 0, 20),
    ]

    def _combine(self, body_copy):
        if body_copy.name == "Ether":
            self._body = body_copy
            return self

        raise ValueError("Unsupported binding")


# =============================================================================
