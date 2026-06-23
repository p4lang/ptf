#!/usr/bin/env python


# Copyright (c) 2022 Intel Corporation.
# SPDX-License-Identifier: Apache-2.0

###############################################################################
"""ERSPAN_II template"""

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
