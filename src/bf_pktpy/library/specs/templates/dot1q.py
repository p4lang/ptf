#!/usr/bin/env python


# Copyright (c) 2022 Intel Corporation.
# SPDX-License-Identifier: Apache-2.0

###############################################################################
"""Dot1Q template"""

from bf_pktpy.library.fields import BitField, XShortEnumField
from bf_pktpy.library.helpers.ether_types import ETYPES
from bf_pktpy.library.specs.packet import Packet


class Dot1Q(Packet):
    """Dot1Q class
    Definition:
        Dot1Q
            type                      (int)
            prio                      (int)
            id                        (int)
            vlan                      (int)
        Examples:
            | + create
            |     dot1q = Dot1Q(type=.., prio=.., ...)
            | + make change
            |     dot1q.type = <value>
            |     dot1q.prio = <value>
            |     ...
    """

    name = "Dot1Q"
    fields_desc = [
        BitField("prio", 0, 3),
        BitField("id", 0, 1),
        BitField("vlan", 1, 12),
        XShortEnumField("type", 0, ETYPES),
    ]

    def _combine(self, body_copy):
        if body_copy.name == "Dot1Q":
            self._body = body_copy
            self.type = 0x8100
            return self
        if body_copy.name == "IP":
            self._body = body_copy
            self.type = 0x0800
            return self
        if body_copy.name == "IPv6":
            self._body = body_copy
            self.type = 0x86DD
            return self
        if body_copy.name == "ARP":
            self._body = body_copy
            self.type = 0x0806
            return self
        if body_copy.name == "MPLS":
            self._body = body_copy
            self._type = 0x8847
            return self
        if body_copy.name == "ERSPAN_III":
            self._body = body_copy
            self._body.o = 0
            return self
        if body_copy.name == "FabricHeader":
            self._body = body_copy
            self._type = 0x9000
            return self

        raise ValueError("Unsupported binding")
