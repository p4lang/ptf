#!/usr/bin/env python


# Copyright (c) 2022 Intel Corporation.
# SPDX-License-Identifier: Apache-2.0

###############################################################################
"""FabricUnicastHeader template"""

from bf_pktpy.library.specs.packet import Packet
from bf_pktpy.library.fields import BitField, ShortField


class FabricUnicastHeader(Packet):
    name = "FabricUnicastHeader"
    fields_desc = [
        BitField("routed", 0, 1),
        BitField("outerRouted", 0, 1),
        BitField("tunnelTerminate", 0, 1),
        BitField("ingressTunnelType", 0, 5),
        ShortField("nexthopIndex", 0),
    ]

    def _combine(self, body_copy):
        if body_copy.name == "FabricPayloadHeader":
            self._body = body_copy
            return self

        raise ValueError("Unsupported binding")
