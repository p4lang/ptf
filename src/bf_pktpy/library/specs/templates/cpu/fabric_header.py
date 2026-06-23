#!/usr/bin/env python


# Copyright (c) 2022 Intel Corporation.
# SPDX-License-Identifier: Apache-2.0

###############################################################################
"""FabricHeader template"""

from bf_pktpy.library.specs.packet import Packet
from bf_pktpy.library.fields import BitField, ByteField


class FabricHeader(Packet):
    name = "FabricHeader"
    fields_desc = [
        BitField("packet_type", 0, 3),
        BitField("header_version", 0, 2),
        BitField("packet_version", 0, 2),
        BitField("pad1", 0, 1),
        BitField("fabric_color", 0, 3),
        BitField("fabric_qos", 0, 5),
        ByteField("dst_device", 0),
    ]

    def _combine(self, body_copy):
        if body_copy.name in (
            "FabricCpuHeader",
            "FabricUnicastHeader",
            "FabricMulticastHeader",
        ):
            self._body = body_copy
            return self

        raise ValueError("Unsupported binding")
