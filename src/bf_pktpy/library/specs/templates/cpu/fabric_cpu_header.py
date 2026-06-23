#!/usr/bin/env python


# Copyright (c) 2022 Intel Corporation.
# SPDX-License-Identifier: Apache-2.0

###############################################################################
"""FabricCpuHeader template"""

from bf_pktpy.library.specs.packet import Packet
from bf_pktpy.library.fields import BitField, ShortField


class FabricCpuHeader(Packet):
    name = "FabricCpuHeader"
    fields_desc = [
        BitField("tx_bypass", 0, 1),
        BitField("reserved1", 0, 2),
        BitField("egress_queue", 0, 5),
        ShortField("ingress_port", 0),
        ShortField("port_lag_index", 0),
        ShortField("ingress_bd", 0),
        ShortField("reason_code", 0),
    ]

    def _combine(self, body_copy):
        if body_copy.name in (
            "FabricCpuSflowHeader",
            "FabricCpuBfdEventHeader",
            "FabricCpuTimestampHeader",
            "FabricPayloadHeader",
        ):
            self._body = body_copy
            return self

        raise ValueError("Unsupported binding")
