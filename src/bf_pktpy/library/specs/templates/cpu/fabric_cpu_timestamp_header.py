#!/usr/bin/env python


# Copyright (c) 2022 Intel Corporation.
# SPDX-License-Identifier: Apache-2.0

###############################################################################
"""FabricCpuTimestampHeader template"""

from bf_pktpy.library.specs.packet import Packet
from bf_pktpy.library.fields import ThreeBytesField


class FabricCpuTimestampHeader(Packet):
    name = "FabricCpuTimestampHeader"
    fields_desc = [
        ThreeBytesField("arrival_time_0", 0),
        ThreeBytesField("arrival_time_1", 0),
    ]

    def _combine(self, body_copy):
        if body_copy.name == "FabricPayloadHeader":
            self._body = body_copy
            return self

        raise ValueError("Unsupported binding")
