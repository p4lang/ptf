#!/usr/bin/env python


# Copyright (c) 2022 Intel Corporation.
# SPDX-License-Identifier: Apache-2.0

###############################################################################
"""FabricCpuSflowHeader template"""

from bf_pktpy.library.specs.packet import Packet
from bf_pktpy.library.fields import ShortField


class FabricCpuSflowHeader(Packet):
    name = "FabricCpuSflowHeader"
    fields_desc = [ShortField("sflow_sid", 0)]

    def _combine(self, body_copy):
        if body_copy.name in (
            "FabricCpuBfdEventHeader",
            "FabricCpuTimestampHeader",
            "FabricPayloadHeader",
        ):
            self._body = body_copy
            return self

        raise ValueError("Unsupported binding")
