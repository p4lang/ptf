#!/usr/bin/env python


# Copyright (c) 2022 Intel Corporation.
# SPDX-License-Identifier: Apache-2.0

###############################################################################
"""FabricCpuBfdEventHeader template"""

from bf_pktpy.library.specs.packet import Packet
from bf_pktpy.library.fields import ShortField


class FabricCpuBfdEventHeader(Packet):
    name = "FabricCpuBfdEventHeader"
    fields_desc = [ShortField("bfd_sid", 0), ShortField("bfd_event", 0)]

    def _combine(self, body_copy):
        if body_copy.name in ("FabricCpuTimestampHeader", "FabricPayloadHeader"):
            self._body = body_copy
            return self

        raise ValueError("Unsupported binding")
