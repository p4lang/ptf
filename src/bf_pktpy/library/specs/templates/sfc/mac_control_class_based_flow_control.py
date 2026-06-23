#!/usr/bin/env python


# Copyright (c) 2022 Intel Corporation.
# SPDX-License-Identifier: Apache-2.0

###############################################################################

from bf_pktpy.library.specs.packet import Packet
from bf_pktpy.library.fields import BitField, ByteField, ShortField


class MACControlClassBasedFlowControl(Packet):
    name = "MACControlClassBasedFlowControl"
    fields_desc = [
        ShortField("_op_code", 0x0101),
        ByteField("_reserved", 0),
        BitField("c7_enabled", 0, 1),
        BitField("c6_enabled", 0, 1),
        BitField("c5_enabled", 0, 1),
        BitField("c4_enabled", 0, 1),
        BitField("c3_enabled", 0, 1),
        BitField("c2_enabled", 0, 1),
        BitField("c1_enabled", 0, 1),
        BitField("c0_enabled", 0, 1),
        ShortField("c0_pause_time", 0),
        ShortField("c1_pause_time", 0),
        ShortField("c2_pause_time", 0),
        ShortField("c3_pause_time", 0),
        ShortField("c4_pause_time", 0),
        ShortField("c5_pause_time", 0),
        ShortField("c6_pause_time", 0),
        ShortField("c7_pause_time", 0),
    ]
