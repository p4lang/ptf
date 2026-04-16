#!/usr/bin/env python


# Copyright (c) 2022 Intel Corporation.
# SPDX-License-Identifier: Apache-2.0

###############################################################################

from bf_pktpy.library.specs.packet import Packet
from bf_pktpy.library.fields import BitField, ByteField, ShortField


class SfcPause(Packet):
    name = "SfcPause"
    fields_desc = [
        ByteField("version", 0),
        ByteField("dscp", 0),
        ShortField("duration_us", 0),
        BitField("pad_0", 0, 112),
    ]
