#!/usr/bin/env python


# Copyright (c) 2022 Intel Corporation.
# SPDX-License-Identifier: Apache-2.0

###############################################################################

from bf_pktpy.library.specs.packet import Packet
from bf_pktpy.library.fields import BitField, ByteField


class SfcFabricHeader(Packet):
    name = "FabricHeader"
    fields_desc = [
        ByteField("reserved", 0),
        BitField("color", 0, 3),
        BitField("qos", 0, 5),
        ByteField("reserved2", 0),
    ]
