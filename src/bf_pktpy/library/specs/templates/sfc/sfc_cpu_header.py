#!/usr/bin/env python


# Copyright (c) 2022 Intel Corporation.
# SPDX-License-Identifier: Apache-2.0

###############################################################################

from bf_pktpy.library.specs.packet import Packet
from bf_pktpy.library.fields import BitField, ShortField


class SfcCPUHeader(Packet):
    name = "CPUHeader"
    fields_desc = [
        BitField("tx_bypass", 0, 1),
        BitField("capture_ts", 0, 1),
        BitField("reserved", 0, 1),
        BitField("egress_queue", 0, 5),
        ShortField("ingress_port", 0),
        ShortField("port_lag_index", 0),
        ShortField("ingress_bd", 0),
        ShortField("reason_code", 0),
        ShortField("ether_type", 0),
    ]
