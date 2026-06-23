#!/usr/bin/env python


# Copyright (c) 2022 Intel Corporation.
# SPDX-License-Identifier: Apache-2.0

###############################################################################
"""PostcardHeader template"""

from bf_pktpy.library.specs.packet import Packet
from bf_pktpy.library.fields import ByteField, ShortField, ThreeBytesField, IntField


class PostcardHeader(Packet):
    name = "PostcardHeader"
    fields_desc = [
        IntField("switch_id", 0),
        ShortField("ingress_port", 0),
        ShortField("egress_port", 0),
        ByteField("queue_id", 0),
        ThreeBytesField("queue_depth", 0),
        IntField("egress_tstamp", 0),
    ]

    def _combine(self, body_copy):
        if body_copy.name == "Ether":
            self._body = body_copy
            return self

        raise ValueError("Unsupported binding")
