#!/usr/bin/env python


# Copyright (c) 2022 Intel Corporation.
# SPDX-License-Identifier: Apache-2.0

###############################################################################
"""ModHeader template"""

from bf_pktpy.library.specs.packet import Packet
from bf_pktpy.library.fields import ByteField, ShortField, IntField


class ModHeader(Packet):
    name = "ModHeader"
    fields_desc = [
        IntField("switch_id", 0),
        ShortField("ingress_port", 0),
        ShortField("egress_port", 0),
        ByteField("queue_id", 0),
        ByteField("drop_reason", 0),
        ShortField("pad", 0),
    ]

    def _combine(self, body_copy):
        if body_copy.name == "Ether":
            self._body = body_copy
            return self

        raise ValueError("Unsupported binding")
