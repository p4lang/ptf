#!/usr/bin/env python


# Copyright (c) 2022 Intel Corporation.
# SPDX-License-Identifier: Apache-2.0

###############################################################################
"""MPLS template"""

from bf_pktpy.library.specs.packet import Packet
from bf_pktpy.library.fields import BitField, ByteField


class MPLS(Packet):
    name = "MPLS"
    fields_desc = [
        # lambda here to ensure, that label will change in bindings only if user didn't
        # provide his value.
        BitField("label", lambda _: 3, 20),
        BitField("cos", 0, 3),
        BitField("s", 1, 1),
        ByteField("ttl", 0),
    ]

    def _combine(self, body_copy):
        if body_copy.name == "MPLS":
            self._body = body_copy
            self.s = 0
            return self
        if body_copy.name == "Ether":
            self._body = body_copy
            return self
        if body_copy.name == "IP":
            self._body = body_copy
            if self.label is None:
                self.label = 0
            return self
        if body_copy.name == "IPv6":
            self._body = body_copy
            if self.label is None:
                self.label = 2
            return self

        raise ValueError("Unsupported binding")
