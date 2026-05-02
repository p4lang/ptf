#!/usr/bin/env python


# Copyright (c) 2021 Intel Corporation.
# SPDX-License-Identifier: Apache-2.0

###############################################################################
"""SourceIPField"""

from bf_pktpy.library.helpers.ip import get_src_ip_addr
from bf_pktpy.library.fields.ip_field import IPField


# noinspection PyPropertyAccess
class SourceIPField(IPField):
    def __init__(self, name, dst_field_name=None):
        super(SourceIPField, self).__init__(name, None)
        self.dst_field_name = dst_field_name

    def post_build(self, pkt):
        if pkt.src is not None:
            return
        dst_ip = (
            "0.0.0.0"
            if self.dst_field_name is None
            else getattr(pkt, self.dst_field_name) or "0.0.0.0"
        )
        try:
            src_ip = get_src_ip_addr(dst_ip)
        except RuntimeError as ex:
            print("WARNING: %s" % ex)
            src_ip = "127.0.0.1"
        setattr(pkt, self.name, src_ip)
