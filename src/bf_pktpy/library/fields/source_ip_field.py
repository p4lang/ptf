#!/usr/bin/env python


# Copyright (c) 2021 Intel Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

###############################################################################
""" SourceIPField """
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
