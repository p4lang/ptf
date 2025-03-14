#!/usr/bin/env python


# Copyright (c) 2022 Intel Corporation.
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
""" FabricPayloadHeader template """
from bf_pktpy.library.specs.packet import Packet
from bf_pktpy.library.fields import ShortField


class FabricPayloadHeader(Packet):
    name = "FabricPayloadHeader"
    fields_desc = [ShortField("ether_type", 0)]

    def _combine(self, body_copy):
        if body_copy.name == "DotAD":
            self._body = body_copy
            self.ether_type = 0x88A8
            return self
        if body_copy.name == "Dot1Q":
            self._body = body_copy
            self.ether_type = 0x8100
            return self
        if body_copy.name == "ARP":
            self._body = body_copy
            self.ether_type = 0x0806
            return self
        if body_copy.name == "IP":
            self._body = body_copy
            self.ether_type = 0x0800
            return self
        if body_copy.name == "IPv6":
            self._body = body_copy
            self.ether_type = 0x86DD
            return self
        if body_copy.name == "MPLS":
            self._body = body_copy
            self.ether_type = 0x8847
            return self
        if body_copy.name == "ERSPAN_III":
            self._body = body_copy
            self._body.o = 0
            return self

        raise ValueError("Unsupported binding")
