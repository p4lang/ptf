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
""" MPLS template """
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
