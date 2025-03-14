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
""" DtelReportHdr template """
from bf_pktpy.library.specs.packet import Packet
from bf_pktpy.library.fields import BitField, IntField


class DtelReportHdr(Packet):
    name = "DtelReportHdr"
    fields_desc = [
        BitField("ver", 0, 4),
        BitField("next_proto", 0, 4),
        BitField("dropped", 0, 1),
        BitField("congested_queue", 0, 1),
        BitField("path_tracking_flow", 0, 1),
        BitField("reserved", 0, 15),
        BitField("hw_id", 0, 6),
        IntField("sequence_number", 0),
        IntField("timestamp", 0),
    ]

    def _combine(self, body_copy):
        if body_copy.name == "Ether":
            self._body = body_copy
            self.next_proto = 0
            return self
        if body_copy.name == "ModHeader":
            self._body = body_copy
            self.next_proto = 1
            return self
        if body_copy.name == "PostcardHeader":
            self._body = body_copy
            self.next_proto = 2
            return self

        raise ValueError("Unsupported binding")
