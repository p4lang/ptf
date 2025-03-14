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
""" FabricCpuHeader template """
from bf_pktpy.library.specs.packet import Packet
from bf_pktpy.library.fields import BitField, ShortField


class FabricCpuHeader(Packet):
    name = "FabricCpuHeader"
    fields_desc = [
        BitField("tx_bypass", 0, 1),
        BitField("reserved1", 0, 2),
        BitField("egress_queue", 0, 5),
        ShortField("ingress_port", 0),
        ShortField("port_lag_index", 0),
        ShortField("ingress_bd", 0),
        ShortField("reason_code", 0),
    ]

    def _combine(self, body_copy):
        if body_copy.name in (
            "FabricCpuSflowHeader",
            "FabricCpuBfdEventHeader",
            "FabricCpuTimestampHeader",
            "FabricPayloadHeader",
        ):
            self._body = body_copy
            return self

        raise ValueError("Unsupported binding")
