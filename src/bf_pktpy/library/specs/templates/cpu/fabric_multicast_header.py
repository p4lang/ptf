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
""" FabricMulticastHeader template """
from bf_pktpy.library.specs.packet import Packet
from bf_pktpy.library.fields import BitField, ShortField


class FabricMulticastHeader(Packet):
    name = "FabricMulticastHeader"
    fields_desc = [
        BitField("routed", 0, 1),
        BitField("outerRouted", 0, 1),
        BitField("tunnelTerminate", 0, 1),
        BitField("ingressTunnelType", 0, 5),
        ShortField("ingressIfindex", 0),
        ShortField("ingressBd", 0),
        ShortField("mcastGrpA", 0),
        ShortField("mcastGrpB", 0),
        ShortField("ingressRid", 0),
        ShortField("l1ExclusionId", 0),
    ]

    def _combine(self, body_copy):
        if body_copy.name == "FabricPayloadHeader":
            self._body = body_copy
            return self

        raise ValueError("Unsupported binding")
