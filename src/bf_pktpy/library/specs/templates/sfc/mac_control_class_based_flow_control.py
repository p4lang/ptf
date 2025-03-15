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

from bf_pktpy.library.specs.packet import Packet
from bf_pktpy.library.fields import BitField, ByteField, ShortField


class MACControlClassBasedFlowControl(Packet):
    name = "MACControlClassBasedFlowControl"
    fields_desc = [
        ShortField("_op_code", 0x0101),
        ByteField("_reserved", 0),
        BitField("c7_enabled", 0, 1),
        BitField("c6_enabled", 0, 1),
        BitField("c5_enabled", 0, 1),
        BitField("c4_enabled", 0, 1),
        BitField("c3_enabled", 0, 1),
        BitField("c2_enabled", 0, 1),
        BitField("c1_enabled", 0, 1),
        BitField("c0_enabled", 0, 1),
        ShortField("c0_pause_time", 0),
        ShortField("c1_pause_time", 0),
        ShortField("c2_pause_time", 0),
        ShortField("c3_pause_time", 0),
        ShortField("c4_pause_time", 0),
        ShortField("c5_pause_time", 0),
        ShortField("c6_pause_time", 0),
        ShortField("c7_pause_time", 0),
    ]
