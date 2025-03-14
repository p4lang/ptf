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
from bf_pktpy.library.fields import BitField, ShortField


class SfcCPUHeader(Packet):
    name = "CPUHeader"
    fields_desc = [
        BitField("tx_bypass", 0, 1),
        BitField("capture_ts", 0, 1),
        BitField("reserved", 0, 1),
        BitField("egress_queue", 0, 5),
        ShortField("ingress_port", 0),
        ShortField("port_lag_index", 0),
        ShortField("ingress_bd", 0),
        ShortField("reason_code", 0),
        ShortField("ether_type", 0),
    ]
