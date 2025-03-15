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

ETYPES = {
    "0800": "IPv4",
    "0806": "ARP",
    "8035": "RARP",
    "8100": "Dot1Q",
    "86dd": "IPv6",
    "8847": "MPLS Ucast",
    "8848": "MPLS Mcast",
    "88a8": "Dot1AD",
    "88CC": "LLDP",
    "8914": "FCoE",
    "9000": "FabricHeader",
    "9100": "Vlan Double tag",
    "BF01": "SimpleL3SwitchCpuHeader",
}
