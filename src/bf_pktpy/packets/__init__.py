# Copyright 2021 Intel Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

from bf_pktpy.library.specs.base import Base
from bf_pktpy.library.specs.packet import Packet

from bf_pktpy.library.specs.templates.ethernet import Ether
from bf_pktpy.library.specs.templates.arp import ARP
from bf_pktpy.library.specs.templates.bfd import BFD
from bf_pktpy.library.specs.templates.ipv4 import IP
from bf_pktpy.library.specs.templates.ipv6 import IPv6
from bf_pktpy.library.specs.templates.udp import UDP
from bf_pktpy.library.specs.templates.tcp import TCP
from bf_pktpy.library.specs.templates.dot1q import Dot1Q
from bf_pktpy.library.specs.templates.dot1ad import Dot1AD
from bf_pktpy.library.specs.templates.icmp import ICMP
from bf_pktpy.library.specs.templates.igmp import IGMP
from bf_pktpy.library.specs.templates.icmpv6_unknown import ICMPv6Unknown
from bf_pktpy.library.specs.templates.bootp import BOOTP
from bf_pktpy.library.specs.templates.dhcp import DHCP
from bf_pktpy.library.specs.templates.vxlan import VXLAN
from bf_pktpy.library.specs.templates.erspan import ERSPAN
from bf_pktpy.library.specs.templates.erspan import ERSPAN_II
from bf_pktpy.library.specs.templates.erspan import ERSPAN_III
from bf_pktpy.library.specs.templates.erspan import ERSPAN_PlatformSpecific
from bf_pktpy.library.specs.templates.gre import GRE
from bf_pktpy.library.specs.templates.cpu import *
from bf_pktpy.library.specs.templates.ipoption import *
from bf_pktpy.library.specs.templates.tcpoption import TCPOptionPlaceholder
from bf_pktpy.library.specs.templates.mpls import MPLS
from bf_pktpy.library.specs.templates.ipv6_ext_hdr_routing import IPv6ExtHdrRouting
from bf_pktpy.library.specs.templates.gtpu import GTPU
from bf_pktpy.library.specs.templates.raw import Raw
from bf_pktpy.library.specs.templates.cpu.simple_l3_mirror_cpu_header import (
    SimpleL3SwitchCpuHeader,
)
from bf_pktpy.library.specs.templates.sfc import *
from bf_pktpy.library.specs.templates.xnt import *
