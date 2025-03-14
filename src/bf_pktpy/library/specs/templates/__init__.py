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

from bf_pktpy.library.specs.templates.ethernet import Ether as EtherTemplate
from bf_pktpy.library.specs.templates.ipv4 import IP as IPv4Template
from bf_pktpy.library.specs.templates.ipv6 import IPv6 as IPv6Template
from bf_pktpy.library.specs.templates.tcp import TCP as TCPTemplate
from bf_pktpy.library.specs.templates.udp import UDP as UDPTemplate
from bf_pktpy.library.specs.templates.icmp import ICMP as ICMPTemplate
from bf_pktpy.library.specs.templates.igmp import IGMP as IGMPTemplate
from bf_pktpy.library.specs.templates.icmpv6_unknown import (
    ICMPv6Unknown as ICMPv6Template,
)
from bf_pktpy.library.specs.templates.mpls import MPLS as MPLSTemplate
from bf_pktpy.library.specs.templates.gre import GRE as GRETemplate
from bf_pktpy.library.specs.templates.dot1q import Dot1Q as Dot1QTemplate
from bf_pktpy.library.specs.templates.arp import ARP as ARPTemplate
from bf_pktpy.library.specs.templates.bfd import BFD as BFDTemplate
from bf_pktpy.library.specs.templates.bootp import BOOTP as BOOTPTemplate
from bf_pktpy.library.specs.templates.dhcp import DHCP as DHCPTemplate
from bf_pktpy.library.specs.templates.erspan import ERSPAN as ERSPAN_Template
from bf_pktpy.library.specs.templates.erspan import ERSPAN_II as ERSPAN_IITemplate
from bf_pktpy.library.specs.templates.erspan import ERSPAN_III as ERSPAN_IIITemplate
from bf_pktpy.library.specs.templates.erspan import (
    ERSPAN_PlatformSpecific as ERSPAN_PlatformSpecificTemplate,
)
from bf_pktpy.library.specs.templates.vxlan import VXLAN as VXLANTemplate


def clone(protocol):
    """Clone to a new object"""
    class_name = protocol.__class__.__name__
    if class_name == "Ether":
        return EtherTemplate(**protocol.parameters)
    if class_name == "IP":
        return IPv4Template(**protocol.parameters)
    if class_name == "IPv6":
        return IPv6Template(**protocol.parameters)
    if class_name == "TCP":
        return TCPTemplate(**protocol.parameters)
    if class_name == "UDP":
        return UDPTemplate(**protocol.parameters)
    if class_name == "ICMP":
        return ICMPTemplate(**protocol.parameters)
    if class_name == "ICMPv6Unknown":
        return ICMPv6Template(**protocol.parameters)
    if class_name == "MPLS":
        return MPLSTemplate(**protocol.parameters)
    if class_name == "GRE":
        return GRETemplate(**protocol.parameters)
    if class_name == "Dot1Q":
        return Dot1QTemplate(**protocol.parameters)
    if class_name == "ARP":
        return ARPTemplate(**protocol.parameters)
    if class_name == "BFD":
        return BFDTemplate(**protocol.parameters)
    if class_name == "BOOTP":
        return BOOTPTemplate(**protocol.parameters)
    if class_name == "DHCP":
        return DHCPTemplate(**protocol.parameters)
    if class_name == "VXLAN":
        return VXLANTemplate(**protocol.parameters)
    if class_name == "ERSPAN":
        return ERSPAN_Template(**protocol.parameters)
    if class_name == "ERSPAN_II":
        return ERSPAN_IITemplate(**protocol.parameters)
    if class_name == "ERSPAN_III":
        return ERSPAN_IIITemplate(**protocol.parameters)
    if class_name == "PlatformSpecific":
        return ERSPAN_PlatformSpecificTemplate(**protocol.parameters)
    if class_name == "IGMP":
        return IGMPTemplate(**protocol.parameters)
