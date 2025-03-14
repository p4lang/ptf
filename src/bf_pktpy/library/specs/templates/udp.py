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
""" UDP template """
from bf_pktpy.library.helpers.bin import to_bin
from bf_pktpy.library.helpers.chksum import checksum
from bf_pktpy.library.specs.packet import Packet
from bf_pktpy.library.fields import ShortField, XShortField


def total_len(packet):
    return packet.total_len


def udp_checksum(packet):
    """Calculate UDP checksum"""

    def members_lookup(members, field_name):
        return next((val, size) for name, val, size in members if name == field_name)

    binary = ""
    ip_layer = packet.underlayer
    if ip_layer is not None and ip_layer.name in ("IP", "IPv6"):
        # noinspection PyProtectedMember
        ip_members = list(ip_layer._members().values())[0]
        src_ip = to_bin(*members_lookup(ip_members, "src"))
        dst_ip = to_bin(*members_lookup(ip_members, "dst"))
        proto_field = "proto" if ip_layer.name == "IP" else "nh"
        l4_proto = to_bin(*members_lookup(ip_members, proto_field))
        ttlen = ip_layer.total_len
        temp = ttlen - ip_layer.hdr_len
        l4_len = to_bin(temp, 16)
        resved = "00000000"
        binary += (
            src_ip + dst_ip + l4_len + resved + l4_proto + packet["UDP"].bin(chksum=0)
        )
        if len(binary) % 16 > 0:
            binary += "00000000"

    calculated_checksum = checksum(binary)
    # According to RFC768 if the result checksum is 0, it should be set to 0xFFFF  # noqa: E501
    return calculated_checksum if calculated_checksum != 0 else 0xFFFF


class UDP(Packet):
    """UDP class

    Definition:
        UDP
            sport                   (int)
            dport                   (int)
            len                     (int)
            chksum                  (int)

        Examples:
            | + create
            |     udp = UDP(sport=.., dport=.., )
            | + make change
            |     udp.sport = <value>
            |     udp.dport = <value>
            |     ...
    """

    name = "UDP"
    fields_desc = [
        ShortField("sport", 53),
        ShortField("dport", 53),
        ShortField("len", total_len),
        XShortField("chksum", udp_checksum),
    ]

    def _combine(self, body_copy):
        if body_copy.name == "BFD":
            self._body = body_copy
            self.sport = 3784
            self.dport = 3784
            return self
        if body_copy.name == "BOOTP":
            self._body = body_copy
            self.sport = 68
            self.dport = 67
            return self
        if body_copy.name == "VXLAN":
            self._body = body_copy
            self.sport = 4789
            self.dport = 4789
            return self
        if body_copy.name == "MPLS":
            self._body = body_copy
            self.dport = 6635
            return self
        if body_copy.name in ("DtelReportHdr", "DtelReportV2Hdr"):
            self._body = body_copy
            self.dport = 32766
            return self
        if body_copy.name == "GTPU":
            self._body = body_copy
            return self
        if body_copy.name == "IB_BTH":
            self._body = body_copy
            self.dport = 4791
            return self
        if body_copy.name == "SfcPause":
            self._body = body_copy
            return self

        raise ValueError("Unsupported binding")

    @staticmethod
    def from_hex(hex_str):
        """Create object from hex value"""
        sport = int(hex_str[0:4], 16)
        dport = int(hex_str[4:8], 16)
        len_ = int(hex_str[8:12], 16)
        chksum = int(hex_str[12:16], 16)
        kwargs = {"sport": sport, "dport": dport, "len": len_, "chksum": chksum}
        return UDP(**kwargs)
