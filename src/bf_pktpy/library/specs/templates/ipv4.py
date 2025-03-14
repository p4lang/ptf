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
""" IP template """
import six

from bf_pktpy.library.helpers.bin import to_bin
from bf_pktpy.library.helpers.chksum import checksum
from bf_pktpy.library.helpers.ip_types import ITYPES
from bf_pktpy.library.specs.packet import Packet
from bf_pktpy.library.fields import (
    BitField,
    ByteField,
    ShortField,
    FlagsField,
    XShortField,
    XByteField,
    ByteEnumField,
    SourceIPField,
    DestIPField,
    IPOptionsListField,
)


def total_len(packet):
    return packet.total_len


def calculate_ihl(packet):
    return packet.hdr_len // 4


def ipv4_checksum(packet):
    """Calculate ipv4 checksum"""
    # noinspection PyProtectedMember
    members = packet._members(chksum=0)
    binary = ""
    for _, value, size in members[packet.name]:
        binary += to_bin(value, size)
    return checksum(binary)


class IP(Packet):
    """IP class

    Definition:
        IP
            version                 (int)
            ihl                     (int)
            tos                     (int)
            len                     (int)
            id                      (int)
            flags                   (int)
            frag                    (int)
            ttl                     (int)
            proto                   (int)
            chksum                  (int)
            src                     (str)
            dst                     (str)
            options                 (str)

        Examples:
            | + create
            |     ipv4 = IP(version=.., ihl=.., )
            | + make change
            |     ipv4.version = <value>  BB
            |     ipv4.ihl = <value>
            |     ...
    """

    name = "IP"
    fields_desc = [
        BitField("version", 4, 4),
        BitField("ihl", calculate_ihl, 4),
        XByteField("tos", 0),
        ShortField("len", total_len),
        ShortField("id", 1),
        FlagsField("flags", 0, 3, ["MF", "DF", "evil"]),
        BitField("frag", 0, 13),
        ByteField("ttl", 64),
        ByteEnumField("proto", 0, ITYPES),
        XShortField("chksum", ipv4_checksum),
        SourceIPField("src", "dst"),
        DestIPField("dst", "127.0.0.1"),
        IPOptionsListField("options", []),
    ]

    @property
    def proto_name(self):
        return ITYPES.get(self.proto)

    def _combine(self, body_copy):
        if body_copy.name == "TCP":
            self._body = body_copy
            self.proto = 6
            if not self._body.is_lock("chksum"):
                self._body._chksum = self.l4_checksum()
            return self
        if body_copy.name == "UDP":
            self._body = body_copy
            self.proto = 17
            return self
        if body_copy.name == "ICMP":
            self._body = body_copy
            self.proto = 1
            self._body.chksum = self.l4_checksum()
            return self
        if body_copy.name == "IGMP":
            self._body = body_copy
            self.proto = 2
            if self.internal_value("ttl") is None:
                self.ttl = 1
            self.frag = 0
            self._body.chksum = self.l4_checksum()
            return self
        if body_copy.name == "GRE":
            self._body = body_copy
            self.proto = 47
            self._body.chksum = self.l4_checksum()
            return self
        if body_copy.name == "MPLS":
            self._body = body_copy
            self.proto = 137
        if body_copy.name == "IP":
            self._body = body_copy
            self.proto = 4
            return self
        if body_copy.name == "IPv6":
            self._body = body_copy
            self.proto = 41
            return self

        raise ValueError("Unsupported binding")

    @property
    def hdr_len(self):
        """Get header size"""
        if not self.options:
            return 20

        option_len = sum(len(bytes(option)) for option in self.options)
        padding = option_len % 4
        if padding != 0:
            option_len += 4 - padding
        return 20 + option_len

    def reset_chksum(self):
        self.chksum = None  # noqa

    def l4_checksum(self):
        """Calculate tcp checksum"""

        def reset_l4_chksum():
            if not self._body.is_lock("chksum", False):
                if hasattr(self._body, "_chksum"):
                    self._body._chksum = 0
                else:
                    self._body.chksum = 0

        def members_lookup(members, field_name):
            return next(
                (val, size) for name, val, size in members if name == field_name
            )

        binary = ""
        if self._body.name == "TCP":
            _members = self._members()["IP"]
            src_ip = to_bin(*members_lookup(_members, "src"))
            dst_ip = to_bin(*members_lookup(_members, "dst"))
            l4_proto = to_bin(*members_lookup(_members, "proto"))
            ttlen = self.total_len
            temp = ttlen - self.hdr_len
            l4_len = to_bin(temp, 16)
            resved = "00000000"
            pseudo = src_ip + dst_ip + l4_len + resved + l4_proto
            reset_l4_chksum()
            l4_bin = self._body.bin()
            binary = pseudo + l4_bin
            if len(binary) % 16 > 0:
                binary += "00000000"
        if self._body.name in ("ICMP", "GRE", "IGMP"):
            reset_l4_chksum()
            binary = self._body.bin()
            if len(binary) % 16 > 0:
                binary += "00000000"
        return checksum(binary)

    def _post_build(self):
        self.update_l4_checksum()

    # TODO(sborkows): To be modified when all L4 headers will be rewritten
    def update_l4_checksum(self):
        """Self update l4 checksum"""
        if self.body is None:
            return

        if isinstance(self._body, (six.binary_type, six.string_types)):
            return

        if self._body.name not in ("TCP", "ICMP", "GRE", "IGMP"):
            return

        if self._body.is_lock("chksum", False):
            return

        if hasattr(self._body, "_chksum"):
            self._body._chksum = self.l4_checksum()
        elif hasattr(self._body, "chksum"):
            self._body.chksum = self.l4_checksum()

    @staticmethod
    def from_hex(hex_str):
        """Create object from hex value"""
        version = int(hex_str[:1], 16)
        ihl = int(hex_str[1:2], 16)
        tos = int(hex_str[2:4], 16)
        len_ = int(hex_str[4:8], 16)
        id_ = int(hex_str[8:12], 16)
        _flags_and_frag_bin = bin(int(hex_str[12:16], 16))[2:].zfill(16)
        flags = int(_flags_and_frag_bin[:3], 2)
        frag = int(_flags_and_frag_bin[3:], 2)
        ttl = int(hex_str[16:18], 16)
        proto = int(hex_str[18:20], 16)
        chksum = int(hex_str[20:24], 16)
        src = hex_str[24:32]
        src = ".".join([str(int(src[x : x + 2], 16)) for x in range(0, 8, 2)])
        dst = hex_str[32:40]
        dst = ".".join([str(int(dst[x : x + 2], 16)) for x in range(0, 8, 2)])

        if ihl > 5:
            opt_end = ihl * 4 * 2
            pad_end = 0
            if opt_end % 8:
                pad_end = 8 - len(opt_end) % 8
            opt_ = hex_str[40 : opt_end + pad_end]
            options = ""
            for idx in range(len(opt_)):
                temp = bin(int(opt_[idx], 16))
                options += temp[2:]
            # if options:
            #     pad = (32 - len(options) % 32) * "0"
            #     options += pad

            kwargs = {
                "version": version,
                "ihl": ihl,
                "tos": tos,
                "len": len_,
                "id": id_,
                "flags": flags,
                "frag": frag,
                "ttl": ttl,
                "proto": proto,
                "chksum": chksum,
                "src": src,
                "dst": dst,
                "options": options,
            }
        else:
            kwargs = {
                "version": version,
                "ihl": ihl,
                "tos": tos,
                "len": len_,
                "id": id_,
                "flags": flags,
                "frag": frag,
                "ttl": ttl,
                "proto": proto,
                "chksum": chksum,
                "src": src,
                "dst": dst,
            }
        return IP(**kwargs)
