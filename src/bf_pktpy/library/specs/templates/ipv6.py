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
""" IPv6 template """
import ipaddress
import six

from bf_pktpy.library.helpers.bin import to_bin
from bf_pktpy.library.helpers.chksum import checksum
from bf_pktpy.library.specs.base import Base


# =============================================================================
from bf_pktpy.library.specs.validate_src_dst import ValidateSrcDst


class IPv6(Base, ValidateSrcDst):
    """IPv6 class

    Definition:
        IPv6
            version                 (int)
            tc                      (int)
            fl                      (int)
            plen                    (int)
            nh                      (int)
            hlim                    (int)
            src                     (str)
            dst                     (str)

        Examples:
            | + create
            |     ipv6 = IPv6(version=.., tc=.., )
            | + make change
            |     ipv6.version = <value>
            |     ipv6.tc = <value>
            |     ...
    """

    name = "IPv6"

    _src = "::1"
    _dst = "::1"

    def __init__(self, **kwargs):
        Base._prepare_kwargs(kwargs)

        super(IPv6, self).__init__()
        self.version = kwargs.pop("version", 6)
        self.tc = kwargs.pop("tc", 0)
        self.fl = kwargs.pop("fl", 0)
        self.plen = kwargs.pop("plen", 0)
        self.nh = kwargs.pop("nh", 59)
        self.hlim = kwargs.pop("hlim", 64)
        self.src = kwargs.pop("src", "::1")
        self.dst = kwargs.pop("dst", "::1")
        if kwargs:
            raise ValueError("Unsupported key(s) %s" % list(kwargs.keys()))

    def _combine(self, body_copy):
        if body_copy.name == "TCP":
            self._body = body_copy
            self.nh = 6
            if not self._body.is_lock("chksum"):
                self._body._chksum = self.l4_checksum()
            return self
        if body_copy.name == "UDP":
            self._body = body_copy
            self.nh = 17
            return self
        if body_copy.name == "ICMP":
            self._body = body_copy
            self.nh = 1
            self._body.chksum = self.l4_checksum()
            return self
        if body_copy.name == "ICMPv6Unknown":
            self._body = body_copy
            self.nh = 58
            self._body.chksum = self.l4_checksum()
            return self
        if body_copy.name == "IP":
            self._body = body_copy
            self.nh = 4
            if not self._body.is_lock("chksum"):
                self._body._chksum = self.l4_checksum()
            return self
        if body_copy.name == "MPLS":
            self._body = body_copy
            self.nh = 137
            return self
        if body_copy.name == "GRE":
            self._body = body_copy
            self.nh = 47
            self._body.chksum = self.l4_checksum()
            return self
        if body_copy.name == "IPv6":
            self._body = body_copy
            self.nh = 41
            self._body.chksum = self.l4_checksum()
            return self
        if body_copy.name == "IPv6ExtHdrRouting":
            self._body = body_copy
            self.nh = 43
            return self

        raise ValueError("Unsupported binding")

    def l4_checksum(self):
        """Calculate tcp checksum"""
        binary = ""
        if self._body.name == "TCP":
            src = int(ipaddress.IPv6Address(six.ensure_text(self.src)))
            dst = int(ipaddress.IPv6Address(six.ensure_text(self.dst)))
            src_ip = to_bin(src, 128)
            dst_ip = to_bin(dst, 128)
            l4_proto = to_bin(self.nh, 8)
            ttlen = self.total_len
            temp = ttlen - self.hdr_len
            l4_len = to_bin(temp, 16)
            resved = "00000000"
            pseudo = src_ip + dst_ip + l4_len + resved + l4_proto
            if hasattr(self._body, "_chksum"):
                self._body._chksum = 0
            else:
                self._body.chksum = 0
            l4_bin = self._body.bin()
            binary = pseudo + l4_bin
            if len(binary) % 16 > 0:
                binary += "00000000"
        if self._body.name in ("ICMP", "GRE"):
            self._body.chksum = 0
            binary = self._body.bin()
            if len(binary) % 16 > 0:
                binary += "00000000"
        return checksum(binary)

    def _post_build(self):
        self.update_l4_checksum()

    def update_l4_checksum(self):
        """Self update l4 checksum"""
        if self.body is None:
            return

        if isinstance(self._body, (six.binary_type, six.string_types)):
            return

        if self._body.name not in ("TCP", "ICMP", "GRE"):
            return

        if self._body.is_lock("chksum", False):
            return

        if hasattr(self._body, "_chksum"):
            self._body._chksum = self.l4_checksum()
        else:
            self._body.chksum = self.l4_checksum()

    @staticmethod
    def from_hex(hex_str):
        """Create object from hex value"""
        version = int(hex_str[:1], 16)
        tc = int(hex_str[1:3], 16)
        fl = int(hex_str[3:8], 16)
        plen = int(hex_str[8:12], 16)
        nh = int(hex_str[12:14], 16)
        hlim = int(hex_str[14:16], 16)
        src = int(hex_str[16:48], 16)
        dst = int(hex_str[48:80], 16)

        kwargs = {
            "version": version,
            "tc": tc,
            "fl": fl,
            "plen": plen,
            "nh": nh,
            "hlim": hlim,
            "src": src,
            "dst": dst,
        }
        return IPv6(**kwargs)

    @property
    def payload_len(self):
        """Get payload length"""
        plen = 0
        if hasattr(self._body, "total_len"):
            plen = self._body.total_len
        return plen

    @property
    def hdr_len(self):
        """Get header size"""
        return 40

    @property
    def total_len(self):
        """Get full length"""
        return self.hdr_len + self.payload_len

    def _members(self):
        """Member information"""
        self.post_build()

        src = int(ipaddress.IPv6Address(six.ensure_text(self.src)))
        dst = int(ipaddress.IPv6Address(six.ensure_text(self.dst)))

        members = (
            ("version", self.version, 4),
            ("tc", self.tc, 8),
            ("fl", self.fl, 20),
            ("plen", self.payload_len, 16),
            ("nh", self.nh, 8),
            ("hlim", self.hlim, 8),
            ("src", src, 128),
            ("dst", dst, 128),
        )
        return {"ipv6": members}


# =============================================================================
