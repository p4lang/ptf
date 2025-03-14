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
""" IPv6ExtHdrRouting template """
from bf_pktpy.library.specs.base import Base


# =============================================================================


class IPv6ExtHdrRouting(Base):
    """IPv6ExtHdrRouting class"""

    name = "IPv6ExtHdrRouting"

    _len = 0  # computed value from len of addresses

    def __init__(self, **kwargs):
        Base._prepare_kwargs(kwargs)

        super(IPv6ExtHdrRouting, self).__init__()
        self.nh = kwargs.pop("nh", 59)
        length = kwargs.pop("len", None)
        if length is not None:
            self.len = length
        self.type = kwargs.pop("type", 0)
        self.segleft = kwargs.pop("segleft", 4)
        self.reserved = kwargs.pop("reserved", 0)
        self.addresses = kwargs.pop("addresses", [])

        if kwargs:
            raise ValueError("Unsupported key(s) %s" % list(kwargs.keys()))

    def _combine(self, body_copy):
        if body_copy.name == "IP":
            self._body = body_copy
            self.nh = 4
            return self
        if body_copy.name == "IPv6":
            self._body = body_copy
            self.nh = 41
            return self
        if body_copy.name == "UDP":
            self._body = body_copy
            self.nh = 17
            return self
        if body_copy.name == "TCP":
            self._body = body_copy
            self.nh = 6
            return self
        if body_copy.name == "GRE":
            self._body = body_copy
            self.nh = 47
            return self
        if body_copy.name == "ICMPv6Unknown":
            self._body = body_copy
            self.nh = 58
            return self
        if body_copy.name == "IPv6ExtHdrRouting":
            self._body = body_copy
            self.nh = 43
            return self
        if body_copy.name == "Ether":
            self._body = body_copy
            return self

        raise ValueError("Unsupported binding")

    @property
    def len(self):
        return self._len

    @len.setter
    def len(self, custom_len):
        self.lock("len")
        self._len = custom_len

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
        return 8 + len(self.addresses) * 16

    @property
    def total_len(self):
        """Get full length"""
        return self.hdr_len + self.payload_len

    def _members(self):
        """Member information"""
        length = (
            self.len if self.is_lock("len") is not None else 2 * len(self.addresses)
        )
        members = (
            ("nh", self.nh, 8),
            ("len", length, 8),
            ("type", self.type, 8),
            ("segleft", self.segleft, 8),
            ("reserved", self.reserved, 32),
            ("addresses", self.addresses, len(self.addresses) * 16 * 8),
        )
        return {"ipv6_ext_hdr_routing": members}


# =============================================================================
