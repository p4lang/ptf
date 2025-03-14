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
""" IGMP template """
import ipaddress
import six

from bf_pktpy.library.specs.base import Base


# =============================================================================
class IGMP(Base):
    """IGMP class

    IGMP
        type                    (int)
        mrcode                  (int)
        chksum                  (int)
        gaddr                   (int)


    Examples:
        | + create
        |     igmp = IGMP(type=.., mrcode=.., ..)
        | + make change
        |     igmp.type = <value>
        |     igmp.mrcode = <value>
        |     igmp.chksum = <value>
        |     igmp.gaddr = <value>
    """

    name = "IGMP"

    def __init__(self, **kwargs):
        Base._prepare_kwargs(kwargs)

        super(IGMP, self).__init__()
        self.type = kwargs.pop("type", 17)
        self.mrcode = kwargs.pop("mrcode", 20)
        self.chksum = kwargs.pop("chksum", 0)
        self.gaddr = kwargs.pop("gaddr", "0.0.0.0")
        if kwargs:
            raise ValueError("Unsupported key(s) %s" % list(kwargs.keys()))

    @property
    def hdr_len(self):
        """Get header length"""
        return 8

    @property
    def total_len(self):
        """Get full length"""
        if self._body:
            return self.hdr_len + len(self._body)
        return self.hdr_len

    @staticmethod
    def from_hex(hex_str):
        """Create object from hex value"""
        type = int(hex_str[:2], 16)
        mrcode = int(hex_str[2:4], 16)
        chksum = int(hex_str[4:8], 16)
        gaddr = int(hex_str[8:16], 16)
        gaddr = ".".join([str(int(gaddr[x : x + 2], 16)) for x in range(0, 8, 2)])
        kwargs = {"type": type, "mrcode": mrcode, "chksum": chksum, "gaddr": gaddr}
        return IGMP(**kwargs)

    def _members(self):
        """Member information"""
        gaddr = int(ipaddress.IPv4Address(six.ensure_text(self.gaddr)))
        members = (
            ("type", self.type, 8),
            ("mrcode", self.mrcode, 8),
            ("chksum", self.chksum, 16),
            ("gaddr", gaddr, 32),
        )
        return {"igmp": members}


# =============================================================================
