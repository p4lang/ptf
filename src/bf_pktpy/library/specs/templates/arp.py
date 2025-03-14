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
""" ARP template """
import ipaddress
import six

from bf_pktpy.library.helpers.mac import correct_mac
from bf_pktpy.library.specs.base import Base
from bf_pktpy.library.specs.validate import remove_unicode

# =============================================================================


class ARP(Base):
    """ARP class

    ARP
        hwtype                      (int)
        ptype                       (int)
        hwlen                       (int)
        plen                        (int)
        op                          (int)
        hwsrc                       (str)
        psrc                        (str)
        hwdst                       (str)
        pdst                        (str)

    Examples:
        | + create
        |     arp = ARP(hwtype=.., ptype=.., ..)
        | + make change
        |     arp.hwtype = <value>
        |     arp.ptype = <value>
        |     arp.hwlen = <value>
        |     arp.plen = <value>
        |     ...
    """

    name = "ARP"

    _hwsrc = "00:00:00:00:00:00"
    _hwdst = "00:00:00:00:00:00"

    def __init__(self, **kwargs):
        Base._prepare_kwargs(kwargs)

        super(ARP, self).__init__()
        self.hwtype = kwargs.pop("hwtype", 1)
        self.ptype = kwargs.pop("ptype", 2048)
        self.hwlen = kwargs.pop("hwlen", 6)
        self.plen = kwargs.pop("plen", 4)
        self.op = kwargs.pop("op", 1)
        self.hwsrc = kwargs.pop("hwsrc", "00:00:00:00:00:00")
        self.psrc = kwargs.pop("psrc", "0.0.0.0")
        self.hwdst = kwargs.pop("hwdst", "00:00:00:00:00:00")
        self.pdst = kwargs.pop("pdst", "0.0.0.0")
        if kwargs:
            raise ValueError("Unsupported key(s) %s" % list(kwargs.keys()))

    @property
    def hwsrc(self):
        return self._hwsrc

    @hwsrc.setter
    def hwsrc(self, value):
        value = remove_unicode(value)
        self._hwsrc = correct_mac(value)

    @property
    def hwdst(self):
        return self._hwdst

    @hwdst.setter
    def hwdst(self, value):
        value = remove_unicode(value)
        self._hwdst = correct_mac(value)

    @property
    def hdr_len(self):
        """Get header size"""
        return 28

    def _members(self):
        """Member information"""
        hwdst = self.hwdst
        hwsrc = self.hwsrc

        if isinstance(hwdst, str):
            hwdst = int(self.hwdst.replace(":", "").replace(".", ""), 16)
        if isinstance(hwsrc, str):
            hwsrc = int(self.hwsrc.replace(":", "").replace(".", ""), 16)

        psrc = self.psrc
        pdst = self.pdst

        if isinstance(psrc, (six.string_types, six.binary_type)):
            psrc = int(ipaddress.IPv4Address(six.ensure_text(self.psrc)))

        if isinstance(pdst, (six.string_types, six.binary_type)):
            pdst = int(ipaddress.IPv4Address(six.ensure_text(self.pdst)))

        members = (
            ("hwtype", self.hwtype, 16),
            ("ptype", self.ptype, 16),
            ("hwlen", self.hwlen, 8),
            ("plen", self.plen, 8),
            ("op", self.op, 16),
            ("hwsrc", hwsrc, 48),
            ("psrc", psrc, 32),
            ("hwdst", hwdst, 48),
            ("pdst", pdst, 32),
        )
        return {"arp": members}


# =============================================================================
