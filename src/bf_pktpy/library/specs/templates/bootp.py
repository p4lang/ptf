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
""" BOOTP template """
from bf_pktpy.library.specs.base import Base


# =============================================================================
_magic = 0x63825363


class BOOTP(Base):
    """
    BOOTP class
    Bootstrap Protocol

        Definition:
        BOOTP
            op          (int)
            htype       (int)
            hlen        (int)
            hops        (int)
            xid         (int)
            secs        (int)
            flags       (int)
            ciaddr      (str)
            yiaddr      (str)
            siaddr      (str)
            giaddr      (str)
            chaddr      (str)
            sname       (str)
            file        (str)
            options     (str)

        Examples:
            | + create
            |     bootp = BOOTP(op=.., htype=.., )
            | + make change
            |     bootp.op = <value>
            |     bootp.htype = <value>
            |     ...
    """

    name = "BOOTP"

    def __init__(self, **kwargs):
        Base._prepare_kwargs(kwargs)

        super(BOOTP, self).__init__()
        self.op = kwargs.pop("op", 1)
        self.htype = kwargs.pop("htype", 1)
        self.hlen = kwargs.pop("hlen", 6)
        self.hops = kwargs.pop("hops", 0)
        self.xid = kwargs.pop("xid", 0)
        self.secs = kwargs.pop("secs", 0)
        self.flags = kwargs.pop("flags", 0)
        self.ciaddr = kwargs.pop("ciaddr", "")
        self.yiaddr = kwargs.pop("yiaddr", "")
        self.siaddr = kwargs.pop("siaddr", "0.0.0.0")
        self.giaddr = kwargs.pop("giaddr", "0.0.0.0")
        self.chaddr = kwargs.pop("chaddr", "")
        self.sname = kwargs.pop("sname", "")
        self.file = kwargs.pop("file", "")
        self.options = kwargs.pop("options", 0)

        if kwargs:
            raise ValueError("Unsupported key(s) %s" % list(kwargs.keys()))

    def _combine(self, body_copy):
        if body_copy.name == "DHCP":
            self._body = body_copy
            self.options = _magic
            return self

        raise ValueError("Unsupported binding")

    @property
    def total_len(self):
        """Get full length"""
        if self._body:
            return self.hdr_len + len(self._body)
        return self.hdr_len

    def _members(self):
        members = (
            ("op", self.op, 8),
            ("htype", self.htype, 8),
            ("hlen", self.hlen, 8),
            ("hops", self.hops, 8),
            ("xid", self.xid, 32),
            ("secs", self.secs, 16),
            ("flags", self.flags, 16),
            ("ciaddr", self.ciaddr, 32),
            ("yiaddr", self.yiaddr, 32),
            ("siaddr", self.siaddr, 32),
            ("giaddr", self.giaddr, 32),
            ("chaddr", self.chaddr, 128),
            ("sname", self.sname, 512),
            ("file", self.file, 1024),
            ("options", self.options, 0),
        )
        return {"bootp": members}


# =============================================================================
