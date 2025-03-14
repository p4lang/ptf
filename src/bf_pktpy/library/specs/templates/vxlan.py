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
""" VXLAN template """
from bf_pktpy.library.specs.base import Base


# =============================================================================
class VXLAN(Base):
    """
    Definition:
        VXLAN:
            vni                     (int)
            reserved1         (int)
            reserved2             (int)
        Example:
            | + create
            |       VXLAN(vni=..., reserved1=..., ...)
            | + make change
            |       vxlan.vni = <value>
            |       vxlan.reserved1 = <value>
    """

    name = "VXLAN"

    def __init__(self, **kwargs):
        Base._prepare_kwargs(kwargs)

        super(VXLAN, self).__init__()

        self.flags = kwargs.pop("flags", 0x08)
        self.reserved0 = kwargs.pop("reserved0", 0)
        self.NextProtocol = kwargs.pop("NextProtocol", 0)
        self.reserved1 = kwargs.pop("reserved1", 0)
        self.vni = kwargs.pop("vni", 0)
        self.reserved2 = kwargs.pop("reserved2", 0)
        if kwargs:
            raise ValueError("Unsupported key(s) %s" % list(kwargs.keys()))

    def _combine(self, body_copy):
        if body_copy.name in ("Ether", "IP", "IPv6"):
            self._body = body_copy
            return self

        raise ValueError("Unsupported binding")

    def _members(self):
        """Members information"""
        members = [("flags", self.flags, 8)]
        if self.flags & 0x04:
            members.append(("reserved0", self.reserved0, 16))
            members.append(("NextProtocol", self.NextProtocol, 8))
        else:
            members.append(("reserved1", self.reserved1, 24))

        members.append(("vni", self.vni, 24))
        members.append(("reserved2", self.reserved2, 8))

        return {"vxlan": members}


# =============================================================================
