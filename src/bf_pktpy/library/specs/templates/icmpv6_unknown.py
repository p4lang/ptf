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
""" ICMPv6Unknown template """
from bf_pktpy.library.specs.base import Base


# =============================================================================
class ICMPv6Unknown(Base):
    """ICMPv6Unknown fallback class

    ICMPv6Unknown
        type                    (int)
        code                    (int)
        chksum                  (int)
        msgbody                 (str)

    Examples:
        | + create
        |     icmp = ICMPv6Unknown(type=.., code=.., ..)
        | + make change
        |     icmp.type = <value>
        |     icmp.code = <value>
        |     icmp.chksum = <value>
        |     icmp.msgbody = <value>
    """

    name = "ICMPv6Unknown"

    def __init__(self, **kwargs):
        Base._prepare_kwargs(kwargs)

        super(ICMPv6Unknown, self).__init__()
        self.type = kwargs.pop("type", 8)
        self.code = kwargs.pop("code", 0)
        self.chksum = kwargs.pop("chksum", 0)
        self.msgbody = kwargs.pop("msgbody", "")
        if kwargs:
            raise ValueError("Unsupported key(s) %s" % list(kwargs.keys()))

    def _members(self):
        """Member information"""

        members = (
            ("type", self.type, 8),
            ("code", self.code, 8),
            ("chksum", self.chksum, 16),
            ("msgbody", self.msgbody, 16),
        )
        return {"icmpv6_unknown": members}


# =============================================================================
