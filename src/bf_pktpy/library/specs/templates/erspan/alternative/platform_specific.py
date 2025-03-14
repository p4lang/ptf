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
""" PlatformSpecific template """
from bf_pktpy.library.specs.base import Base
from bf_pktpy.library.specs.validate import ToBeBitField, ToBeIntegerField


# =============================================================================
class PlatformSpecific(Base):
    """
    PlatformSpecific class

        PlatformSpecific
            platf_id    (int)
            info1       (int)
            info2       (int)

        Examples:
            | + create
            |     platform_specific = PlatformSpecific(platf_id=.., info1=.., .)
            | + make change
            |     platform_specific.platf_id = <value>
            |     platform_specific.info1 = <value>
            |     ...
    """

    name = "PlatformSpecific"

    platf_id = ToBeBitField(6)
    info1 = ToBeBitField(26)
    info2 = ToBeIntegerField()

    def __init__(self, **kwargs):
        super(PlatformSpecific, self).__init__()
        self.alternative = True

        self.platf_id = kwargs.pop("platf_id", 0)
        self.info1 = kwargs.pop("info1", 0)
        self.info2 = kwargs.pop("info2", 0)

        if kwargs:
            raise ValueError("Unsupported key(s) %s" % kwargs.keys())

    def _combine(self, body):
        if hasattr(body, "name"):
            last = self.get_last()
            if last.name == "PlatformSpecific":
                if body.name == "Ether":
                    last._body = body
                    return self
        try:
            self._body / body
            return self
        except ValueError:
            raise ValueError("Unsupported value type")

    def _members(self):
        """Members information"""
        members = (
            ("platf_id", self.platf_id, 6),
            ("info1", self.info1, 26),
            ("info2", self.info2, 32),
        )
        return {"platform_specific": members}


# =============================================================================
