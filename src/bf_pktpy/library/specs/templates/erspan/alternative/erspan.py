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
""" ERSPAN template """
from bf_pktpy.library.specs.base import Base
from bf_pktpy.library.specs.validate import ToBeBitField, ToBeIntegerField


# =============================================================================
class ERSPAN(Base):
    """
    ERSPAN class

        ERSPAN
            version     (int)
            vlan        (int)
            priority    (int)
            unknown2    (int)
            direction   (int)
            truncated   (int)
            span_id     (int)
            unknown7    (int)

        Examples:
            | + create
            |     erspan = ERSPAN(version=.., vlan=.., ..)
            | + make change
            |     erspan.version = <value>
            |     erspan.vlan = <value>
            |     ...
    """

    name = "ERSPAN"

    version = ToBeBitField(4, default=1)
    vlan = ToBeBitField(12)
    priority = ToBeBitField(3)
    unknown2 = ToBeBitField(1)
    direction = ToBeBitField(1)
    truncated = ToBeBitField(1)
    span_id = ToBeBitField(10)
    unknown7 = ToBeIntegerField()

    def __init__(self, **kwargs):
        super(ERSPAN, self).__init__()
        self.alternative = True

        self.version = kwargs.pop("version", 1)
        self.vlan = kwargs.pop("vlan", 0)
        self.priority = kwargs.pop("priority", 0)
        self.unknown2 = kwargs.pop("unknown2", 0)
        self.direction = kwargs.pop("direction", 0)
        self.truncated = kwargs.pop("truncated", 0)
        self.span_id = kwargs.pop("span_id", 0)
        self.unknown7 = kwargs.pop("unknown7", 0)

        if kwargs:
            raise ValueError("Unsupported key(s) %s" % kwargs.keys())

    def _combine(self, body):
        if hasattr(body, "name"):
            last = self.get_last()
            if last.name == "ERSPAN":
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
            ("version", self.version, 4),
            ("vlan", self.vlan, 12),
            ("priority", self.priority, 3),
            ("unknown2", self.unknown2, 1),
            ("direction", self.direction, 1),
            ("truncated", self.truncated, 1),
            ("span_id", self.span_id, 10),
            ("unknown7", self.unknown7, 32),
        )
        return {"erspan": members}


# =============================================================================
