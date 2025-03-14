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
""" Dot1AD template """

from bf_pktpy.library.specs.templates.dot1q import Dot1Q


class Dot1AD(Dot1Q):
    """Dot1AD class
    Definition:
        Dot1AD
            type                      (int)
            prio                      (int)
            id                        (int)
            vlan                      (int)
        Examples:
            | + create
            |     dot1ad = Dot1AD(type=.., prio=.., ...)
            | + make change
            |     dot1ad.type = <value>
            |     dot1ad.prio = <value>
            |     ...
    """

    name = "Dot1AD"

    def _combine(self, body_copy):
        if body_copy.name == "Dot1AD":
            self._body = body_copy
            self.type = 0x88A8
            return self
        return super(Dot1AD, self)._combine(body_copy)
