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
""" ERSPAN_OLD Platform Specific template """
from bf_pktpy.library.specs.packet import Packet
from bf_pktpy.library.fields import BitField, XIntField

# =============================================================================


class ERSPAN_PlatformSpecific(Packet):
    """
    ERSPAN_PlatformSpecific class

        ERSPAN_PlatformSpecific
            platf_if     (int)
            info1        (int)
            info2        (int)

        Examples:
            | + create
            |     erspan_platform_specific =
            |       ERSPAN_PlatformSpecific(platf_if=.., info1=.., ..)
            | + make change
            |       erspan_platform_specific.info1 = <value>
            |       ...
    """

    name = "ERSPAN_PlatformSpecific"
    fields_desc = [
        BitField("platf_id", 0, 6),
        BitField("info1", 0, 26),
        XIntField("info2", 0x00000000),
    ]

    def _combine(self, body_copy):
        if body_copy.name == "Ether":
            self._body = body_copy
            return self

        raise ValueError("Unsupported binding")


# =============================================================================
