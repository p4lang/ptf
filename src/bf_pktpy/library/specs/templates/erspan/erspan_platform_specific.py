#!/usr/bin/env python


# Copyright (c) 2022 Intel Corporation.
# SPDX-License-Identifier: Apache-2.0

###############################################################################
"""ERSPAN_OLD Platform Specific template"""

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
