#!/usr/bin/env python


# Copyright (c) 2021 Intel Corporation.
# SPDX-License-Identifier: Apache-2.0

###############################################################################
"""TCPOption template"""

from bf_pktpy.library.specs.base import Base

# =============================================================================


class TCPOptionPlaceholder(Base):
    """TCPOption class
    Definition:
        TCPOption

        Examples:
            | + create
            |     TCPOption = TCPOption('0x14040000')
            |
    """

    name = "TCPOptionPlaceholder"

    def __init__(self, *args):
        super(TCPOptionPlaceholder, self).__init__()

        self.b = None
        if args:
            self.b = args[0]

    def __int__(self):
        return int(self.hex().replace(" ", ""), 16)

    def _members(self):
        """Member information"""
        return {"tcpoption": {("bin", self.b, len(self.b) * 2)}}


# =============================================================================
