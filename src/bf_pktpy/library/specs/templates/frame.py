#!/usr/bin/env python


# Copyright (c) 2021 Intel Corporation.
# SPDX-License-Identifier: Apache-2.0

###############################################################################
"""Frame template"""

from bf_pktpy.library.specs.base import Base


# =============================================================================
class Frame(Base):
    """Frame class

    Frame
        sizes                   (list)

    Examples:
        | + create
        |     frame = Frame(sizes=[256])
        | + make change
        |     frame.sizes = [256]
    """

    def __init__(self, sizes=None):
        self.sizes = sizes or [512]

    def _members(self):
        """Member information"""
        members = (("sizes", self.sizes),)
        return {"frame": members}


# =============================================================================
