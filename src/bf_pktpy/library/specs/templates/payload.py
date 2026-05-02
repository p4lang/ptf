#!/usr/bin/env python


# Copyright (c) 2021 Intel Corporation.
# SPDX-License-Identifier: Apache-2.0

###############################################################################
"""Payload template"""

from bf_pktpy.library.specs.base import Base


# =============================================================================
class Payload(Base):
    """Payload class

    Definition:
        Payload
            pattern                 (str)
            data                    (str)

        Examples:
            | + create
            |     payload = Payload(pattern=.., data=..)
            | + make change
            |     payload.pattern = <value>
            |     payload.data = <value>
    """

    def __init__(self, pattern="ByteIncrement", data=""):
        self.pattern = pattern
        self.data = data

    def _members(self):
        """Member information"""
        members = (("pattern", self.pattern), ("data", self.data))
        return {"payload": members}


# =============================================================================
