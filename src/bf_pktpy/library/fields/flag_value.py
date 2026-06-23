#!/usr/bin/env python


# Copyright (c) 2021 Intel Corporation.
# SPDX-License-Identifier: Apache-2.0

###############################################################################
"""FlagValue class"""


class FlagValue(object):
    def __init__(self, value, types):
        self.value = value
        self.types = types

    def __repr__(self):
        delimiter = "+" if isinstance(self.types, list) else ""
        bin_val = bin(self.value)[2:].zfill(len(self.types))
        flags_str = delimiter.join(
            flag for bit, flag in zip(bin_val[::-1], self.types) if int(bit)
        )
        return "<Flag %d (%s)>" % (self.value, flags_str)
