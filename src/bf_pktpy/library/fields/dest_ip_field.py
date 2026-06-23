#!/usr/bin/env python


# Copyright (c) 2021 Intel Corporation.
# SPDX-License-Identifier: Apache-2.0

###############################################################################
"""DestIPField"""

from bf_pktpy.library.fields.ip_field import IPField


class DestIPField(IPField):
    def __init__(self, name, default_value=None):
        super(DestIPField, self).__init__(name, default_value)
