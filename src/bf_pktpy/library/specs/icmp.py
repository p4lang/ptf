#!/usr/bin/env python


# Copyright (c) 2021 Intel Corporation.
# SPDX-License-Identifier: Apache-2.0

###############################################################################
"""ICMP class"""

from bf_pktpy.library.specs.container import Container
from bf_pktpy.library.specs.templates.icmp import ICMP as ICMPTemplate


# =============================================================================
class ICMP(Container):
    """ICMP class"""

    fields = "type code chksum id seq".split()

    def __init__(self, **kwargs):
        super(ICMP, self).__init__(ICMPTemplate, **kwargs)

    def __truediv__(self, payload):
        self.clear()  # not done
        return self


# =============================================================================
