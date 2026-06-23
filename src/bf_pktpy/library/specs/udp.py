#!/usr/bin/env python


# Copyright (c) 2021 Intel Corporation.
# SPDX-License-Identifier: Apache-2.0

###############################################################################
"""UDP class"""

from bf_pktpy.library.specs.container import Container
from bf_pktpy.library.specs.templates.udp import UDP as UDPTemplate


# =============================================================================
class UDP(Container):
    """UDP class"""

    fields = "sport dport len chksum".split()

    def __init__(self, **kwargs):
        super(UDP, self).__init__(UDPTemplate, **kwargs)

    def __truediv__(self, payload):
        self.clear()  # not done
        return self


# =============================================================================
