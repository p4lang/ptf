#!/usr/bin/env python


# Copyright (c) 2021 Intel Corporation.
# SPDX-License-Identifier: Apache-2.0

###############################################################################
"""TCP class"""

from bf_pktpy.library.specs.container import Container
from bf_pktpy.library.specs.templates.tcp import TCP as TCPTemplate


# =============================================================================
class TCP(Container):
    """TCP class"""

    fields = (
        "sport dport seq ack dataofs reserved flags window chksum " "urgptr options"
    ).split()

    def __init__(self, **kwargs):
        super(TCP, self).__init__(TCPTemplate, **kwargs)

    def __truediv__(self, payload):
        self.clear()  # not done
        return self


# =============================================================================
