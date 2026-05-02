#!/usr/bin/env python


# Copyright (c) 2021 Intel Corporation.
# SPDX-License-Identifier: Apache-2.0

###############################################################################
"""BOOTP class"""

from bf_pktpy.library.specs.container import Container
from bf_pktpy.library.specs.templates.bootp import BOOTP as BOOTPTemplate


# =============================================================================
class BOOTP(Container):
    """BOOTP class"""

    fields = (
        "op htype hlen hops xid secs flags ciaddr yiaddr siaddr giaddr "
        "chaddr sname file options"
    ).split()

    def __init__(self, **kwargs):
        super(BOOTP, self).__init__(BOOTPTemplate, **kwargs)


# =============================================================================
