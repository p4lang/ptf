#!/usr/bin/env python


# Copyright (c) 2021 Intel Corporation.
# SPDX-License-Identifier: Apache-2.0

###############################################################################
"""DHCP class"""

from bf_pktpy.library.specs.container import Container
from bf_pktpy.library.specs.templates.dhcp import DHCP as DHCPTemplate


# =============================================================================
class DHCP(Container):
    """DHCP class"""

    fields = ("options",)

    def __init__(self, **kwargs):
        super(DHCP, self).__init__(DHCPTemplate, **kwargs)


# =============================================================================
