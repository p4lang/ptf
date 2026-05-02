#!/usr/bin/env python


# Copyright (c) 2021 Intel Corporation.
# SPDX-License-Identifier: Apache-2.0

###############################################################################
"""GRE class"""

from bf_pktpy.library.specs.container import Container
from bf_pktpy.library.specs.templates.gre import GRE as GRETemplate


# =============================================================================
class GRE(Container):
    """GRE class"""

    fields = (
        "chksum_present routing_present key_present seqnum_present "
        "strict_route_source recursion_control flags version proto "
        "chksum offset key sequence_number"
    ).split()

    def __init__(self, **kwargs):
        super(GRE, self).__init__(GRETemplate, **kwargs)

    def __truediv__(self, payload):
        self.clear()  # not done

        return self


# =============================================================================
