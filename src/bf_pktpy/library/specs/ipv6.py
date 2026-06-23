#!/usr/bin/env python


# Copyright (c) 2021 Intel Corporation.
# SPDX-License-Identifier: Apache-2.0

###############################################################################
"""IPv6 class"""

from bf_pktpy.library.specs.container import Container
from bf_pktpy.library.specs.templates.ipv6 import IPv6 as IPv6Template


# =============================================================================
class IPv6(Container):
    """IPv6 class"""

    fields = (
        "version ihl tos len id flags frag ttl proto chksum src dst " "options"
    ).split()

    def __init__(self, **kwargs):
        super(IPv6, self).__init__(IPv6Template, **kwargs)

    def __truediv__(self, child_container):
        self.clear()

        if child_container.name in ("UDP", "TCP", "ICMP"):
            if len(child_container) > 1:
                for child in child_container:
                    parent = self.clone(0)
                    self.append(parent / child)
                return self

            if len(self.params) > 1:
                for idx in range(len(self.params)):
                    parent = self.clone(idx)
                    child = child_container[0]
                    self.append(parent / child)
                return self

            parent = self.clone(0)
            self.append(parent / child_container[0])
        return self


# =============================================================================
