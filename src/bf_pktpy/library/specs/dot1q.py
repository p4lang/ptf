#!/usr/bin/env python


# Copyright (c) 2021 Intel Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

###############################################################################
""" Dot1Q class """
from bf_pktpy.library.specs.container import Container
from bf_pktpy.library.specs.templates.dot1q import Dot1Q as Dot1QTemplate


# =============================================================================
class Dot1Q(Container):
    """Dot1Q class"""

    fields = "type prio id vlan".split()

    def __init__(self, **kwargs):
        super(Dot1Q, self).__init__(Dot1QTemplate, **kwargs)

    def __truediv__(self, payload):
        self.clear()

        if payload.name in ("UDP", "TCP", "ICMP"):
            if len(payload) > 1:
                if len(self.params) > 1:
                    raise ValueError("Only support at most 1 dynamic field")
                for layer4 in payload:
                    ipv4 = self.clone(0)
                    self.append(ipv4 / layer4)
                return self

            if len(self.params) > 1:
                for idx in range(len(self.params)):
                    ipv4 = self.clone(idx)
                    layer4 = payload[0]
                    self.append(ipv4 / layer4)
                return self

            ipv4 = self.clone(0)
            self.append(ipv4 / payload[0])
        return self


# =============================================================================
