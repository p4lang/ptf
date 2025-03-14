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
""" GRE class """
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
