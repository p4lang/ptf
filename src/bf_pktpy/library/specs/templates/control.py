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
""" Stream control template """
from bf_pktpy.library.specs.base import Base


# =============================================================================
class StreamControl(Base):
    """Stream Control class

    StreamControl
        rate       (int): rate to send traffic
        unit       (str): send unit
        mode       (str):send mode

    Examples:
        | stream_control = StreamControl(rate=1000000)
        | stream_control.rate = 25000000000
    """

    def __init__(self, rate=1000000, unit="kbps", mode="continuous"):
        self.rate = rate
        self.unit = unit
        self.mode = mode

    def _members(self):
        """Member information"""
        members = (("rate", self.rate), ("unit", self.unit), ("mode", self.mode))
        return {"stream_control": members}


# =============================================================================
