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
""" Payload template """
from bf_pktpy.library.specs.base import Base


# =============================================================================
class Payload(Base):
    """Payload class

    Definition:
        Payload
            pattern                 (str)
            data                    (str)

        Examples:
            | + create
            |     payload = Payload(pattern=.., data=..)
            | + make change
            |     payload.pattern = <value>
            |     payload.data = <value>
    """

    def __init__(self, pattern="ByteIncrement", data=""):
        self.pattern = pattern
        self.data = data

    def _members(self):
        """Member information"""
        members = (("pattern", self.pattern), ("data", self.data))
        return {"payload": members}


# =============================================================================
