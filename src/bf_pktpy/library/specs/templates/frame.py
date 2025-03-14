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
""" Frame template """
from bf_pktpy.library.specs.base import Base


# =============================================================================
class Frame(Base):
    """Frame class

    Frame
        sizes                   (list)

    Examples:
        | + create
        |     frame = Frame(sizes=[256])
        | + make change
        |     frame.sizes = [256]
    """

    def __init__(self, sizes=None):
        self.sizes = sizes or [512]

    def _members(self):
        """Member information"""
        members = (("sizes", self.sizes),)
        return {"frame": members}


# =============================================================================
