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
""" TCPOption template """

from bf_pktpy.library.specs.base import Base

# =============================================================================


class TCPOptionPlaceholder(Base):
    """TCPOption class
    Definition:
        TCPOption

        Examples:
            | + create
            |     TCPOption = TCPOption('0x14040000')
            |
    """

    name = "TCPOptionPlaceholder"

    def __init__(self, *args):
        super(TCPOptionPlaceholder, self).__init__()

        self.b = None
        if args:
            self.b = args[0]

    def __int__(self):
        return int(self.hex().replace(" ", ""), 16)

    def _members(self):
        """Member information"""
        return {"tcpoption": {("bin", self.b, len(self.b) * 2)}}


# =============================================================================
