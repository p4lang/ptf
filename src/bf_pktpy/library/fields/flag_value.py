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
""" FlagValue class """


class FlagValue(object):
    def __init__(self, value, types):
        self.value = value
        self.types = types

    def __repr__(self):
        delimiter = "+" if isinstance(self.types, list) else ""
        bin_val = bin(self.value)[2:].zfill(len(self.types))
        flags_str = delimiter.join(
            flag for bit, flag in zip(bin_val[::-1], self.types) if int(bit)
        )
        return "<Flag %d (%s)>" % (self.value, flags_str)
