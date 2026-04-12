# Copyright 2021 Intel Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

import math

import six

from bf_pktpy.library.fields.field import Field


# noinspection PyPropertyAccess,PyAttributeOutsideInit
class BitField(Field):
    def __init__(self, name, default_value, size=1):
        super(BitField, self).__init__(name, default_value, size)

    def from_internal(self, raw_value):
        return super(BitField, self).from_internal(raw_value)

    def validate(self, new_value):
        if new_value is None:
            return True

        if isinstance(new_value, six.binary_type):
            new_value = int.from_bytes(new_value, "big")
        return isinstance(new_value, six.integer_types) and (
            0 <= new_value <= math.pow(2, self.size) - 1
        )

    def to_internal(self, new_value):
        if isinstance(new_value, six.binary_type):
            return int.from_bytes(new_value, "big")
        return int(new_value) if new_value is not None else 0
