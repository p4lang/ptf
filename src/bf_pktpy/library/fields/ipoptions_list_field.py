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
import six

from bf_pktpy.library.specs.templates.ipoption import (
    _IPOption,
    IPOption,
    ipoptions_mapping,
)
from bf_pktpy.library.fields.field import Field


# noinspection PyPropertyAccess,PyAttributeOutsideInit
class IPOptionsListField(Field):
    def __init__(self, name, default_value=None):
        if default_value is None:
            default_value = []
        if not isinstance(default_value, list):
            default_value = [default_value]
        super(IPOptionsListField, self).__init__(
            name, default_value, size=lambda value: len(value) * 8
        )

    def from_internal(self, raw_value):
        return [
            ipoptions_mapping.get(raw_option[0], IPOption)(raw_option)
            for raw_option in raw_value
        ]

    def to_internal(self, new_value):
        if new_value is None or not new_value:
            return []
        if not isinstance(new_value, list):
            new_value = [new_value]
        return [bytes(option) for option in new_value]

    def validate(self, new_value):
        if new_value is None or not new_value:
            return True
        if not isinstance(new_value, list):
            new_value = [new_value]
        return all(
            isinstance(option, (_IPOption, six.binary_type)) for option in new_value
        )
