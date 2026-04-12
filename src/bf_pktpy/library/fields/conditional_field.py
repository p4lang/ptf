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

from bf_pktpy.library.fields import Field


class ConditionalField(Field):
    def __init__(self, field_def, condition):
        """A field container for any field and a condition.

        If the condition is met, the underlying field will be taken into account when
        generating _members and printing representation of header (repr). Condition
        should be in form of callable, which takes a Packet obj (or any child) and
        returns boolean value.

        :param field_def: a Field object (or any child)
        :type field_def: Field
        :param condition: a boolean callable which takes a Packet obj (or any child)
        """
        self.field = field_def
        self.condition = condition
        # We want to pass internal default value and size of underlying field in case
        # of callables
        super(ConditionalField, self).__init__(
            field_def.name, field_def._default_value, field_def._size
        )

    def from_internal(self, raw_value):
        return self.field.from_internal(raw_value)

    def to_internal(self, new_value):
        return self.field.to_internal(new_value)

    def validate(self, new_value):
        return self.field.validate(new_value)

    def post_build(self, pkt):
        self.field.post_build(pkt)
