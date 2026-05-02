#!/usr/bin/env python


# Copyright (c) 2021 Intel Corporation.
# SPDX-License-Identifier: Apache-2.0

###############################################################################
"""EnumField"""

import math
from operator import attrgetter
import six

from bf_pktpy.library.fields import Field


# noinspection PyPropertyAccess,PyAttributeOutsideInit
class EnumField(Field):
    """EnumField adds another property: `types` which holds valid int:str mapping
    for the field.
    """

    def __init__(self, name, default_value, size, types=None):
        super(EnumField, self).__init__(name, default_value, size)
        self.types = types

    types = property(attrgetter("_types"))

    @types.setter
    def types(self, types):
        if isinstance(types, dict):
            self._types = types
        elif types is None:
            self._types = {}
        else:
            raise TypeError(
                "Types in enum field should be dictionary not: {}".format(type(types))
            )

    def __repr__(self):
        return "{}(name={}, default_value={}, length={})".format(
            type(self).__name__,
            self.name,
            self._get_hex_value(self.default_value),
            self.size,
        )

    def _get_hex_value(self, value):
        hex_value = self.defaultvalue2hex()
        return self.types[hex_value] if hex_value in self.types else hex(value)

    def from_internal(self, raw_value):
        return super(EnumField, self).from_internal(raw_value)

    def validate(self, new_value):
        if new_value is None:
            return True
        if isinstance(new_value, six.string_types):
            try:
                _ = int(new_value, 0)
                return True
            except (TypeError, ValueError):
                return False
        return isinstance(new_value, six.integer_types) and (
            0 <= new_value <= math.pow(2, self.size) - 1
        )

    def to_internal(self, new_value):
        if new_value is None:
            return 0
        if isinstance(new_value, six.string_types):
            return int(new_value, 0)
        return int(new_value)
