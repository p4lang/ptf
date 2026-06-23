#!/usr/bin/env python


# Copyright (c) 2021 Intel Corporation.
# SPDX-License-Identifier: Apache-2.0

###############################################################################
"""MACField"""

import six

from bf_pktpy.library.helpers.mac import correct_mac
from bf_pktpy.library.fields import Field
from scapy_helper import mac2int, int2mac


# noinspection PyPropertyAccess,PyAttributeOutsideInit
class MACField(Field):
    def __init__(self, name, default_value):
        super(MACField, self).__init__(name, default_value, size=48)

    def defaultvalue2mac(self):
        return self.from_internal(self._default_value)

    def from_internal(self, raw_value):
        return int2mac(raw_value)

    def validate(self, new_value):
        try:
            if isinstance(new_value, (six.string_types, six.binary_type)):
                new_value = correct_mac(new_value)
                _ = mac2int(new_value)
                return True
            if isinstance(new_value, six.integer_types):
                if new_value > 2**48 - 1:
                    return False
                _ = int2mac(new_value)
                return True
            return False
        except (TypeError, ValueError):
            return False

    def to_internal(self, new_value):
        if isinstance(new_value, (six.string_types, six.binary_type)):
            new_value = correct_mac(new_value)
            return mac2int(new_value)
        return int(new_value)
