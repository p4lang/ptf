# Copyright 2021 Intel Corporation
# SPDX-License-Identifier: Apache-2.0

from bf_pktpy.library.fields import EnumField


class ByteEnumField(EnumField):
    def __init__(self, name, default_value, types=None):
        super(ByteEnumField, self).__init__(name, default_value, size=8, types=types)
