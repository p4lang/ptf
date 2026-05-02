# Copyright 2021 Intel Corporation
# SPDX-License-Identifier: Apache-2.0

from bf_pktpy.library.fields.x_bit_field import XBitField


class XByteField(XBitField):
    def __init__(self, name, default_value):
        super(XByteField, self).__init__(name, default_value, size=8)
