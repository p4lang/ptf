#!/usr/bin/env python


# Copyright (c) 2021 Intel Corporation.
# SPDX-License-Identifier: Apache-2.0

###############################################################################
from bf_pktpy.library.fields.ip_field import IPField


# noinspection PyPropertyAccess,PyAttributeOutsideInit
class IPListField(IPField):
    def __init__(self, name, default_value=None):
        if default_value is None:
            default_value = []
        if not isinstance(default_value, list):
            default_value = [default_value]
        # We are omitting IPField constructor, as size will be different than 32
        super(IPField, self).__init__(
            name, default_value, size=lambda value: value * 32
        )

    def from_internal(self, raw_value):
        return [super(IPListField, self).from_internal(raw_ip) for raw_ip in raw_value]

    def to_internal(self, new_value):
        if new_value is None:
            return []
        if not isinstance(new_value, list):
            new_value = [new_value]
        return [super(IPListField, self).to_internal(new_ip) for new_ip in new_value]

    def validate(self, new_value):
        if new_value is None:
            return True
        if not isinstance(new_value, list):
            new_value = [new_value]
        return all(super(IPListField, self).validate(new_ip) for new_ip in new_value)
