#!/usr/bin/env python


# Copyright (c) 2021 Intel Corporation.
# SPDX-License-Identifier: Apache-2.0

###############################################################################
"""IPField"""

import ipaddress
import six
import socket

from scapy_helper import int2ip, ip2int

from bf_pktpy.library.fields import Field


# noinspection PyPropertyAccess,PyAttributeOutsideInit
class IPField(Field):
    def __init__(self, name, default_value):
        super(IPField, self).__init__(name, default_value, size=32)

    def from_internal(self, raw_value):
        return int2ip(raw_value)

    def to_internal(self, new_value):
        if new_value is None:
            new_value = "127.0.0.1"
        if isinstance(new_value, six.string_types):
            return ip2int(new_value)
        if isinstance(new_value, six.binary_type):
            return int.from_bytes(new_value, "big")
        return int(new_value)

    def validate(self, new_value):
        if new_value is None:
            return True
        if isinstance(new_value, six.integer_types):
            try:
                _ = int2ip(new_value)
                return True
            except (TypeError, socket.error):
                return False
        if isinstance(new_value, six.string_types):
            try:
                _ = ipaddress.IPv4Address(six.ensure_text(new_value))
                return True
            except ipaddress.AddressValueError:
                return False
        if isinstance(new_value, six.binary_type):
            try:
                _ = ipaddress.IPv4Address(new_value)
                return True
            except ipaddress.AddressValueError:
                return False

        return False
