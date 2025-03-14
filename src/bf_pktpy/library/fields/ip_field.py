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
""" IPField """
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
