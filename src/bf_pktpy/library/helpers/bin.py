# Copyright (c) 2021 Intel Corporation.
# SPDX-License-Identifier: Apache-2.0


import ipaddress
import six


def to_bin(value, bit_size=1):
    """Convert to binary"""
    if isinstance(value, (list, tuple)):
        if not value:
            return ""
        binary = ""
        for entry in value:
            binary += to_bin(entry)
        return binary

    if isinstance(value, six.binary_type):
        if not value:
            return "0".zfill(bit_size)
        return "".join(bin(b)[2:].zfill(8) for b in value)

    if isinstance(value, six.string_types):
        if not value:
            return "0".zfill(bit_size)
        try:
            ip = ipaddress.ip_address(six.u(value))
            if ip.version == 4:
                return bin(int(ip))[2:].zfill(32)
            elif ip.version == 6:
                return bin(int(ip))[2:].zfill(128)
        except ValueError:
            pass
        temp = (
            format(i, "b").zfill(bit_size) for i in bytearray(six.ensure_binary(value))
        )
        return "".join(temp)
    if bit_size:
        return bin(value)[2:].zfill(bit_size)
    return bin(value)[2:]
