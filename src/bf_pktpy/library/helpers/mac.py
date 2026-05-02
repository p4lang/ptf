# Copyright (c) 2021 Intel Corporation.
# SPDX-License-Identifier: Apache-2.0
import binascii
import getmac
import six

from scapy_helper import int2mac


def get_src_mac_address():
    """
    Get MAC Address of the host
    """
    # noinspection PyBroadException
    try:
        mac = getmac.get_mac_address()
        if mac is None:
            return "00:00:00:00:00:00"
        return mac
    except Exception:
        return "00:00:00:00:00:00"


def correct_mac(value):
    if isinstance(value, six.integer_types):
        return int2mac(value)

    if isinstance(value, six.binary_type):
        if b"-" in value:
            value = value.replace(b"-", b"")
        if b"0x" in value:
            value = value.replace(b"0x", b"")
        if b":" in value:
            value = b"".join(x.zfill(2) for x in value.split(b":"))
        try:
            str_value = six.ensure_str(value)
            int(str_value, 16)
        except ValueError:
            str_value = six.ensure_str(binascii.hexlify(value))
        return ":".join(
            str_value[i : i + 2].zfill(2) for i in range(0, len(str_value), 2)
        )

    if isinstance(value, six.string_types):
        value = six.ensure_str(value)
        if "-" in value:
            value = value.replace("-", "")
        if "0x" in value:
            value = value.replace("0x", "")
        if ":" in value:
            value = "".join(x.zfill(2) for x in value.split(":"))
        # case when provide address as encoded string: SEEYOU -> 53:45:45:59:4f:55 (hex)
        if len(value) == 6:
            value = "".join("%02x" % ord(num) for num in value)
        try:
            int(value, 16)
        except ValueError:
            value = six.ensure_str(binascii.hexlify(six.ensure_binary(value)))
        return ":".join(value[i : i + 2].zfill(2) for i in range(0, len(value), 2))

    raise TypeError(
        "Only values of type: %s are supported" % six.integer_types
        + six.string_types
        + (six.binary_type,)
    )
