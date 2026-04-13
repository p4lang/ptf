# Copyright (c) 2021 Intel Corporation.
# SPDX-License-Identifier: Apache-2.0


def bytes2hex(packet):
    import sys

    if sys.version_info.major == 2:
        import binascii

        str_hex = binascii.b2a_hex(bytes(packet))
    else:
        try:
            # noinspection PyUnresolvedReferences
            str_hex = bytes(packet).hex()
        except TypeError:
            # noinspection PyUnresolvedReferences,PyArgumentList
            str_hex = bytes(packet, encoding="utf-8").hex()
    return str_hex
