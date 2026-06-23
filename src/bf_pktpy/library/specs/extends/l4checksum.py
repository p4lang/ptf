# Copyright (c) 2021 Intel Corporation.
# SPDX-License-Identifier: Apache-2.0

from bf_pktpy.library.helpers.chksum import checksum


class L4Checksum:
    def __init__(self):
        self._body = None

    def l4_checksum(self):
        """Calculate checksum"""
        if self._body is None:
            return

        if not self._body.is_lock("chksum", False):
            if hasattr(self._body, "_chksum"):
                self._body._chksum = 0
            else:
                self._body.chksum = 0
        binary = self._body.bin()
        if len(binary) % 16 > 0:
            binary += "00000000"
        return checksum(binary)
