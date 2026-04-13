# Copyright (c) 2021 Intel Corporation.
# SPDX-License-Identifier: Apache-2.0
import ipaddress

from bf_pktpy.library.specs.validate import remove_unicode


class ValidateSrcDst:
    @property
    def src(self):
        return self._src

    @src.setter
    def src(self, value):
        if isinstance(value, int):
            value = str(ipaddress.ip_address(value))
        else:
            value = remove_unicode(value)
        self._src = value

    @property
    def dst(self):
        return self._dst

    @dst.setter
    def dst(self, value):
        if isinstance(value, int):
            value = str(ipaddress.ip_address(value))
        else:
            value = remove_unicode(value)
        self._dst = value
