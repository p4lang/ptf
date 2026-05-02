# Copyright (c) 2021 Intel Corporation.
# SPDX-License-Identifier: Apache-2.0


class ValidateSportDport:
    @property
    def sport(self):
        return self._sport

    @sport.setter
    def sport(self, value):
        self._sport = value

    @property
    def dport(self):
        return self._dport

    @dport.setter
    def dport(self, value):
        self._dport = value

    # these 4 properties are only for cross compatibility
    @property
    def src(self):
        return self.sport

    @src.setter
    def src(self, value):
        self.sport = value

    @property
    def dst(self):
        return self.dport

    @dst.setter
    def dst(self, value):
        self.dport = value
