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
