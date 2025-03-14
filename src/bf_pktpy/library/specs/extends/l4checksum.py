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
