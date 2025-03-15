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
