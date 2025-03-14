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
""" Answer module """


# =============================================================================
class Answer(list):
    """Answer container class"""

    def __iter__(self):
        for each in self[:]:
            yield each

    def is_empty(self):
        """Check if container is empty or not"""
        return False if self[:] else True

    def summary(self):
        """get summary"""
        for sent, rcvd in self:
            print("%s ==> %s" % (sent.brief(), rcvd.brief()))


# =============================================================================
class Unanswer(list):
    """Unanswer container class"""

    def __iter__(self):
        for each in self[:]:
            yield each

    def is_empty(self):
        """Check if container is empty or not"""
        return False if self[:] else True

    def summary(self):
        """get summary"""
        for sent in self:
            print(sent.brief())


# =============================================================================
