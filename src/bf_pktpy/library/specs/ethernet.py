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
""" Ether class """
from bf_pktpy.library.specs.container import Container
from bf_pktpy.library.specs.templates import clone
from bf_pktpy.library.specs.templates.ethernet import Ether as EtherTemplate


# =============================================================================
class Ether(Container):
    """Ether class"""

    fields = "src dst type".split()

    def __init__(self, **kwargs):
        super(Ether, self).__init__(EtherTemplate, **kwargs)
        Container.count_field_with_values = 0

    def clone_parent(self, idx):
        """Clone parent"""
        cloned_parent = self.clone(idx)
        child = self[idx].body
        while hasattr(child, "name"):
            cloned_child = clone(child)
            cloned_parent = cloned_parent / cloned_child
            child = child.body
        return cloned_parent

    def __div__(self, other):
        self.__truediv__(other)

    def __truediv__(self, child_container):
        new_list = []
        if len(child_container) > 1:
            # Last protocol has a field with multiple values
            for child in child_container:
                parent = self.clone_parent(0)
                new_list.append(parent / child)
            self.clear()
            self.extend(new_list)
            return self

        if len(self.params) > 1:
            # First protocol has a field with multiple values
            for idx in range(len(self.params)):
                parent = self.clone_parent(idx)
                child = clone(child_container[0])
                new_list.append(parent / child)
            self.clear()
            self.extend(new_list)
            return self

        if len(self) > 1:
            # Existing protocol(s) has a field with multiple values
            for parent in self:
                child = clone(child_container[0])
                parent / child
            return self

        # no protocols have multiple values
        parent = self.clone_parent(0)
        temp = parent / child_container[0]
        new_list.append(temp)
        self.clear()
        self.extend(new_list)
        return self


# =============================================================================
