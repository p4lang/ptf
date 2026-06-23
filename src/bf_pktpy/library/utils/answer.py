#!/usr/bin/env python


# Copyright (c) 2021 Intel Corporation.
# SPDX-License-Identifier: Apache-2.0

###############################################################################
"""Answer module"""


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
