# Copyright 2026 The P4 Language Consortium
# SPDX-License-Identifier: Apache-2.0

import unittest

from ptf.base_tests import BaseTest


@unittest.skip("intentional skip")
class Skipped(BaseTest):
    _nonstandard = True

    def runTest(self):
        pass


class Timed(BaseTest):
    _nonstandard = True
    _testtimeout = 1

    def runTest(self):
        pass
