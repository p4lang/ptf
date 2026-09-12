# Copyright 2026 The P4 Language Consortium
# SPDX-License-Identifier: Apache-2.0

from ptf.base_tests import BaseTest
from ptf.testutils import test_param_get

IMPORT_VALUE = test_param_get("import_value", default=-1)


class ImportStateProbe(BaseTest):
    _nonstandard = True

    def runTest(self):
        print(">>>import_value={}".format(IMPORT_VALUE))
