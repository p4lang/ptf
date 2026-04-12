# Copyright 2019 Antonin Bas
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

import ptf
from ptf.base_tests import BaseTest
from ptf import testutils


class TestParamsGet(BaseTest):
    def setUp(self):
        BaseTest.setUp(self)

    def runTest(self):
        params = testutils.test_params_get(default=None)
        if params is None:
            print(">>>None")
        else:
            for k, v in params.items():
                print(">>>{}={}".format(k, v))


class TestParamGet(BaseTest):
    def setUp(self):
        BaseTest.setUp(self)

    def runTest(self):
        v = testutils.test_param_get("k1", default=-1)
        if v is None:
            print(">>>None")
        else:
            print(">>>k1={}".format(v))
