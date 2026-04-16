# Copyright 2010 The Board of Trustees of The Leland Stanford Junior University
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

# This file was derived from code in the Floodlight OFTest repository
# https://github.com/floodlight/oftest released under the OpenFlow
# Software License:
# https://github.com/floodlight/oftest/blob/master/LICENSE
# See file README-oftest.md in the ptf repository for more details.

"""
Base classes for test cases

Tests will usually inherit from one of these classes to have the controller
and/or dataplane automatically set up.
"""

import logging
import unittest
import os

import ptf
from ptf import config
import ptf.dataplane as dataplane


class BaseTest(unittest.TestCase):
    def __str__(self):
        return self.id().replace(".runTest", "")

    def setUp(self):
        ptf.open_logfile(str(self))
        logging.info("** START TEST CASE " + str(self))

    def run(self, result=None):
        unittest.TestCase.run(self, result)

    def tearDown(self):
        logging.info("** END TEST CASE " + str(self))

    def before_send(self, pkt, device_number=0, port_number=-1):
        """
        This function is meant to be overwritten in children classes if
        needed. It is called every time a packet is about to be send.
        """
        # print ":".join("{:02x}".format(ord(c)) for c in pkt)
        pass

    def at_receive(self, pkt, device_number=0, port_number=-1):
        """
        This function is meant to be overwritten in children classes if
        needed. It is called every time a packet has been received.
        """
        # print ":".join("{:02x}".format(ord(c)) for c in pkt)
        pass
