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
        return self.id().replace('.runTest', '')

    def setUp(self):
        ptf.open_logfile(str(self))
        logging.info("** START TEST CASE " + str(self))

    def tearDown(self):
        logging.info("** END TEST CASE " + str(self))
