# Copyright 2026
# SPDX-License-Identifier: Apache-2.0

from ptf.base_tests import BaseTest


module_events = []


def setUpModule():
    module_events.append("setUpModule")
    print(">>>setUpModule")


def tearDownModule():
    module_events.append("tearDownModule")
    print(">>>tearDownModule")


class ModuleFixtureProbeOne(BaseTest):
    class_events = []

    @classmethod
    def setUpClass(cls):
        cls.class_events.append("setUpClass")
        print(">>>ModuleFixtureProbeOne.setUpClass")

    @classmethod
    def tearDownClass(cls):
        cls.class_events.append("tearDownClass")
        print(">>>ModuleFixtureProbeOne.tearDownClass")

    def setUp(self):
        BaseTest.setUp(self)

    def runTest(self):
        print(">>>ModuleFixtureProbeOne.runTest")


class ModuleFixtureProbeTwo(BaseTest):
    class_events = []

    @classmethod
    def setUpClass(cls):
        cls.class_events.append("setUpClass")
        print(">>>ModuleFixtureProbeTwo.setUpClass")

    @classmethod
    def tearDownClass(cls):
        cls.class_events.append("tearDownClass")
        print(">>>ModuleFixtureProbeTwo.tearDownClass")

    def setUp(self):
        BaseTest.setUp(self)

    def runTest(self):
        print(">>>ModuleFixtureProbeTwo.runTest")
