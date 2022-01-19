from ptf.base_tests import BaseTest
"""
This class is the test data for test group_mode_test.py
"""

class FrameworkTest21(BaseTest):
    def setUp(self) -> None:
        print("FrameworkTest21::setUp")
        
    def tearDown(self) -> None:
        print("FrameworkTest21::setUp")
    
    def runTest(self):
        self.aTest()
        #self.bTest()
        self.cTest()
        
    def aTest(self):
        print("FrameworkTest21::aTest")
        
    def bTest(self):
        print("FrameworkTest21::bTest")
    
    def cTest(self):
        print("FrameworkTest21::cTest")



class FrameworkTest22(BaseTest):
    def setUp(self) -> None:
        print("FrameworkTest22::setUp")
        
    def tearDown(self) -> None:
        print("FrameworkTest22::setUp")
    
    def runTest(self):
        self.aTest()
        #self.bTest()
        self.cTest()
        
    def aTest(self):
        print("FrameworkTest22::aTest")
        
    def bTest(self):
        print("FrameworkTest22::bTest")
    
    def cTest(self):
        print("FrameworkTest22::cTest")
