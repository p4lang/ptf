import subprocess
import unittest


class BaseTestCase(unittest.TestCase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def setUp(self):
        super().setUp()

    def run_ptf(self, args=[], input=None):
        # redirect stderr to stdout so we can get error messages
        r = subprocess.run(
            ['sudo', './ptf'] + args,
            input=input,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            universal_newlines=True)
        return r.returncode, r.stdout

    def tearDown(self):
        super().tearDown()


class GroupModeTestCase(BaseTestCase):
    """
    Test cases to test the group_mode.
    """
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)


    def parse_output(self, out, expects):
        hits = 0
        for line in out.splitlines():
            if line == "None":
                return None
            for s in expects:
                if s in line:
                    hits += 1 
        return hits


    def run_tests(self, groupMode):
        if groupMode != None:
            args=['--test-dir', "utests/group_mode_tests/sample",
                   '--group-mode', groupMode]
        else:
            args=['--test-dir', 
                  'utests/group_mode_tests/sample']
        rc, out = self.run_ptf(args)
        return out


    def test_method_group_mode(self):
        out = self.run_tests("method")
        expects = {"FrameworkTest.aTest ... ok",
                   "FrameworkTest.bTest ... ok",
                   "FrameworkTest.cTest ... ok",
                   "Ran 6 tests"} #hit twice
        hits = self.parse_output(out, expects)
        self.assertEqual(hits, len(expects) + 1)


    def test_class_group_mode(self):
        out = self.run_tests("class")
        expects = ["framework_tests.FrameworkTest ", 
                   "Ran 1 test"] #X4
        hits = self.parse_output(out, expects)
        self.assertEqual(hits, len(expects) + 3)


    def test_non_group_mode(self):
        out = self.run_tests(None)
        expects = ["framework_tests.FrameworkTest ",
                   "Ran 1 test"] #X4
        hits = self.parse_output(out, expects)
        self.assertEqual(hits, len(expects) + 3)


    def test_invalidate_group_mode(self):
        out = self.run_tests("no-existing")
        expects = ["error: argument --group-mode: invalid choice: 'no-existing' (choose from 'class', 'method')"]
        hits = self.parse_output(out, expects)
        self.assertEqual(hits, len(expects))
