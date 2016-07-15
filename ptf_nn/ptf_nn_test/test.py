import ptf
from ptf.base_tests import BaseTest
from ptf import config
import ptf.testutils as testutils

class DataplaneBaseTest(BaseTest):
    def __init__(self):
        BaseTest.__init__(self)

    def setUp(self):
        self.dataplane = ptf.dataplane_instance
        self.dataplane.flush()
        if config["log_dir"] != None:
            filename = os.path.join(config["log_dir"], str(self)) + ".pcap"
            self.dataplane.start_pcap(filename)

    def tearDown(self):
        if config["log_dir"] != None:
            self.dataplane.stop_pcap()

class OneTest(DataplaneBaseTest):
    def __init__(self):
        DataplaneBaseTest.__init__(self)

    def runTest(self):
        pkt = "ab" * 20
        testutils.send_packet(self, (0, 1), str(pkt))
        print "packet sent"
        testutils.verify_packet(self, pkt, (1, 1))
