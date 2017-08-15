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

class GetMacTest(DataplaneBaseTest):
    def __init__(self):
        DataplaneBaseTest.__init__(self)

    def runTest(self):
        def check_mac(device, port):
            mac = self.dataplane.get_mac(device, port)
            self.assertIsNotNone(mac)
            self.assertEqual(mac.count(":"), 5)

        check_mac(0, 1)
        pkt = "ab" * 20
        testutils.send_packet(self, (0, 1), str(pkt))
        print "packet sent"
        testutils.verify_packet(self, pkt, (1, 1))
        check_mac(1, 1)


class GetCountersTest(DataplaneBaseTest):
    def __init__(self):
        DataplaneBaseTest.__init__(self)

    def runTest(self):
        def check_counters(device, port):
            counters = self.dataplane.get_nn_counters(device, port)
            self.assertIsNotNone(counters)
            self.assertTrue(type(counters) is tuple)
            self.assertEqual(len(counters), 2)

            return counters

        counters_01_b = check_counters(0, 1)
        counters_11_b = check_counters(1, 1)
        print "Counters:"
        print " (0, 1) %d:%d" % counters_01_b
        print " (1, 1) %d:%d" % counters_11_b
        pkt = "ab" * 20
        testutils.send_packet(self, (0, 1), str(pkt))
        print "packet sent"
        testutils.verify_packet(self, pkt, (1, 1))
        counters_01_e = check_counters(0, 1)
        counters_11_e = check_counters(1, 1)
        print "Counters:"
        print " (0, 1) %d:%d" % counters_01_e
        print " (1, 1) %d:%d" % counters_11_e
        self.assertTrue(counters_01_e[1] > counters_01_b[1])
        self.assertTrue(counters_11_e[0] > counters_11_b[0])

class VerifyAnyPacketAnyPort(DataplaneBaseTest):
    def __init__(self):
        DataplaneBaseTest.__init__(self)

    def runTest(self):
        pkt = "ab" * 20

        testutils.send_packet(self, (0, 1), str(pkt))
        print "packet sent"
        testutils.verify_any_packet_any_port(
            self, pkts=[pkt], ports=[3, 1], device_number=1)

        # negative test: if the packet is indeed received, but not on one of the
        # expected ports, the test should fail
        with self.assertRaises(AssertionError):
            testutils.send_packet(self, (0, 1), str(pkt))
            print "packet sent"
            testutils.verify_any_packet_any_port(
                self, pkts=[pkt], ports=[0, 2, 3], device_number=1)

class RemovePort(DataplaneBaseTest):
    def __init__(self):
        DataplaneBaseTest.__init__(self)

    def runTest(self):
        pkt = "ab" * 20

        testutils.send_packet(self, (0, 1), str(pkt))
        print "packet sent"
        testutils.verify_packet(self, pkt, (1, 1))

        # We remove a port to test port_remove, but in order to execute
        # subsequent tests, we need to make sure we re-add the port
        # afterwards. In order to re-add the port, we need the interface name,
        # which is what this method is for. This is a little hacky but fine for
        # testing. In practice, you would not be removing ports which are part
        # of the original ptf config.
        def find_ifname(device_number, port_number):
            for port_id, ifname in config["port_map"].items():
                if (device_number, port_number) == port_id:
                    return ifname

        ifname = find_ifname(1, 1)
        self.assertTrue(self.dataplane.port_remove(1, 1))
        testutils.send_packet(self, (0, 1), str(pkt))
        print "packet sent"
        testutils.verify_no_other_packets(self, device_number=1)

        self.dataplane.port_add(ifname, 1, 1)
        testutils.send_packet(self, (0, 1), str(pkt))
        print "packet sent"
        testutils.verify_packet(self, pkt, (1, 1))
