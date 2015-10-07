"""
OpenFlow Test Framework

DataPlane and DataPlanePort classes

Provide the interface to the control the set of ports being used
to stimulate the switch under test.

See the class dataplaneport for more details.  This class wraps
a set of those objects allowing general calls and parsing
configuration.

@todo Add "filters" for matching packets.  Actions supported
for filters should include a callback or a counter
"""

import sys
import os
import socket
import time
import select
import logging
from threading import Thread
from threading import Lock
from threading import Condition
import ptfutils
import netutils
import mask
from pcap_writer import PcapWriter

if "linux" in sys.platform:
    import afpacket
else:
    import pcap

have_pypcap = False
# See Jira issue TSW-13
#try:
#    import pcap
#    if hasattr(pcap, "pcap"):
#        # the incompatible pylibpcap library masquerades as pcap
#        have_pypcap = True
#except:
#    pass

def match_exp_pkt(exp_pkt, pkt):
    """
    Compare the string value of pkt with the string value of exp_pkt,
    and return True iff they are identical.  If the length of exp_pkt is
    less than the minimum Ethernet frame size (60 bytes), then padding
    bytes in pkt are ignored.
    """
    if isinstance(exp_pkt, mask.Mask):
        if not exp_pkt.is_valid():
            return False
        return exp_pkt.pkt_match(pkt)
    e = str(exp_pkt)
    p = str(pkt)
    if len(e) < 60:
        p = p[:len(e)]
    return e == p

class DataPlanePortLinux:
    """
    Uses raw sockets to capture and send packets on a network interface.
    """

    RCV_SIZE_DEFAULT = 4096
    ETH_P_ALL = 0x03
    RCV_TIMEOUT = 10000

    def __init__(self, interface_name, device_number, port_number):
        """
        @param interface_name The name of the physical interface like eth1
        """
        self.interface_name = interface_name
        self.socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, 0)
        afpacket.enable_auxdata(self.socket)
        self.socket.bind((interface_name, self.ETH_P_ALL))
        netutils.set_promisc(self.socket, interface_name)
        self.socket.settimeout(self.RCV_TIMEOUT)

    def __del__(self):
        if self.socket:
            self.socket.close()

    def fileno(self):
        """
        Return an integer file descriptor that can be passed to select(2).
        """
        return self.socket.fileno()

    def recv(self):
        """
        Receive a packet from this port.
        @retval (packet data, timestamp)
        """
        pkt = afpacket.recv(self.socket, self.RCV_SIZE_DEFAULT)
        return (pkt, time.time())

    def send(self, packet):
        """
        Send a packet out this port.
        @param packet The packet data to send to the port
        @retval The number of bytes sent
        """
        return self.socket.send(packet)

    def down(self):
        """
        Bring the physical link down.
        """
        os.system("ifconfig down %s" % self.interface_name)

    def up(self):
        """
        Bring the physical link up.
        """
        os.system("ifconfig up %s" % self.interface_name)

class DataPlanePort:
    """
    Uses raw sockets to capture and send packets on a network interface.
    """

    RCV_SIZE_DEFAULT = 4096
    ETH_P_ALL = 0x03
    RCV_TIMEOUT = 10000

    def __init__(self, interface_name, device_number, port_number):
        """
        @param interface_name The name of the physical interface like eth1
        """
        self.interface_name = interface_name
        self.socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                                    socket.htons(self.ETH_P_ALL))
        self.socket.bind((interface_name, 0))
        netutils.set_promisc(self.socket, interface_name)
        self.socket.settimeout(self.RCV_TIMEOUT)

    def __del__(self):
        if self.socket:
            self.socket.close()

    def fileno(self):
        """
        Return an integer file descriptor that can be passed to select(2).
        """
        return self.socket.fileno()

    def recv(self):
        """
        Receive a packet from this port.
        @retval (packet data, timestamp)
        """
        pkt = self.socket.recv(self.RCV_SIZE_DEFAULT)
        return (pkt, time.time())

    def send(self, packet):
        """
        Send a packet out this port.
        @param packet The packet data to send to the port
        @retval The number of bytes sent
        """
        return self.socket.send(packet)

    def down(self):
        """
        Bring the physical link down.
        """
        os.system("ifconfig down %s" % self.interface_name)

    def up(self):
        """
        Bring the physical link up.
        """
        os.system("ifconfig up %s" % self.interface_name)

class DataPlanePortPcap:
    """
    Alternate port implementation using libpcap. This is required for recent
    versions of Linux (such as Linux 3.2 included in Ubuntu 12.04) which
    offload the VLAN tag, so it isn't in the data returned from a read on a raw
    socket. libpcap understands how to read the VLAN tag from the kernel.
    """

    def __init__(self, interface_name, device_number, port_number):
        self.pcap = pcap.pcap(interface_name)
        self.pcap.setnonblock()

    def fileno(self):
        return self.pcap.fileno()

    def recv(self):
        (timestamp, pkt) = next(self.pcap)
        return (pkt[:], timestamp)

    def send(self, packet):
        return self.pcap.inject(packet, len(packet))

    def down(self):
        pass

    def up(self):
        pass

class DataPlane(Thread):
    """
    This class provides methods to send and receive packets on the dataplane.
    It uses the DataPlanePort class, or an alternative implementation of that
    interface, to do IO on a particular port. A background thread is used to
    read packets from the dataplane ports and enqueue them to be read by the
    test. The kill() method must be called to shutdown this thread.
    """

    MAX_QUEUE_LEN = 100

    def __init__(self, config=None):
        Thread.__init__(self)

        # dict from device number, port number to port object
        self.ports = {}

        # dict from device number, port number to list of (timestamp, packet)
        self.packet_queues = {}

        # cvar serves double duty as a regular top level lock and
        # as a condition variable
        self.cvar = Condition()

        # Used to wake up the event loop from another thread
        self.waker = ptfutils.EventDescriptor()
        self.killed = False

        self.logger = logging.getLogger("dataplane")
        self.pcap_writer = None

        if config is None:
            self.config = {}
        else:
            self.config = config;

        ############################################################
        #
        # The platform/config can provide a custom DataPlanePort class
        # here if you have a custom implementation with different
        # behavior.
        #
        # Set config.dataplane.portclass = MyDataPlanePortClass
        # where MyDataPlanePortClass has the same interface as the class
        # DataPlanePort defined here.
        #
        if "dataplane" in self.config and "portclass" in self.config["dataplane"]:
            self.dppclass = self.config["dataplane"]["portclass"]
        elif "linux" in sys.platform:
            self.dppclass = DataPlanePortLinux
        elif have_pypcap:
            self.dppclass = DataPlanePortPcap
        else:
            self.logger.warning("Missing pypcap, VLAN tests may fail. See README for installation instructions.")
            self.dppclass = DataPlanePort

        self.start()

    def run(self):
        """
        Activity function for class
        """
        while not self.killed:
            sockets = [self.waker] + self.ports.values()
            try:
                sel_in, sel_out, sel_err = select.select(sockets, [], [], 1)
            except:
                print sys.exc_info()
                self.logger.error("Select error, exiting")
                break

            with self.cvar:
                for port in sel_in:
                    if port == self.waker:
                        self.waker.wait()
                        continue
                    else:
                        # Enqueue packet
                        pkt, timestamp = port.recv()
                        port_number = port._port_number
                        device_number = port._device_number
                        self.logger.debug("Pkt len %d in on device %d, port %d",
                                          len(pkt), device_number, port_number)
                        if self.pcap_writer:
                            self.pcap_writer.write(pkt, timestamp,
                                                   device_number, port_number)
                        queue = self.packet_queues[(device_number, port_number)]
                        if len(queue) >= self.MAX_QUEUE_LEN:
                            # Queue full, throw away oldest
                            queue.pop(0)
                            self.logger.debug("Discarding oldest packet to make room")
                        queue.append((pkt, timestamp))
                self.cvar.notify_all()

        self.logger.info("Thread exit")

    def port_add(self, interface_name, device_number, port_number):
        """
        Add a port to the dataplane
        @param interface_name The name of the physical interface like eth1
        @param device_number The device id used to refer to the device
        @param port_number The port number used to refer to the port
        Stashes the port number on the created port object.
        """
        port_id = (device_number, port_number)
        self.ports[port_id] = self.dppclass(interface_name,
                                            device_number, port_number)
        self.ports[port_id]._port_number = port_number
        self.ports[port_id]._device_number = device_number
        self.packet_queues[port_id] = []
        # Need to wake up event loop to change the sockets being selected on.
        self.waker.notify()

    def send(self, device_number, port_number, packet):
        """
        Send a packet to the given port
        @param device_number, port_number The port to send the data to
        @param packet Raw packet data to send to port
        """
        self.logger.debug("Sending %d bytes to device %d, port %d" %
                          (len(packet), device_number, port_number))
        if self.pcap_writer:
            self.pcap_writer.write(packet, time.time(),
                                   device_number, port_number)
        bytes = self.ports[(device_number, port_number)].send(packet)
        if bytes != len(packet):
            self.logger.error("Unhandled send error, length mismatch %d != %d" %
                     (bytes, len(packet)))
        return bytes

    def oldest_port_number(self, device):
        """
        Returns the port number with the oldest packet,
        or None if no packets are queued.
        """
        min_port_number = None
        min_time = float('inf')
        for (port_id, queue) in self.packet_queues.items():
            if port_id[0] != device:
                continue
            if queue and queue[0][1] < min_time:
                min_time = queue[0][1]
                min_port_number = port_id[1]
        return min_port_number

    # Dequeues and yields packets in the order they were received.
    # Yields (port, packet, received time).
    # If port is not specified yields packets from all ports.
    def packets(self, device, port=None):
        while True:
            if port is None:
                rcv_port = self.oldest_port_number(device)
            else:
                rcv_port = port

            if rcv_port == None:
                self.logger.debug("Out of packets on all ports")
                break
            queue = self.packet_queues[(device, rcv_port)]

            if len(queue) == 0:
                self.logger.debug("Out of packets on device %d, port %d",
                                  device, rcv_port)
                break

            pkt, time = queue.pop(0)
            yield (rcv_port, pkt, time)

    def poll(self, device_number=0, port_number=None, timeout=-1, exp_pkt=None, filters=[]):
        """
        Poll one or all dataplane ports for a packet

        If port_number is given, get the oldest packet from that port (and for
        that device).
        Otherwise, find the port with the oldest packet and return
        that packet.

        If exp_pkt is true, discard all packets until that one is found

        @param device_number Get packet from this device
        @param port_number If set, get packet from this port
        @param timeout If positive and no packet is available, block
        until a packet is received or for this many seconds
        @param exp_pkt If not None, look for this packet and ignore any
        others received.  Note that if port_number is None, all packets
        from all ports will be discarded until the exp_pkt is found
        @return The tuple device_number, port_number, packet, pkt_time where
        packet is received from device_number, port_number at time pkt_time.  If
        a timeout occurs, return None, None, None, None
        """

        def filter_check(pkt):
            for f in filters:
                if not f(pkt): return False
            return True

        if exp_pkt and (port_number is None):
            self.logger.warn("Dataplane poll with exp_pkt but no port number")

        # Retrieve the packet. Returns (device number, port number, packet, time).
        def grab():
            self.logger.debug("Grabbing packet")
            for (rcv_port_number, pkt, time) in self.packets(device_number, port_number):
                rcv_device_number = device_number
                self.logger.debug("Checking packet from device %d, port %d",
                                  rcv_device_number, rcv_port_number)
                if not filter_check(pkt):
                    self.logger.debug("Paket does not match filter, discarding")
                    continue
                if not exp_pkt or match_exp_pkt(exp_pkt, pkt):
                    return (rcv_device_number, rcv_port_number, pkt, time)
            self.logger.debug("Did not find packet")
            return None

        with self.cvar:
            ret = ptfutils.timed_wait(self.cvar, grab, timeout=timeout)

        if ret != None:
            return ret
        else:
            self.logger.debug("Poll time out, no packet from device %d, port %r",
                              device_number, port_number)
            return (None, None, None, None)

    def kill(self):
        """
        Stop the dataplane thread.
        """
        self.killed = True
        self.waker.notify()
        self.join()
        # Explicitly release ports to ensure we don't run out of sockets
        # even if someone keeps holding a reference to the dataplane.
        del self.ports

    def port_down(self, device_number, port_number):
        """Brings the specified port down"""
        self.ports[(device_number, port_number)].down()

    def port_up(self, device_number, port_number):
        """Brings the specified port up"""
        self.ports[(device_number, port_number)].up()

    def flush(self):
        """
        Drop any queued packets.
        """
        for port_id in self.packet_queues.keys():
            self.packet_queues[port_id] = []

    def start_pcap(self, filename):
        assert(self.pcap_writer == None)
        self.pcap_writer = PcapWriter(filename)

    def stop_pcap(self):
        if self.pcap_writer:
            self.pcap_writer.close()
            self.pcap_writer = None
