#!/usr/bin/env python


# Copyright (c) 2021 Intel Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

###############################################################################
""" bf_pktpy python library """
import socket
import time
from bf_pktpy.library.utils import Interface, Stream, Listener, Decoder
from bf_pktpy.library.utils import Answer, Unanswer, Sniffer, Received
from bf_pktpy.library.utils import BridgeSniff


# =============================================================================
def send(packets, **kwargs):
    """Send packets at layer 3

    Args:
        packets         (list): list of packets
        inter            (int): time in sec between 2 packets (default 0)
        loop             (int): send packet indefinetly (default 0)
        count            (int): number of packets to send (default -1)
        verbose         (bool): verbose mode
        realtime         (int): check pkt was sent before sending next one
        return_packets  (bool): return the sent packets
        socket           (obj): the socket to use
        iface            (str): the interface to send the packets on
    Returns:
        bool: None
    Examples:
        | send(packets)
    """

    inter = kwargs.pop("inter", 0)
    loop = kwargs.pop("loop", 0)
    count = kwargs.pop("count", -1)
    verbose = kwargs.pop("verbose", False)
    realtime = kwargs.pop("realtime", None)
    return_packets = kwargs.pop("return_packets", False)
    sock = kwargs.pop("socket", None)
    iface = kwargs.pop("iface", None)

    if not isinstance(packets, (list, tuple)):
        packets = [packets]

    interface = Interface.select(iface)
    sock_ = sock

    if not sock:
        try:
            sock_ = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        except socket.error:
            print("ERROR- Cannot create a socket")
            raise
    if not kwargs.get("noprint", False) and kwargs.get("verbose", True):
        print("Send %s packet(s)" % len(packets))

    stream = Stream(packets, interface)
    result = stream.send(
        sock_,
        inter=inter,
        loop=loop,
        count=count,
        verbose=verbose,
        realtime=realtime,
        return_packets=return_packets,
    )
    if verbose:
        print(result)

    if not sock:
        sock_.close()
    return result


def sendp(packets, **kwargs):
    """Send packets at layer 2

    Args:
        packets         (list): list of packets
        inter            (int): time in sec between 2 packets (default 0)
        loop             (int): send packet indefinetly (default 0)
        count            (int): number of packets to send (default None=1)
        verbose         (bool): verbose mode
        realtime         (int): check pkt was sent before sending next one
        return_packets  (bool): return the sent packets
        socket           (obj): the socket to use
        iface            (str): the interface to send the packets on
    Returns:
        bool: None
    Examples:
        | send(packets)
    """
    inter = kwargs.pop("inter", 0)
    loop = kwargs.pop("loop", 0)
    count = kwargs.pop("count", -1)
    verbose = kwargs.pop("verbose", False)
    realtime = kwargs.pop("realtime", None)
    return_packets = kwargs.pop("return_packets", False)
    sock = kwargs.pop("socket", None)
    iface = kwargs.pop("iface", None)

    if not isinstance(packets, (list, tuple)):
        packets = [packets]

    interface = Interface.select(iface)
    sock_ = sock

    if not sock:
        try:
            sock_ = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
        except socket.error:
            print("ERROR- Cannot create a socket")
            raise
        sock_.bind((interface, 0))

    if not kwargs.get("noprint", False) and kwargs.get("verbose", True):
        print("Send %s packet(s)" % len(packets))

    stream = Stream(packets, interface)
    result = stream.send(
        sock_,
        inter=inter,
        loop=loop,
        count=count,
        verbose=verbose,
        realtime=realtime,
        return_packets=return_packets,
    )
    if verbose:
        print(result)

    if not sock:
        sock_.close()

    return result


def sr(packets, **kwargs):
    """Send and receive packets at layer 3

    Args:
        packets         (list): list of packets
        promisc         (bool): promiscuous mode
        filter           (int): filter
        iface            (str): the interface to send the packets on
        nofilter         (int): no filter
    Returns:
        tuple: (<ans>, <unans>) objects
    Examples:
        | sr(packets)
    """

    # select interface
    iface = kwargs.pop("iface", None)
    interface = Interface.select(iface)
    kwargs.update({"iface": interface})

    # promisc = kwargs.pop("promisc", False)
    # _filter = kwargs.pop("filter", None)
    # iface = kwargs.pop("iface", None)
    # nofilter = kwargs.pop("nofilter", 0)
    timeout = kwargs.get("timeout", 1)

    # Setup listener
    listener = Listener(interface, **kwargs)
    listener.start(count=kwargs.get("count", 0))

    # Send packets
    if kwargs.get("verbose", True):
        print("Begin emission:")
    send(packets, noprint=True, **kwargs)
    if kwargs.get("verbose", True):
        print("Finish to send %s packet(s)" % len(packets))

    answered, unanswered = Answer(), Unanswer()

    # Receive with expiration
    time.sleep(timeout)
    result = listener.received()
    if not result:
        return None, None

    matches = []
    intf_addr = None
    for packet in packets:
        # check if layer4 is TCP or UDP
        if packet.proto in (6, 17):
            layer4 = packet.body
            matches.append(
                (packet.src, packet.dst, packet.proto, layer4.sport, layer4.dport)
            )
        else:
            matches.append((packet.src, packet.dst, packet.proto))
        if intf_addr is None:
            intf_addr = packet.src

    # look for matching src IP address
    rcvd_pkts = 0
    markers = [1] * len(packets)
    for raw in result:
        decoded = Decoder(raw)
        if decoded.is_protocol("IPv4"):
            layer3 = decoded.layer3
            if layer3.dst == intf_addr:
                rcvd_pkts += 1
            if layer3.proto in (6, 17):
                layer4 = decoded.layer4
                to_match = (
                    layer3.dst,
                    layer3.src,
                    layer3.proto,
                    layer4.dport,
                    layer4.sport,
                )
            else:
                to_match = (layer3.dst, layer3.src, layer3.proto)
            if to_match in matches:
                sent = packets[matches.index(to_match)]
                answered.append((sent, decoded))
                markers[matches.index(to_match)] = 0
    if packets:
        for idx, packet in enumerate(packets):
            if markers[idx]:
                unanswered.append(packet)

    if kwargs.get("verbose", True):
        print(
            "Received %s packets, got %s answered, remaining %s packets"
            % (rcvd_pkts, len(answered), len(unanswered))
        )

    return answered, unanswered


def sr1(packets, **kwargs):
    """Send and receive packet at layer 3. Return only 1st answer"""
    ans, _ = sr(packets, **kwargs)
    if ans:
        return ans[0]
    return None


def srp(packets, **kwargs):
    """Send and receive packet at layer 2

    Args:
        packets         (list): list of packets
        promisc         (bool): promiscuous mode
        filter           (int): filter
        iface            (str): the interface to send the packets on
        nofilter         (int): no filter
    Returns:
        bool: None
    Examples:
        | sr(packet)
    """

    # select interface
    iface = kwargs.pop("iface", None)
    interface = Interface.select(iface)
    kwargs.update({"iface": interface})

    # promisc = kwargs.pop("promisc", False)
    # _filter = kwargs.pop("filter", None)
    # iface = kwargs.pop("iface", None)
    # nofilter = kwargs.pop("nofilter", 0)
    timeout = kwargs.get("timeout", 1)

    # Setup listener
    listener = Listener(interface, **kwargs)
    listener.start(count=kwargs.get("count", 0))

    # Send packet
    if kwargs.get("verbose", True):
        print("Begin emission:")
    sendp(packets, noprint=True, **kwargs)
    if kwargs.get("verbose", True):
        print("Finish to send 1 packet")

    answered, unanswered = Answer(), Unanswer()

    # Receive with expiration
    time.sleep(timeout)
    result = listener.received()
    if not result:
        return None, None
    for raw in result:
        decoded = Decoder(raw)
        answered.append(decoded)
    return answered, unanswered


def srp1(packets, **kwargs):
    """Send and receive packet at layer 2. Return only 1st answer"""
    ans, _ = srp(packets, **kwargs)
    if ans:
        return ans[0]
    return None


def srloop(packets, **kwargs):
    """Send and Receive packets in loop at layer 3"""
    return _loop(sr, packets, **kwargs)


def srploop(packets, **kwargs):
    """Send and Receive packets in loop at layer 2"""
    return _loop(srp, packets, **kwargs)


def _loop(fun, packets, inter=1, count=None, store=True, **kwargs):
    answered, unanswered = [], []
    try:
        while True:
            if count is not None:
                if count == 0:
                    break
                count -= 1

            start = time.time()
            ans, unans = fun(packets, **kwargs)
            if store:
                answered.append(ans)
                unanswered.append(unans)
            t_delta = time.time() - start

            if t_delta < inter:
                time.sleep(inter + t_delta)
    except KeyboardInterrupt:
        pass
    return answered, unanswered


def sniff(*args, **kwargs):
    """Sniff packets
    Args:
        iface            (str): interface or list of interfaces
        filter           (str): BPF filter to apply
        store           (bool): store or discard pkts
        timeout          (int): expire time
        count            (int): number of captured pkts; 0 means infinity
        nofilter         (int): no filter
        prn              (obj): function to apply to each packet
    Returns:
        obj: Received object
    Examples:
        | received = sniff(filter="tcp", count=2, timeout=3)
        | received.summary()
    """
    iface = kwargs.get("iface", None)
    if iface is None:
        interface = Interface.select()
        kwargs.update({"iface": interface})
    sniffer = Sniffer(*args, **kwargs)
    sniffer.start()
    while not sniffer.is_completed():
        time.sleep(0.1)

    received = Received()
    packets = sniffer.received()
    received.extend(packets)
    return received


def bridge_and_sniff(
    if1, if2, xfrm12=None, xfrm21=None, prn=None, L2socket=None, *args, **kwargs
):
    """Forward traffic between interfaces if1 and if2, sniff and return
    the exchanged packets
    Args:
        if1          (str|obj): interface names or opened socket
        if2          (str|obj): interface names or opened socket
        xfrm12           (obj): fn to call when fwd pkt from if1 to if2
        xfrm21           (obj): fn to call when fwd pkt from if2 to if1
        prn              (obj): function to apply to each packet
    Returns:
        obj: Received object
    Examples:
        | received = bridge_and_sniff(...)
        | received.summary()
    """
    kwargs.update(
        {"xfrm12": xfrm12, "xfrm21": xfrm21, "prn": prn, "L2socket": L2socket}
    )
    br_sniff = BridgeSniff(if1, if2, *args, **kwargs)
    br_sniff.start()
    while not br_sniff.is_completed():
        time.sleep(0.1)

    received = Received()
    packets = br_sniff.received()
    received.extend(packets)
    return received


# =============================================================================
