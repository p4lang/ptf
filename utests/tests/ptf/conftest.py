import pytest

from ptf.packet import Ether, IP, UDP, TCP, VXLAN, Packet


@pytest.fixture
def pktmanip_simple_tcp_packet():  # type: () -> Packet
    return (
        Ether(
            dst="00:01:02:03:04:05",
            src="00:06:07:08:09:0a",
        )
        / IP(src="192.168.0.1", dst="192.168.0.2")
        / TCP(sport=1234, dport=80)
    )


@pytest.fixture
def pktmanip_simple_vxlan_packet():  # type: () -> Packet
    return (
        Ether(
            dst="00:01:02:03:04:05",
            src="00:06:07:08:09:0a",
        )
        / IP(src="192.168.0.1", dst="192.168.0.2")
        / UDP()
        / VXLAN()
        / Ether(
            dst="00:01:02:03:04:05",
            src="00:06:07:08:09:0a",
        )
        / IP(src="192.168.0.1", dst="192.168.0.2")
        / TCP(sport=1234, dport=80)
    )
