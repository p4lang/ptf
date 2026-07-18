# Copyright 2021 Nex Sabre
# SPDX-License-Identifier: Apache-2.0

from ptf.testutils import (
    simple_igmp_packet,
    simple_tcp_packet,
    simple_tcpv6_packet,
    simple_udp_packet,
)


def test_simple_igmp_packet__proper_setting_mrtime_mrcode():
    simple_packet = simple_igmp_packet(igmp_mrtime=10)
    assert simple_packet["IGMP"].mrcode == 10


def test_simple_tcp_packets_use_same_default_payload():
    tcp_payload = bytes(simple_tcp_packet()["TCP"].payload)
    tcpv6_payload = bytes(simple_tcpv6_packet()["TCP"].payload)

    assert tcp_payload[: len(tcpv6_payload)] == tcpv6_payload


def test_payload_is_padded_to_packet_length():
    pkt = simple_tcp_packet(pktlen=60, payload=b"abc")

    assert len(pkt) == 60
    assert bytes(pkt["TCP"].payload) == b"abc" + bytes(range(3))


def test_payload_is_truncated_to_packet_length():
    pkt = simple_tcp_packet(pktlen=60, payload=b"a" * 100)

    assert len(pkt) == 60
    assert bytes(pkt["TCP"].payload) == b"a" * 6


def test_protocol_specific_and_generic_payload_are_mutually_exclusive():
    try:
        simple_udp_packet(payload=b"generic", udp_payload=b"legacy")
    except ValueError as error:
        assert str(error) == "Specify either payload or udp_payload, not both"
    else:
        raise AssertionError("Expected conflicting payload arguments to fail")
