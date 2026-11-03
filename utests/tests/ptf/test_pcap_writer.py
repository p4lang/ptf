# Copyright 2026 Keshav Kumar
# SPDX-License-Identifier: Apache-2.0

import pytest

from ptf.pcap_writer import LINKTYPE_ETHERNET, PcapWriter, rdpcap

PKT_A = b"\xde\xad\xbe\xef" * 8
PKT_B = b"\x01\x02\x03\x04" * 4


@pytest.fixture
def pcap_path(tmp_path):
    return str(tmp_path / "test.pcap")


def write_pcap(path, packets):
    writer = PcapWriter(path, linktype=LINKTYPE_ETHERNET)
    for data, timestamp in packets:
        writer.write(data, timestamp)
    writer.close()


def test_rdpcap_returns_packet_data(pcap_path):
    write_pcap(pcap_path, [(PKT_A, 1.5), (PKT_B, 2.25)])

    assert rdpcap(pcap_path) == [PKT_A, PKT_B]


def test_rdpcap_returns_metadata(pcap_path):
    write_pcap(pcap_path, [(PKT_A, 1.5), (PKT_B, 2.25)])

    pkts = rdpcap(pcap_path, return_packet_metadata=True)

    assert pkts == [
        {"timestamp": 1.5, "length": len(PKT_A), "pkt_data": PKT_A},
        {"timestamp": 2.25, "length": len(PKT_B), "pkt_data": PKT_B},
    ]


def test_rdpcap_on_file_without_packets(pcap_path):
    write_pcap(pcap_path, [])

    assert rdpcap(pcap_path) == []
    assert rdpcap(pcap_path, return_packet_metadata=True) == []
