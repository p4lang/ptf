# Copyright 2026 Keshav Kumar
# SPDX-License-Identifier: Apache-2.0

import pytest

from bf_pktpy.library.specs.templates.igmp import IGMP

CASES = [
    ("1164eeabe0000001", 0x11, 100, 0xEEAB, "224.0.0.1"),
    ("1100abcde0000016", 0x11, 0, 0xABCD, "224.0.0.22"),
    ("1600000ae000fb01", 0x16, 0, 0x000A, "224.0.251.1"),
    ("1200000aefffff FA".replace(" ", ""), 0x12, 0, 0x000A, "239.255.255.250"),
]


@pytest.mark.parametrize("hex_str, type_, mrcode, chksum, gaddr", CASES)
def test_from_hex_parses_each_field(hex_str, type_, mrcode, chksum, gaddr):
    pkt = IGMP.from_hex(hex_str)

    assert pkt.type == type_
    assert pkt.mrcode == mrcode
    assert pkt.chksum == chksum
    assert pkt.gaddr == gaddr


def test_from_hex_group_address_round_trips():
    pkt = IGMP.from_hex("1164eeabe0000001")
    members = pkt._members()

    assert members["igmp"][3] == ("gaddr", 0xE0000001, 32)
