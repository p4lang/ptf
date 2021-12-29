import pytest

from ptf.mask import Mask, MaskException
from ptf.packet_scapy import VXLAN, Ether, IP, TCP, UDP, Packet
from ptf.testutils import simple_vxlan_packet, simple_ip_packet


class TestMask:
    def test_mask__mask_simple_packet(self):
        packet = Ether() / IP() / TCP()
        mask_packet = Mask(packet)
        assert mask_packet.pkt_match(packet)

        modified_packet = Ether() / IP() / TCP(sport=97)
        assert not mask_packet.pkt_match(modified_packet)

        # try to mask only sport (still packet will be different on chksum!)
        mask_packet.set_do_not_care_packet(TCP, "sport")
        assert not mask_packet.pkt_match(modified_packet)

        mask_packet.set_do_not_care_packet(TCP, "chksum")
        assert mask_packet.pkt_match(modified_packet)

    def test_mask__set_do_not_care(self):
        expected_packet = "\x01\x02\x03\x04\x05\x06"
        packet = "\x01\x00\x00\x04\x05\x06\x07\x08"
        mask = Mask(expected_packet.encode(), ignore_extra_bytes=True)
        mask.set_do_not_care(8, 16)
        assert mask.pkt_match(packet.encode())

    def test_mask__check_masking_conditional_field(self):
        simple_vxlan = simple_vxlan_packet(vxlan_flags="G")
        masked_simple_vxlan = Mask(simple_vxlan)
        masked_simple_vxlan.set_do_not_care_packet(VXLAN, "gpid")  # gpflags, gpid

        second_masked_packet = Mask(simple_vxlan)
        second_masked_packet.set_do_not_care_packet(VXLAN, "gpflags")

        assert (
            masked_simple_vxlan.mask != second_masked_packet.mask
        ), "Masks should not be equal"

    def test_mask__mask_has_problem_with_conditional_fields(self):
        pkt = VXLAN(flags=0x80, gpflags=0x23, gpid=0x1234, vni=0x1337)
        mask_pkt = Mask(pkt)
        mask_pkt.set_do_not_care_packet(VXLAN, "gpid")

        assert mask_pkt.mask == [
            255,
            255,
            0,
            0,
            255,
            255,
            255,
            255,
        ], "Only gpid field should be masked"

    def test_mask__conditional_field__gpid_should_be_masked_correctly(self):
        masked_simple_vxlan = Mask(simple_vxlan_packet(vxlan_flags="G"))  # type: Mask
        masked_simple_vxlan.set_do_not_care_packet(VXLAN, "gpid")
        # UDP chksum will be different when we change VXLAN
        masked_simple_vxlan.set_do_not_care_packet(UDP, "chksum")

        packet_wth_custom_gpid = simple_vxlan_packet(vxlan_flags="G")  # type: Packet
        packet_wth_custom_gpid[VXLAN].gpid = 0x15  # 21

        assert masked_simple_vxlan.pkt_match(
            packet_wth_custom_gpid
        ), "Packets should match"

    @pytest.mark.parametrize(
        "elements_to_ignore", ((UDP, "sport"), (IP, "not_existing_field"))
    )
    def test_mask__negative__try_to_mask_not_existing_layer_or_field(
        self, elements_to_ignore
    ):
        simple_packet = simple_ip_packet()  # type: Packet
        masked_packet = Mask(simple_packet)  # type: Mask
        with pytest.raises(MaskException):
            masked_packet.set_do_not_care_packet(
                elements_to_ignore[0], elements_to_ignore[1]
            )
        assert not masked_packet.valid

    def test_mask__validate_str_conversion(self):
        masked_packet = Mask(simple_vxlan_packet())  # type: Mask
        assert str(masked_packet) == EXPECTED_MASKED_PACKET


EXPECTED_MASKED_PACKET = """
packet:
0000  00 01 02 03 04 05 00 06 07 08 09 0A 08 00 45 00  ..............E.
0010  01 1E 00 01 00 00 40 11 F8 7A C0 A8 00 01 C0 A8  ......@..z......
0020  00 02 04 D2 12 B5 01 0A 07 06 08 00 00 00 00 0A  ................
0030  BA 00 00 01 02 03 04 05 00 06 07 08 09 0A 08 00  ................
0040  45 00 00 EC 00 01 00 00 40 06 F8 B7 C0 A8 00 01  E.......@.......
0050  C0 A8 00 02 04 D2 00 50 00 00 00 00 00 00 00 00  .......P........
0060  50 02 20 00 C0 FF 00 00 00 01 02 03 04 05 06 07  P. .............
0070  08 09 0A 0B 0C 0D 0E 0F 10 11 12 13 14 15 16 17  ................
0080  18 19 1A 1B 1C 1D 1E 1F 20 21 22 23 24 25 26 27  ........ !"#$%&'
0090  28 29 2A 2B 2C 2D 2E 2F 30 31 32 33 34 35 36 37  ()*+,-./01234567
00a0  38 39 3A 3B 3C 3D 3E 3F 40 41 42 43 44 45 46 47  89:;<=>?@ABCDEFG
00b0  48 49 4A 4B 4C 4D 4E 4F 50 51 52 53 54 55 56 57  HIJKLMNOPQRSTUVW
00c0  58 59 5A 5B 5C 5D 5E 5F 60 61 62 63 64 65 66 67  XYZ[\]^_`abcdefg
00d0  68 69 6A 6B 6C 6D 6E 6F 70 71 72 73 74 75 76 77  hijklmnopqrstuvw
00e0  78 79 7A 7B 7C 7D 7E 7F 80 81 82 83 84 85 86 87  xyz{|}~.........
00f0  88 89 8A 8B 8C 8D 8E 8F 90 91 92 93 94 95 96 97  ................
0100  98 99 9A 9B 9C 9D 9E 9F A0 A1 A2 A3 A4 A5 A6 A7  ................
0110  A8 A9 AA AB AC AD AE AF B0 B1 B2 B3 B4 B5 B6 B7  ................
0120  B8 B9 BA BB BC BD BE BF C0 C1 C2 C3              ............

packet's mask:
0000  FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF  ................
0010  FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF  ................
0020  FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF  ................
0030  FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF  ................
0040  FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF  ................
0050  FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF  ................
0060  FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF  ................
0070  FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF  ................
0080  FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF  ................
0090  FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF  ................
00a0  FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF  ................
00b0  FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF  ................
00c0  FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF  ................
00d0  FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF  ................
00e0  FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF  ................
00f0  FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF  ................
0100  FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF  ................
0110  FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF  ................
0120  FF FF FF FF FF FF FF FF FF FF FF FF              ............
"""
