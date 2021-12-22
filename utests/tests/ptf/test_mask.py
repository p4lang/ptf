from ptf.mask import Mask
from ptf.packet_scapy import VXLAN, Ether, IP, TCP
from ptf.testutils import simple_vxlan_packet


class TestMask:
    def test_mask__mask_simple_packet(self):
        packet = Ether() / IP() / TCP()
        mask_packet = Mask(packet)
        assert mask_packet.pkt_match(packet)

        modified_packet = Ether() / IP() / TCP(sport=97)
        assert not mask_packet.pkt_match(modified_packet)

        # try to mask only sport (still packet will be diffrent on chksum!)
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
