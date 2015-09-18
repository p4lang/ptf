import sys
import copy
import logging
import types
import time
import re
import packet as scapy

import ptf
import ptf.dataplane
import ptf.parse
import ptf.ptfutils

global skipped_test_count
skipped_test_count = 0

_import_blacklist = set(locals().keys())

# Some useful defines
IP_ETHERTYPE = 0x800
TCP_PROTOCOL = 0x6
UDP_PROTOCOL = 0x11

MINSIZE = 0

FILTERS = []

def reset_filters():
    FILTERS = []

# Needs to be a callable
def add_filter(my_filter):
    FILTERS.append(my_filter)

def get_filters():
    return FILTERS

def ether_filter(pkt_str):
    try:
        pkt = scapy.Ether(pkt_str)
        return True
    except:
        return False

def ipv6_filter(pkt_str):
    try:
        pkt = scapy.Ether(pkt_str)
        return (scapy.IPv6 in pkt)
    except:
        return False

def not_ipv6_filter(pkt_str):
    return not ipv6_filter(pkt_str)

def simple_tcp_packet(pktlen=100,
                      eth_dst='00:01:02:03:04:05',
                      eth_src='00:06:07:08:09:0a',
                      dl_vlan_enable=False,
                      vlan_vid=0,
                      vlan_pcp=0,
                      dl_vlan_cfi=0,
                      ip_src='192.168.0.1',
                      ip_dst='192.168.0.2',
                      ip_tos=0,
                      ip_ttl=64,
                      ip_id=0x0001,
                      tcp_sport=1234,
                      tcp_dport=80,
                      tcp_flags="S",
                      ip_ihl=None,
                      ip_options=False,
                      with_tcp_chksum=True
                      ):
    """
    Return a simple dataplane TCP packet

    Supports a few parameters:
    @param len Length of packet in bytes w/o CRC
    @param eth_dst Destinatino MAC
    @param eth_src Source MAC
    @param dl_vlan_enable True if the packet is with vlan, False otherwise
    @param vlan_vid VLAN ID
    @param vlan_pcp VLAN priority
    @param ip_src IP source
    @param ip_dst IP destination
    @param ip_tos IP ToS
    @param ip_ttl IP TTL
    @param ip_id IP ID
    @param tcp_dport TCP destination port
    @param tcp_sport TCP source port
    @param tcp_flags TCP Control flags  	
    @param with_tcp_chksum Valid TCP checksum

    Generates a simple TCP request.  Users
    shouldn't assume anything about this packet other than that
    it is a valid ethernet/IP/TCP frame.
    """

    if MINSIZE > pktlen:
        pktlen = MINSIZE

    if with_tcp_chksum:
        tcp_hdr = scapy.TCP(sport=tcp_sport, dport=tcp_dport, flags=tcp_flags)
    else:
        tcp_hdr = scapy.TCP(sport=tcp_sport, dport=tcp_dport, flags=tcp_flags, chksum=0)

    # Note Dot1Q.id is really CFI
    if (dl_vlan_enable):
        pkt = scapy.Ether(dst=eth_dst, src=eth_src)/ \
            scapy.Dot1Q(prio=vlan_pcp, id=dl_vlan_cfi, vlan=vlan_vid)/ \
            scapy.IP(src=ip_src, dst=ip_dst, tos=ip_tos, ttl=ip_ttl, id=ip_id, ihl=ip_ihl)/ \
            tcp_hdr
    else:
        if not ip_options:
            pkt = scapy.Ether(dst=eth_dst, src=eth_src)/ \
                scapy.IP(src=ip_src, dst=ip_dst, tos=ip_tos, ttl=ip_ttl, id=ip_id, ihl=ip_ihl)/ \
                tcp_hdr
        else:
            pkt = scapy.Ether(dst=eth_dst, src=eth_src)/ \
                scapy.IP(src=ip_src, dst=ip_dst, tos=ip_tos, ttl=ip_ttl, id=ip_id, ihl=ip_ihl, options=ip_options)/ \
                tcp_hdr

    pkt = pkt/("".join([chr(x) for x in xrange(pktlen - len(pkt))]))

    return pkt

def simple_tcpv6_packet(pktlen=100,
                        eth_dst='00:01:02:03:04:05',
                        eth_src='00:06:07:08:09:0a',
                        dl_vlan_enable=False,
                        vlan_vid=0,
                        vlan_pcp=0,
                        ipv6_src='2001:db8:85a3::8a2e:370:7334',
                        ipv6_dst='2001:db8:85a3::8a2e:370:7335',
                        ipv6_tc=0,
                        ipv6_hlim=64,
                        ipv6_fl=0,
                        tcp_sport=1234,
                        tcp_dport=80,
                        tcp_flags="S"):
    """
    Return a simple IPv6/TCP packet

    Supports a few parameters:
    @param len Length of packet in bytes w/o CRC
    @param eth_dst Destination MAC
    @param eth_src Source MAC
    @param dl_vlan_enable True if the packet is with vlan, False otherwise
    @param vlan_vid VLAN ID
    @param vlan_pcp VLAN priority
    @param ipv6_src IPv6 source
    @param ipv6_dst IPv6 destination
    @param ipv6_tc IPv6 traffic class
    @param ipv6_ttl IPv6 hop limit
    @param ipv6_fl IPv6 flow label
    @param tcp_dport TCP destination port
    @param tcp_sport TCP source port
    @param tcp_flags TCP Control flags

    Generates a simple TCP request. Users shouldn't assume anything about this
    packet other than that it is a valid ethernet/IPv6/TCP frame.
    """

    if MINSIZE > pktlen:
        pktlen = MINSIZE

    pkt = scapy.Ether(dst=eth_dst, src=eth_src)
    if dl_vlan_enable or vlan_vid or vlan_pcp:
        pkt /= scapy.Dot1Q(vlan=vlan_vid, prio=vlan_pcp)
    pkt /= scapy.IPv6(src=ipv6_src, dst=ipv6_dst, fl=ipv6_fl, tc=ipv6_tc, hlim=ipv6_hlim)
    pkt /= scapy.TCP(sport=tcp_sport, dport=tcp_dport, flags=tcp_flags)
    pkt /= ("D" * (pktlen - len(pkt)))

    return pkt

def simple_udp_packet(pktlen=100,
                      eth_dst='00:01:02:03:04:05',
                      eth_src='00:06:07:08:09:0a',
                      dl_vlan_enable=False,
                      vlan_vid=0,
                      vlan_pcp=0,
                      dl_vlan_cfi=0,
                      ip_src='192.168.0.1',
                      ip_dst='192.168.0.2',
                      ip_tos=0,
                      ip_ttl=64,
                      udp_sport=1234,
                      udp_dport=80,
                      ip_ihl=None,
                      ip_options=False,
                      with_udp_chksum=True
                      ):
    """
    Return a simple dataplane UDP packet

    Supports a few parameters:
    @param len Length of packet in bytes w/o CRC
    @param eth_dst Destination MAC
    @param eth_src Source MAC
    @param dl_vlan_enable True if the packet is with vlan, False otherwise
    @param vlan_vid VLAN ID
    @param vlan_pcp VLAN priority
    @param ip_src IP source
    @param ip_dst IP destination
    @param ip_tos IP ToS
    @param ip_ttl IP TTL
    @param udp_dport UDP destination port
    @param udp_sport UDP source port
    @param with_udp_chksum Valid UDP checksum

    Generates a simple UDP packet. Users shouldn't assume anything about
    this packet other than that it is a valid ethernet/IP/UDP frame.
    """

    if MINSIZE > pktlen:
        pktlen = MINSIZE

    if with_udp_chksum:
        udp_hdr = scapy.UDP(sport=udp_sport, dport=udp_dport)
    else:
        udp_hdr = scapy.UDP(sport=udp_sport, dport=udp_dport, chksum=0)

    # Note Dot1Q.id is really CFI
    if (dl_vlan_enable):
        pkt = scapy.Ether(dst=eth_dst, src=eth_src)/ \
            scapy.Dot1Q(prio=vlan_pcp, id=dl_vlan_cfi, vlan=vlan_vid)/ \
            scapy.IP(src=ip_src, dst=ip_dst, tos=ip_tos, ttl=ip_ttl, ihl=ip_ihl)/ \
            udp_hdr
    else:
        if not ip_options:
            pkt = scapy.Ether(dst=eth_dst, src=eth_src)/ \
                scapy.IP(src=ip_src, dst=ip_dst, tos=ip_tos, ttl=ip_ttl, ihl=ip_ihl)/ \
                udp_hdr
        else:
            pkt = scapy.Ether(dst=eth_dst, src=eth_src)/ \
                scapy.IP(src=ip_src, dst=ip_dst, tos=ip_tos, ttl=ip_ttl, ihl=ip_ihl, options=ip_options)/ \
                udp_hdr

    pkt = pkt/("".join([chr(x) for x in xrange(pktlen - len(pkt))]))

    return pkt

def simple_geneve_packet(pktlen=300,
                        eth_dst='00:01:02:03:04:05',
                        eth_src='00:06:07:08:09:0a',
                        dl_vlan_enable=False,
                        vlan_vid=0,
                        vlan_pcp=0,
                        dl_vlan_cfi=0,
                        ip_src='192.168.0.1',
                        ip_dst='192.168.0.2',
                        ip_tos=0,
                        ip_ttl=64,
                        ip_id=0x0001,
                        udp_sport=1234,
                        with_udp_chksum=True,
                        ip_ihl=None,
                        ip_options=False,
			            geneve_ver=0x0,
                        geneve_reserved = 0x0,
                        geneve_vni=0x1234,
			            geneve_reserved2=0x0,
                        geneve_proto=0x6558,
                        inner_frame = None):
    """
    Return a simple dataplane GENEVE packet

    Supports a few parameters:
    @param len Length of packet in bytes w/o CRC
    @param eth_dst Destination MAC
    @param eth_src Source MAC
    @param dl_vlan_enable True if the packet is with vlan, False otherwise
    @param vlan_vid VLAN ID
    @param vlan_pcp VLAN priority
    @param ip_src IP source
    @param ip_dst IP destination
    @param ip_tos IP ToS
    @param ip_ttl IP TTL
    @param ip_id IP ID
    @param udp_sport UDP source port
    @param geneve_ver version
    @param geneve_reserved reserved field
    @param geneve_vni GENEVE Network Identifier
    @param geneve_reserved2 reserved field
    @param inner_frame The inner Ethernet frame
    """
    if scapy.GENEVE is None:
        logging.error("A GENEVE packet was requested but GENEVE is not supported by your Scapy. See README for more information")
        return None

    udp_dport = 6081 # UDP port assigned by IANA for GENEVE

    if MINSIZE > pktlen:
        pktlen = MINSIZE

    if with_udp_chksum:
        udp_hdr = scapy.UDP(sport=udp_sport, dport=udp_dport)
    else:
        udp_hdr = scapy.UDP(sport=udp_sport, dport=udp_dport, chksum=0)

    # Note Dot1Q.id is really CFI
    if (dl_vlan_enable):
        pkt = scapy.Ether(dst=eth_dst, src=eth_src)/ \
            scapy.Dot1Q(prio=vlan_pcp, id=dl_vlan_cfi, vlan=vlan_vid)/ \
            scapy.IP(src=ip_src, dst=ip_dst, tos=ip_tos, ttl=ip_ttl, id=ip_id, ihl=ip_ihl)/ \
            udp_hdr
    else:
        if not ip_options:
            pkt = scapy.Ether(dst=eth_dst, src=eth_src)/ \
                scapy.IP(src=ip_src, dst=ip_dst, tos=ip_tos, ttl=ip_ttl, id=ip_id, ihl=ip_ihl)/ \
                udp_hdr
        else:
            pkt = scapy.Ether(dst=eth_dst, src=eth_src)/ \
                scapy.IP(src=ip_src, dst=ip_dst, tos=ip_tos, ttl=ip_ttl, id=ip_id, ihl=ip_ihl, options=ip_options)/ \
                udp_hdr

    pkt = pkt / GENEVE(vni = geneve_vni, proto = geneve_proto )

    if inner_frame:
        pkt = pkt / inner_frame
    else:
        pkt = pkt / simple_tcp_packet(pktlen = pktlen - len(pkt))

    return pkt

def simple_nvgre_packet(pktlen=300,
                      eth_dst='00:01:02:03:04:05',
                      eth_src='00:06:07:08:09:0a',
                      dl_vlan_enable=False,
                      vlan_vid=0,
                      vlan_pcp=0,
                      dl_vlan_cfi=0,
                      ip_src='192.168.0.1',
                      ip_dst='192.168.0.2',
                      ip_tos=0,
                      ip_ttl=64,
                      ip_id=0x0001,
                      ip_ihl=None,
                      ip_options=False,
                      nvgre_version=0,
                      nvgre_tni=None,
                      inner_frame=None
                      ):
    """
    Return a simple dataplane GRE packet

    Supports a few parameters:
    @param len Length of packet in bytes w/o CRC
    @param eth_dst Destination MAC
    @param eth_src Source MAC
    @param dl_vlan_enable True if the packet is with vlan, False otherwise
    @param vlan_vid VLAN ID
    @param vlan_pcp VLAN priority
    @param ip_src IP source
    @param ip_dst IP destination
    @param ip_tos IP ToS
    @param ip_ttl IP TTL
    @param ip_id IP ID
    @param nvgre_version Version
    @param nvgre_tni
    @param inner_frame payload of the GRE packet

    Generates a simple GRE packet. Users shouldn't assume anything about
    this packet other than that it is a valid ethernet/IP/NVGRE frame.
    """
    if scapy.NVGRE is None:
        logging.error("A NVGRE packet was requested but NVGRE is not supported by your Scapy. See README for more information")
        return None

    if MINSIZE > pktlen:
        pktlen = MINSIZE

    nvgre_hdr = scapy.NVGRE(vsid=nvgre_tni)

    # Note Dot1Q.id is really CFI
    if (dl_vlan_enable):
        pkt = scapy.Ether(dst=eth_dst, src=eth_src)/ \
            scapy.Dot1Q(prio=vlan_pcp, id=dl_vlan_cfi, vlan=vlan_vid)/ \
            scapy.IP(src=ip_src, dst=ip_dst, tos=ip_tos, ttl=ip_ttl, id=ip_id, ihl=ip_ihl)/ \
            nvgre_hdr
    else:
        if not ip_options:
            pkt = scapy.Ether(dst=eth_dst, src=eth_src)/ \
                scapy.IP(src=ip_src, dst=ip_dst, tos=ip_tos, ttl=ip_ttl, id=ip_id, ihl=ip_ihl)/ \
                nvgre_hdr
        else:
            pkt = scapy.Ether(dst=eth_dst, src=eth_src)/ \
                scapy.IP(src=ip_src, dst=ip_dst, tos=ip_tos, ttl=ip_ttl, id=ip_id, ihl=ip_ihl, options=ip_options)/ \
                nvgre_hdr

    if inner_frame:
        pkt = pkt / inner_frame
    else:
        pkt = pkt / scapy.IP()
        pkt = pkt/("D" * (pktlen - len(pkt)))

    return pkt

def simple_vxlan_packet(pktlen=300,
                        eth_dst='00:01:02:03:04:05',
                        eth_src='00:06:07:08:09:0a',
                        dl_vlan_enable=False,
                        vlan_vid=0,
                        vlan_pcp=0,
                        dl_vlan_cfi=0,
                        ip_src='192.168.0.1',
                        ip_dst='192.168.0.2',
                        ip_tos=0,
                        ip_ttl=64,
                        ip_id=0x0001,
                        udp_sport=1234,
                        with_udp_chksum=True,
                        ip_ihl=None,
                        ip_options=False,
			vxlan_reserved1=0x000000,
                        vxlan_vni = 0xaba,
			vxlan_reserved2=0x00,
                        inner_frame = None):
    """
    Return a simple dataplane VXLAN packet

    Supports a few parameters:
    @param len Length of packet in bytes w/o CRC
    @param eth_dst Destination MAC
    @param eth_src Source MAC
    @param dl_vlan_enable True if the packet is with vlan, False otherwise
    @param vlan_vid VLAN ID
    @param vlan_pcp VLAN priority
    @param ip_src IP source
    @param ip_dst IP destination
    @param ip_tos IP ToS
    @param ip_ttl IP TTL
    @param ip_id IP ID
    @param udp_sport UDP source port
    @param vxlan_reserved1 reserved field (3B)
    @param vxlan_vni VXLAN Network Identifier
    @param vxlan_reserved2 reserved field (1B)
    @param inner_frame The inner Ethernet frame

    Generates a simple VXLAN packet. Users shouldn't assume anything about
    this packet other than that it is a valid ethernet/IP/UDP/VXLAN frame.
    """
    if scapy.VXLAN is None:
        logging.error("A VXLAN packet was requested but VXLAN is not supported by your Scapy. See README for more information")
        return None

    udp_dport = 4789 # UDP port assigned by IANA for VXLAN

    if MINSIZE > pktlen:
        pktlen = MINSIZE

    if with_udp_chksum:
        udp_hdr = scapy.UDP(sport=udp_sport, dport=udp_dport)
    else:
        udp_hdr = scapy.UDP(sport=udp_sport, dport=udp_dport, chksum=0)

    # Note Dot1Q.id is really CFI
    if (dl_vlan_enable):
        pkt = scapy.Ether(dst=eth_dst, src=eth_src)/ \
            scapy.Dot1Q(prio=vlan_pcp, id=dl_vlan_cfi, vlan=vlan_vid)/ \
            scapy.IP(src=ip_src, dst=ip_dst, tos=ip_tos, ttl=ip_ttl, id=ip_id, ihl=ip_ihl)/ \
            udp_hdr
    else:
        if not ip_options:
            pkt = scapy.Ether(dst=eth_dst, src=eth_src)/ \
                scapy.IP(src=ip_src, dst=ip_dst, tos=ip_tos, ttl=ip_ttl, id=ip_id, ihl=ip_ihl)/ \
                udp_hdr
        else:
            pkt = scapy.Ether(dst=eth_dst, src=eth_src)/ \
                scapy.IP(src=ip_src, dst=ip_dst, tos=ip_tos, ttl=ip_ttl, id=ip_id, ihl=ip_ihl, options=ip_options)/ \
                udp_hdr

    pkt = pkt / VXLAN(vni = vxlan_vni, reserved1 = vxlan_reserved1, reserved2 = vxlan_reserved2)

    if inner_frame:
        pkt = pkt / inner_frame
    else:
        pkt = pkt / simple_tcp_packet(pktlen = pktlen - len(pkt))

    return pkt

def simple_gre_packet(pktlen=300,
                      eth_dst='00:01:02:03:04:05',
                      eth_src='00:06:07:08:09:0a',
                      dl_vlan_enable=False,
                      vlan_vid=0,
                      vlan_pcp=0,
                      dl_vlan_cfi=0,
                      ip_src='192.168.0.1',
                      ip_dst='192.168.0.2',
                      ip_tos=0,
                      ip_ttl=64,
                      ip_id=0x0001,
                      ip_ihl=None,
                      ip_options=False,
                      gre_chksum_present=0,
                      gre_routing_present=0, # begin reserved0
                      gre_key_present=0,
                      gre_seqnum_present=0,
                      gre_strict_route_source=0,
                      gre_flags=0, # end reserved0
                      gre_version=0,
                      gre_offset=None, # reserved1
                      gre_key=None,
                      gre_sequence_number=None,
                      inner_frame=None
                      ):
    """
    Return a simple dataplane GRE packet

    Supports a few parameters:
    @param len Length of packet in bytes w/o CRC
    @param eth_dst Destination MAC
    @param eth_src Source MAC
    @param dl_vlan_enable True if the packet is with vlan, False otherwise
    @param vlan_vid VLAN ID
    @param vlan_pcp VLAN priority
    @param ip_src IP source
    @param ip_dst IP destination
    @param ip_tos IP ToS
    @param ip_ttl IP TTL
    @param ip_id IP ID
    @param gre_chkum_present with or without checksum
    @param gre_routing_present
    @param gre_key_present
    @param gre_seqnum_present
    @param gre_strict_route_source
    @param gre_flags
    @param gre_version Version
    @param gre_offset
    @param gre_key
    @param gre_sequence_number
    @param inner_frame payload of the GRE packet

    Generates a simple GRE packet. Users shouldn't assume anything about
    this packet other than that it is a valid ethernet/IP/GRE frame.
    """

    if MINSIZE > pktlen:
        pktlen = MINSIZE

    # proto (ethertype) is set by Scapy based on the payload
    gre_hdr = scapy.GRE(chksum_present=gre_chksum_present,
                        routing_present=gre_routing_present,
                        key_present=gre_key_present,
                        seqnum_present=gre_seqnum_present,
                        strict_route_source=gre_strict_route_source,
                        flags=gre_flags, version=gre_version,
                        offset=gre_offset, key=gre_key,
                        seqence_number=gre_sequence_number) # typo in Scapy

    # Note Dot1Q.id is really CFI
    if (dl_vlan_enable):
        pkt = scapy.Ether(dst=eth_dst, src=eth_src)/ \
            scapy.Dot1Q(prio=vlan_pcp, id=dl_vlan_cfi, vlan=vlan_vid)/ \
            scapy.IP(src=ip_src, dst=ip_dst, tos=ip_tos, ttl=ip_ttl, id=ip_id, ihl=ip_ihl)/ \
            gre_hdr
    else:
        if not ip_options:
            pkt = scapy.Ether(dst=eth_dst, src=eth_src)/ \
                scapy.IP(src=ip_src, dst=ip_dst, tos=ip_tos, ttl=ip_ttl, id=ip_id, ihl=ip_ihl)/ \
                gre_hdr
        else:
            pkt = scapy.Ether(dst=eth_dst, src=eth_src)/ \
                scapy.IP(src=ip_src, dst=ip_dst, tos=ip_tos, ttl=ip_ttl, id=ip_id, ihl=ip_ihl, options=ip_options)/ \
                gre_hdr

    if inner_frame:
        pkt = pkt / inner_frame
    else:
        pkt = pkt / scapy.IP()
        pkt = pkt/("D" * (pktlen - len(pkt)))

    return pkt

def simple_gre_erspan_packet(pktlen=300,
                             eth_dst='00:01:02:03:04:05',
                             eth_src='00:06:07:08:09:0a',
                             dl_vlan_enable=False,
                             vlan_vid=0,
                             vlan_pcp=0,
                             dl_vlan_cfi=0,
                             ip_src='192.168.0.1',
                             ip_dst='192.168.0.2',
                             ip_tos=0,
                             ip_ttl=64,
                             ip_id=0x0001,
                             ip_ihl=None,
                             ip_options=False,
                             gre_chksum_present=0,
                             gre_routing_present=0, # begin reserved0
                             gre_key_present=0,
                             gre_seqnum_present=0,
                             gre_strict_route_source=0,
                             gre_flags=0, # end reserved0
                             gre_version=0,
                             gre_offset=None, # reserved1
                             gre_key=None,
                             gre_sequence_number=None,
                             erspan_vlan=0,
                             erspan_priority=0,
                             erspan_direction=0,
                             erspan_truncated=0,
                             erspan_span_id=0,
                             erspan_unknown7=0,
                             inner_frame=None
                         ):
    """
    Return a simple dataplane GRE/ERSPAN packet

    Supports a few parameters:
    @param len Length of packet in bytes w/o CRC
    @param eth_dst Destination MAC
    @param eth_src Source MAC
    @param dl_vlan_enable True if the packet is with vlan, False otherwise
    @param vlan_vid VLAN ID
    @param vlan_pcp VLAN priority
    @param ip_src IP source
    @param ip_dst IP destination
    @param ip_tos IP ToS
    @param ip_ttl IP TTL
    @param ip_id IP ID
    @param gre_chkum_present with or without checksum
    @param gre_routing_present
    @param gre_key_present
    @param gre_seqnum_present
    @param gre_strict_route_source
    @param gre_flags
    @param gre_version Version
    @param gre_offset
    @param gre_key
    @param gre_sequence_number
    @param inner_frame payload of the GRE packet
    @param erspan_vlan
    @param erspan_priority
    @param erspan_direction
    @param erspan_truncated
    @param erspan_span_id
    @param erspan_unknown7

    Generates a simple GRE/ERSPAN packet. Users shouldn't assume anything about
    this packet other than that it is a valid ethernet/IP/GRE/ERSPAN frame.
    """
    if scapy.GRE is None or scapy.ERSPAN is None:
        logging.error("A GRE/ERSPAN packet was requested but GRE or ERSPAN is not supported by your Scapy. See README for more information")
        return None

    if MINSIZE > pktlen:
        pktlen = MINSIZE

    # proto (ethertype) is set by Scapy based on the payload
    gre_hdr = scapy.GRE(chksum_present=gre_chksum_present,
                        routing_present=gre_routing_present,
                        key_present=gre_key_present,
                        seqnum_present=gre_seqnum_present,
                        strict_route_source=gre_strict_route_source,
                        flags=gre_flags, version=gre_version,
                        offset=gre_offset, key=gre_key,
                        seqence_number=gre_sequence_number) # typo in Scapy

    erspan_hdr = scapy.ERSPAN(vlan = erspan_vlan,
                              priority = erspan_priority,
                              direction = erspan_direction,
                              truncated = erspan_truncated,
                              span_id = erspan_span_id,
                              unknown7 = erspan_unknown7)

    # Note Dot1Q.id is really CFI
    if (dl_vlan_enable):
        pkt = scapy.Ether(dst=eth_dst, src=eth_src)/ \
            scapy.Dot1Q(prio=vlan_pcp, id=dl_vlan_cfi, vlan=vlan_vid)/ \
            scapy.IP(src=ip_src, dst=ip_dst, tos=ip_tos, ttl=ip_ttl, id=ip_id, ihl=ip_ihl)/ \
            gre_hdr / erspan_hdr
    else:
        if not ip_options:
            pkt = scapy.Ether(dst=eth_dst, src=eth_src)/ \
                scapy.IP(src=ip_src, dst=ip_dst, tos=ip_tos, ttl=ip_ttl, id=ip_id, ihl=ip_ihl)/ \
                gre_hdr / erspan_hdr
        else:
            pkt = scapy.Ether(dst=eth_dst, src=eth_src)/ \
                scapy.IP(src=ip_src, dst=ip_dst, tos=ip_tos, ttl=ip_ttl, id=ip_id, ihl=ip_ihl, options=ip_options)/ \
                gre_hdr / erspan_hdr

    if inner_frame:
        pkt = pkt / inner_frame
    else:
        pkt = pkt / scapy.IP()
        pkt = pkt/("D" * (pktlen - len(pkt)))

    return pkt

def ipv4_erspan_pkt(pktlen=350,
                      eth_dst='00:01:02:03:04:05',
                      eth_src='00:06:07:08:09:0a',
                      dl_vlan_enable=False,
                      vlan_vid=0,
                      vlan_pcp=0,
                      dl_vlan_cfi=0,
                      ip_src='192.168.0.1',
                      ip_dst='192.168.0.2',
                      ip_tos=0,
                      ip_ttl=64,
                      ip_id=0x0001,
                      ip_ihl=None,
                      ip_options=False,
                      version=2,
                      mirror_id=0x3FF,
                      inner_frame=None
                      ):
    """
    Return a GRE ERSPAN packet

    Supports a few parameters:
    @param len Length of packet in bytes w/o CRC
    @param eth_dst Destination MAC
    @param eth_src Source MAC
    @param dl_vlan_enable True if the packet is with vlan, False otherwise
    @param vlan_vid VLAN ID
    @param vlan_pcp VLAN priority
    @param ip_src IP source
    @param ip_dst IP destination
    @param ip_tos IP ToS
    @param ip_ttl IP TTL
    @param ip_id IP ID
    @param erspan version
    @param span_id (mirror_session_id)
    @param inner_frame payload of the GRE packet
    """
    if scapy.GRE is None or scapy.ERSPAN is None or scapy.ERSPAN_III is None:
        logging.error("A GRE/ERSPAN packet was requested but GRE or ERSPAN is not supported by your Scapy. See README for more information")
        return None

    if MINSIZE > pktlen:
        pktlen = MINSIZE

    if version == 2:
        erspan_hdr = scapy.GRE(proto=0x22eb)/scapy.ERSPAN_III(span_id=mirror_id)
    else:
        erspan_hdr = scapy.GRE(proto=0x88be)/scapy.ERSPAN(span_id=mirror_id)

    # Note Dot1Q.id is really CFI
    if (dl_vlan_enable):
        pkt = scapy.Ether(dst=eth_dst, src=eth_src)/ \
            scapy.Dot1Q(prio=vlan_pcp, id=dl_vlan_cfi, vlan=vlan_vid)/ \
            scapy.IP(src=ip_src, dst=ip_dst, tos=ip_tos, ttl=ip_ttl, id=ip_id, ihl=ip_ihl)/ \
            erspan_hdr
    else:
        if not ip_options:
            pkt = scapy.Ether(dst=eth_dst, src=eth_src)/ \
                scapy.IP(src=ip_src, dst=ip_dst, tos=ip_tos, ttl=ip_ttl, id=ip_id, ihl=ip_ihl)/ \
                erspan_hdr
        else:
            pkt = scapy.Ether(dst=eth_dst, src=eth_src)/ \
                scapy.IP(src=ip_src, dst=ip_dst, tos=ip_tos, ttl=ip_ttl, id=ip_id, ihl=ip_ihl, options=ip_options)/ \
                erspan_hdr

    if inner_frame:
        pkt = pkt / inner_frame
    else:
        pkt = pkt / scapy.IP()
        pkt = pkt/("D" * (pktlen - len(pkt)))

    return pkt

def simple_udpv6_packet(pktlen=100,
                        eth_dst='00:01:02:03:04:05',
                        eth_src='00:06:07:08:09:0a',
                        dl_vlan_enable=False,
                        vlan_vid=0,
                        vlan_pcp=0,
                        ipv6_src='2001:db8:85a3::8a2e:370:7334',
                        ipv6_dst='2001:db8:85a3::8a2e:370:7335',
                        ipv6_tc=0,
                        ipv6_hlim=64,
                        ipv6_fl=0,
                        udp_sport=1234,
                        udp_dport=80):
    """
    Return a simple IPv6/UDP packet

    Supports a few parameters:
    @param len Length of packet in bytes w/o CRC
    @param eth_dst Destination MAC
    @param eth_src Source MAC
    @param dl_vlan_enable True if the packet is with vlan, False otherwise
    @param vlan_vid VLAN ID
    @param vlan_pcp VLAN priority
    @param ipv6_src IPv6 source
    @param ipv6_dst IPv6 destination
    @param ipv6_tc IPv6 traffic class
    @param ipv6_ttl IPv6 hop limit
    @param ipv6_fl IPv6 flow label
    @param udp_dport UDP destination port
    @param udp_sport UDP source port

    Generates a simple UDP request. Users shouldn't assume anything about this
    packet other than that it is a valid ethernet/IPv6/UDP frame.
    """

    if MINSIZE > pktlen:
        pktlen = MINSIZE

    pkt = scapy.Ether(dst=eth_dst, src=eth_src)
    if dl_vlan_enable or vlan_vid or vlan_pcp:
        pkt /= scapy.Dot1Q(vlan=vlan_vid, prio=vlan_pcp)
    pkt /= scapy.IPv6(src=ipv6_src, dst=ipv6_dst, fl=ipv6_fl, tc=ipv6_tc, hlim=ipv6_hlim)
    pkt /= scapy.UDP(sport=udp_sport, dport=udp_dport)
    pkt /= ("D" * (pktlen - len(pkt)))

    return pkt

def simple_icmp_packet(pktlen=60,
                      eth_dst='00:01:02:03:04:05',
                      eth_src='00:06:07:08:09:0a',
                      dl_vlan_enable=False,
                      vlan_vid=0,
                      vlan_pcp=0,
                      ip_src='192.168.0.1',
                      ip_dst='192.168.0.2',
                      ip_tos=0,
                      ip_ttl=64,
                      ip_id=1,
                      icmp_type=8,
                      icmp_code=0,
                      icmp_data=''):
    """
    Return a simple ICMP packet

    Supports a few parameters:
    @param len Length of packet in bytes w/o CRC
    @param eth_dst Destinatino MAC
    @param eth_src Source MAC
    @param dl_vlan_enable True if the packet is with vlan, False otherwise
    @param vlan_vid VLAN ID
    @param vlan_pcp VLAN priority
    @param ip_src IP source
    @param ip_dst IP destination
    @param ip_tos IP ToS
    @param ip_ttl IP TTL
    @param ip_id IP Identification
    @param icmp_type ICMP type
    @param icmp_code ICMP code
    @param icmp_data ICMP data

    Generates a simple ICMP ECHO REQUEST.  Users
    shouldn't assume anything about this packet other than that
    it is a valid ethernet/ICMP frame.
    """

    if MINSIZE > pktlen:
        pktlen = MINSIZE

    if (dl_vlan_enable):
        pkt = scapy.Ether(dst=eth_dst, src=eth_src)/ \
            scapy.Dot1Q(prio=vlan_pcp, id=0, vlan=vlan_vid)/ \
            scapy.IP(src=ip_src, dst=ip_dst, ttl=ip_ttl, tos=ip_tos, id=ip_id)/ \
            scapy.ICMP(type=icmp_type, code=icmp_code)/ icmp_data
    else:
        pkt = scapy.Ether(dst=eth_dst, src=eth_src)/ \
            scapy.IP(src=ip_src, dst=ip_dst, ttl=ip_ttl, tos=ip_tos, id=ip_id)/ \
            scapy.ICMP(type=icmp_type, code=icmp_code)/ icmp_data

    pkt = pkt/("0" * (pktlen - len(pkt)))

    return pkt

def simple_icmpv6_packet(pktlen=100,
                         eth_dst='00:01:02:03:04:05',
                         eth_src='00:06:07:08:09:0a',
                         dl_vlan_enable=False,
                         vlan_vid=0,
                         vlan_pcp=0,
                         ipv6_src='2001:db8:85a3::8a2e:370:7334',
                         ipv6_dst='2001:db8:85a3::8a2e:370:7335',
                         ipv6_tc=0,
                         ipv6_hlim=64,
                         ipv6_fl=0,
                         icmp_type=8,
                         icmp_code=0):
    """
    Return a simple ICMPv6 packet

    Supports a few parameters:
    @param len Length of packet in bytes w/o CRC
    @param eth_dst Destination MAC
    @param eth_src Source MAC
    @param dl_vlan_enable True if the packet is with vlan, False otherwise
    @param vlan_vid VLAN ID
    @param vlan_pcp VLAN priority
    @param ipv6_src IPv6 source
    @param ipv6_dst IPv6 destination
    @param ipv6_tc IPv6 traffic class
    @param ipv6_ttl IPv6 hop limit
    @param ipv6_fl IPv6 flow label
    @param icmp_type ICMP type
    @param icmp_code ICMP code

    Generates a simple ICMP ECHO REQUEST. Users shouldn't assume anything
    about this packet other than that it is a valid ethernet/IPv6/ICMP frame.
    """

    if MINSIZE > pktlen:
        pktlen = MINSIZE

    pkt = scapy.Ether(dst=eth_dst, src=eth_src)
    if dl_vlan_enable or vlan_vid or vlan_pcp:
        pkt /= scapy.Dot1Q(vlan=vlan_vid, prio=vlan_pcp)
    pkt /= scapy.IPv6(src=ipv6_src, dst=ipv6_dst, fl=ipv6_fl, tc=ipv6_tc, hlim=ipv6_hlim)
    pkt /= scapy.ICMPv6Unknown(type=icmp_type, code=icmp_code)
    pkt /= ("D" * (pktlen - len(pkt)))

    return pkt

def simple_arp_packet(pktlen=60,
                      eth_dst='ff:ff:ff:ff:ff:ff',
                      eth_src='00:06:07:08:09:0a',
                      vlan_vid=0,
                      vlan_pcp=0,
                      arp_op=1,
                      ip_snd='192.168.0.1',
                      ip_tgt='192.168.0.2',
                      hw_snd='00:06:07:08:09:0a',
                      hw_tgt='00:00:00:00:00:00',
                      ):
    """
    Return a simple ARP packet

    Supports a few parameters:
    @param len Length of packet in bytes w/o CRC
    @param eth_dst Destinatino MAC
    @param eth_src Source MAC
    @param arp_op Operation (1=request, 2=reply)
    @param ip_snd Sender IP
    @param ip_tgt Target IP
    @param hw_snd Sender hardware address
    @param hw_tgt Target hardware address

    Generates a simple ARP REQUEST.  Users
    shouldn't assume anything about this packet other than that
    it is a valid ethernet/ARP frame.
    """

    if MINSIZE > pktlen:
        pktlen = MINSIZE

    pkt = scapy.Ether(dst=eth_dst, src=eth_src)
    if vlan_vid or vlan_pcp:
        pkt /= scapy.Dot1Q(vlan=vlan_vid, prio=vlan_pcp)
    pkt /= scapy.ARP(hwsrc=hw_snd, hwdst=hw_tgt, pdst=ip_tgt, psrc=ip_snd, op=arp_op)

    pkt = pkt/("\0" * (pktlen - len(pkt)))

    return pkt

def simple_eth_packet(pktlen=60,
                      eth_dst='00:01:02:03:04:05',
                      eth_src='00:06:07:08:09:0a',
                      eth_type=0x88cc):

    if MINSIZE > pktlen:
        pktlen = MINSIZE

    pkt = scapy.Ether(dst=eth_dst, src=eth_src, type=eth_type)

    pkt = pkt/("0" * (pktlen - len(pkt)))

    return pkt

def simple_ip_packet(pktlen=100,
                     eth_dst='00:01:02:03:04:05',
                     eth_src='00:06:07:08:09:0a',
                     dl_vlan_enable=False,
                     vlan_vid=0,
                     vlan_pcp=0,
                     dl_vlan_cfi=0,
                     ip_src='192.168.0.1',
                     ip_dst='192.168.0.2',
                     ip_tos=0,
                     ip_ttl=64,
                     ip_id=0x0001,
                     ip_ihl=None,
                     ip_options=False
                     ):
    """
    Return a simple dataplane IP packet

    Supports a few parameters:
    @param len Length of packet in bytes w/o CRC
    @param eth_dst Destinatino MAC
    @param eth_src Source MAC
    @param dl_vlan_enable True if the packet is with vlan, False otherwise
    @param vlan_vid VLAN ID
    @param vlan_pcp VLAN priority
    @param ip_src IP source
    @param ip_dst IP destination
    @param ip_tos IP ToS
    @param ip_ttl IP TTL
    @param ip_id IP ID

    Generates a simple IP packet.  Users
    shouldn't assume anything about this packet other than that
    it is a valid ethernet/IP frame.
    """

    if MINSIZE > pktlen:
        pktlen = MINSIZE

    # Note Dot1Q.id is really CFI
    if (dl_vlan_enable):
        pkt = scapy.Ether(dst=eth_dst, src=eth_src)/ \
            scapy.Dot1Q(prio=vlan_pcp, id=dl_vlan_cfi, vlan=vlan_vid)/ \
            scapy.IP(src=ip_src, dst=ip_dst, tos=ip_tos, ttl=ip_ttl, id=ip_id, ihl=ip_ihl)
    else:
        if not ip_options:
            pkt = scapy.Ether(dst=eth_dst, src=eth_src)/ \
                scapy.IP(src=ip_src, dst=ip_dst, tos=ip_tos, ttl=ip_ttl, id=ip_id, ihl=ip_ihl)
        else:
            pkt = scapy.Ether(dst=eth_dst, src=eth_src)/ \
                scapy.IP(src=ip_src, dst=ip_dst, tos=ip_tos, ttl=ip_ttl, id=ip_id, ihl=ip_ihl, options=ip_options)

    pkt = pkt/("".join([chr(x) for x in xrange(pktlen - len(pkt))]))

    return pkt

def simple_ip_only_packet(pktlen=100,
                     ip_src='192.168.0.1',
                     ip_dst='192.168.0.2',
                     ip_tos=0,
                     ip_ttl=64,
                     ip_id=0x0001,
                     ip_ihl=None,
                     ip_options=False,
                     tcp_sport=1234,
                     tcp_dport=80,
                     tcp_flags="S",
                     with_tcp_chksum=True
                     ):
    """
    Return a simple dataplane IP packet

    Supports a few parameters:
    @param len Length of packet in bytes w/o CRC
    @param ip_src IP source
    @param ip_dst IP destination
    @param ip_tos IP ToS
    @param ip_ttl IP TTL
    @param ip_id IP ID

    Generates a simple IP packet.  Users
    shouldn't assume anything about this packet other than that
    it is a valid IP frame.
    """

    if MINSIZE > pktlen:
        pktlen = MINSIZE

    if with_tcp_chksum:
        tcp_hdr = scapy.TCP(sport=tcp_sport, dport=tcp_dport, flags=tcp_flags)
    else:
        tcp_hdr = scapy.TCP(sport=tcp_sport, dport=tcp_dport, flags=tcp_flags, chksum=0)

    if not ip_options:
        pkt = scapy.IP(src=ip_src, dst=ip_dst, tos=ip_tos, ttl=ip_ttl, id=ip_id, ihl=ip_ihl) / tcp_hdr
    else:
        pkt = scapy.IP(src=ip_src, dst=ip_dst, tos=ip_tos, ttl=ip_ttl, id=ip_id, ihl=ip_ihl, options=ip_options) / tcp_hdr

    pkt = pkt/("".join([chr(x) for x in xrange(pktlen - len(pkt))]))

    return pkt

def simple_mpls_packet(pktlen=300,
                       eth_dst='00:01:02:03:04:05',
                       eth_src='00:06:07:08:09:0a',
                       dl_vlan_enable=False,
                       vlan_vid=0,
                       vlan_pcp=0,
                       mpls_type=0x8847,
                       mpls_tags=[],
                       dl_vlan_cfi=0,
                       inner_frame = None):
    """
    Return a simple dataplane MPLS packet

    Supports a few parameters:
    @param len Length of packet in bytes w/o CRC
    @param eth_dst Destination MAC
    @param eth_src Source MAC
    @param dl_vlan_enable True if the packet is with vlan, False otherwise
    @param vlan_vid VLAN ID
    @param vlan_pcp VLAN priority
    @param mpls_tags mpls tag stack
    @param inner_frame The inner frame

    """
    if scapy.MPLS is None:
        logging.error("A MPLS packet was requested but MPLS is not supported by your Scapy. See README for more information")
        return None

    if MINSIZE > pktlen:
        pktlen = MINSIZE

    pkt = scapy.Ether(dst=eth_dst, src=eth_src)
    pkt[Ether].setfieldval('type', mpls_type)

    if (dl_vlan_enable):
        pkt / scapy.Dot1Q(prio=vlan_pcp, id=dl_vlan_cfi, vlan=vlan_vid)
        pkt[Dot1Q].setfieldval('type', mpls_type)

    mpls_tags = list(mpls_tags)
    while len(mpls_tags):
        tag = mpls_tags.pop(0)
        mpls = MPLS()
        if 'label' in tag:
            mpls.label = tag['label']
        if 'tc' in tag:
            mpls.cos = tag['tc']
        if 'ttl' in tag:
            mpls.ttl = tag['ttl']
        if 's' in tag:
            mpls.s = tag['s']
        pkt = pkt / mpls

    if inner_frame:
        pkt = pkt / inner_frame
    else:
        pkt = pkt / simple_tcp_packet(pktlen = pktlen - len(pkt))

    return pkt

def get_egr_list(parent, ports, how_many, exclude_list=[]):
    """
    Generate a list of ports avoiding those in the exclude list
    @param parent Supplies logging
    @param ports List of OF port numbers
    @param how_many Number of ports to be added to the list
    @param exclude_list List of ports not to be used
    @returns An empty list if unable to find enough ports
    """

    if how_many == 0:
        return []

    count = 0
    egr_ports = []
    for egr_idx in range(len(ports)):
        if ports[egr_idx] not in exclude_list:
            egr_ports.append(ports[egr_idx])
            count += 1
            if count >= how_many:
                return egr_ports
    logging.debug("Could not generate enough egress ports for test")
    return []

def test_params_get(default={}):
    """
    Return all the values passed via test-params if present

    @param default Default dictionary to use if no valid params found

    WARNING: TEST PARAMETERS MUST BE PYTHON IDENTIFIERS;
    AND CANNOT START WITH "__";
    eg egr_count, not egr-count.
    """
    test_params = ptf.config["test_params"]
    params_str = "class _TestParams:\n    " + test_params
    try:
        exec params_str
    except:
        return default

    params = {}
    for k, v in vars(_TestParams).items():
        if k[:2] != "__":
            params[k] = v
    return params

def test_param_get(key, default=None):
    """
    Return value passed via test-params if present

    @param key The lookup key
    @param default Default value to use if not found

    WARNING: TEST PARAMETERS MUST BE PYTHON IDENTIFIERS;
    eg egr_count, not egr-count.
    """
    params = test_params_get()

    try:
        return params[key]
    except:
        return default

def format_packet(pkt):
    return "Packet length %d \n%s" % (len(str(pkt)),
                                      hex_dump_buffer(str(pkt)))

def inspect_packet(pkt):
    """
    Wrapper around scapy's show() method.
    @returns A string showing the dissected packet.
    """
    from cStringIO import StringIO
    out = None
    backup = sys.stdout
    try:
        tmp = StringIO()
        sys.stdout = tmp
        pkt.show2()
        out = tmp.getvalue()
        tmp.close()
    finally:
        sys.stdout = backup
    return out

def nonstandard(cls):
    """
    Testcase decorator that marks the test as being non-standard.
    These tests are not automatically added to the "standard" group.
    """
    cls._nonstandard = True
    return cls

def disabled(cls):
    """
    Testcase decorator that marks the test as being disabled.
    These tests are not automatically added to the "standard" group or
    their module's group.
    """
    cls._disabled = True
    return cls

def group(name):
    """
    Testcase decorator that adds the test to a group.
    """
    def fn(cls):
        if not hasattr(cls, "_groups"):
            cls._groups = []
        cls._groups.append(name)
        return cls
    return fn

def ptf_ports(num=None):
    """
    Return a list of 'num' port numbers

    If 'num' is None, return all available ports. Otherwise, limit the length
    of the result to 'num' and raise an exception if not enough ports are
    available.
    """
    ports = sorted(ptf.config["port_map"].keys())
    if num != None and len(ports) < num:
        raise Exception("test requires %d ports but only %d are available" % (num, len(ports)))
    return ports[:num]

def verify_packet(test, pkt, port):
    """
    Check that an expected packet is received
    """
    logging.debug("Checking for pkt on port %r", port)
    (rcv_port, rcv_pkt, pkt_time) = test.dataplane.poll(port_number=port, timeout=2, exp_pkt=pkt, filters=FILTERS)
    test.assertTrue(rcv_pkt != None, "Did not receive pkt on %r" % port)

def verify_no_packet(test, pkt, port):
    """
    Check that a particular packet is not received
    """
    logging.debug("Negative check for pkt on port %r", port)
    (rcv_port, rcv_pkt, pkt_time) = \
        test.dataplane.poll(
            port_number=port, exp_pkt=pkt,
            timeout=ptf.ptfutils.default_negative_timeout,
            filters=FILTERS)
    test.assertTrue(rcv_pkt == None, "Received packet on %r" % port)

def verify_no_other_packets(test):
    """
    Check that no unexpected packets are received

    This is a no-op if the --relax option is in effect.
    """
    if ptf.config["relax"]:
        return
    logging.debug("Checking for unexpected packets on all ports")
    (rcv_port, rcv_pkt, pkt_time) = test.dataplane.poll(timeout=ptf.ptfutils.default_negative_timeout, filters=FILTERS)
    if rcv_pkt != None:
        logging.debug("Received unexpected packet on port %r: %s", rcv_port, format_packet(rcv_pkt))
    test.assertTrue(rcv_pkt == None, "Unexpected packet on port %r" % rcv_port)

def verify_packets(test, pkt, ports):
    """
    Check that a packet is received on each of the specified ports.

    Also verifies that the packet is not received on any other ports, and that no
    other packets are received (unless --relax is in effect).

    This covers the common and simplest cases for checking dataplane outputs.
    For more complex usage, like multiple different packets being output, or
    multiple packets on the same port, use the primitive verify_packet,
    verify_no_packet, and verify_no_other_packets functions directly.
    """
    for port in ptf_ports():
        if port in ports:
            verify_packet(test, pkt, port)
        else:
            verify_no_packet(test, pkt, port)
    verify_no_other_packets(test)

def verify_packets_any(test, pkt, ports):
    """
    Check that a packet is received on _any_ of the specified ports.

    Also verifies that the packet is ot received on any other ports, and that no
    other packets are received (unless --relax is in effect).
    """
    received = False
    for port in ptf_ports():
        if port in ports:
            logging.debug("Checking for pkt on port %r", port)
            print 'verifying packet on port {0}'.format(port)
            (rcv_port, rcv_pkt, pkt_time) = test.dataplane.poll(port_number=port, exp_pkt=pkt, filters=FILTERS)
            if rcv_pkt != None:
                received = True
        else:
            verify_no_packet(test, pkt, port)
    verify_no_other_packets(test)

    test.assertTrue(received == True, "Did not receive pkt on any of ports %r" % ports)

__all__ = list(set(locals()) - _import_blacklist)
