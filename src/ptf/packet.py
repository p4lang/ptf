# Distributed under the OpenFlow Software License (see LICENSE)
# Copyright (c) 2010 The Board of Trustees of The Leland Stanford Junior University
# Copyright (c) 2012, 2013 Big Switch Networks, Inc.
"""
Wrap scapy to satisfy pylint
"""
import ptf
from ptf import config
import sys
import logging

try:
    import scapy.config
    import scapy.route
    import scapy.layers.l2
    import scapy.layers.inet
    import scapy.layers.dhcp
    import scapy.packet
    import scapy.main
    if not config.get("disable_ipv6", False):
        import scapy.route6
        import scapy.layers.inet6
except ImportError:
    sys.exit("Need to install scapy for packet parsing")

Ether = scapy.layers.l2.Ether
LLC = scapy.layers.l2.LLC
SNAP = scapy.layers.l2.SNAP
Dot1Q = scapy.layers.l2.Dot1Q
GRE = scapy.layers.l2.GRE
IP = scapy.layers.inet.IP
IPOption = scapy.layers.inet.IPOption
try:
    ARP = scapy.layers.inet.ARP
except AttributeError:
    # Works with more recent versions of Scapy
    ARP = scapy.layers.l2.ARP
TCP = scapy.layers.inet.TCP
UDP = scapy.layers.inet.UDP
ICMP = scapy.layers.inet.ICMP
DHCP = scapy.layers.dhcp.DHCP
BOOTP = scapy.layers.dhcp.BOOTP
PADDING = scapy.packet.Padding

if not config.get("disable_ipv6", False):
    IPv6 = scapy.layers.inet6.IPv6
    IPv6ExtHdrRouting = scapy.layers.inet6.IPv6ExtHdrRouting
    ICMPv6Unknown = scapy.layers.inet6.ICMPv6Unknown
    ICMPv6EchoRequest = scapy.layers.inet6.ICMPv6EchoRequest

VXLAN = None
if not config.get("disable_vxlan", False):
    try:
        ptf.disable_logging()
        scapy.main.load_contrib("vxlan")
        VXLAN = scapy.contrib.vxlan.VXLAN
        ptf.enable_logging()
        logging.info("VXLAN support found in Scapy")
    except:
        ptf.enable_logging()
        logging.warn("VXLAN support not found in Scapy")
        pass

ERSPAN = None
ERSPAN_III = None
PlatformSpecific = None
if not config.get("disable_erspan", False):
    try:
        ptf.disable_logging()
        scapy.main.load_contrib("erspan")
        ERSPAN = scapy.contrib.erspan.ERSPAN
        ERSPAN_III = scapy.contrib.erspan.ERSPAN_III
        PlatformSpecific = scapy.contrib.erspan.PlatformSpecific
        ptf.enable_logging()
        logging.info("ERSPAN support found in Scapy")
    except:
        ptf.enable_logging()
        logging.warn("ERSPAN support not found in Scapy")
        pass

GENEVE = None
if not config.get("disable_geneve", False):
    try:
        ptf.disable_logging()
        scapy.main.load_contrib("geneve")
        GENEVE = scapy.contrib.geneve.GENEVE
        ptf.enable_logging()
        logging.info("GENEVE support found in Scapy")
    except:
        ptf.enable_logging()
        logging.warn("GENEVE support not found in Scapy")
        pass

MPLS = None
if not config.get("disable_mpls", False):
    try:
        ptf.disable_logging()
        scapy.main.load_contrib("mpls")
        MPLS = scapy.contrib.mpls.MPLS
        ptf.enable_logging()
        logging.info("MPLS support found in Scapy")
    except:
        ptf.enable_logging()
        logging.warn("MPLS support not found in Scapy")
        pass

NVGRE = None
if not config.get("disable_nvgre", False):
    try:
        ptf.disable_logging()
        scapy.main.load_contrib("nvgre")
        NVGRE = scapy.contrib.nvgre.NVGRE
        ptf.enable_logging()
        logging.info("NVGRE support found in Scapy")
    except:
        ptf.enable_logging()
        logging.warn("NVGRE support not found in Scapy")
        pass

IGMP = None
if not config.get("disable_igmp", False):
    try:
        ptf.disable_logging()
        scapy.main.load_contrib("igmp")
        IGMP = scapy.contrib.igmp.IGMP
        ptf.enable_logging()
        logging.info("IGMP support found in Scapy")
    except:
        ptf.enable_logging()
        logging.warn("IGMP support not found in Scapy")
        pass