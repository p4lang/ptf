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
""" DHCP template """
from bf_pktpy.library.specs.base import Base
import ipaddress


# =============================================================================
_options = {
    "pad": (0, 0, ""),
    "subnet_mask": (1, 4, "0.0.0.0"),
    "time_zone": (2, 4, 500),
    "router": (3, 4, "0.0.0.0"),
    "time_server": (4, 4, "0.0.0.0"),
    "IEN_name_server": (5, 4, "0.0.0.0"),
    "name_server": (6, 4, "0.0.0.0"),
    "log_server": (7, 4, "0.0.0.0"),
    "cookie_server": (8, 4, "0.0.0.0"),
    "lpr_server": (9, 4, "0.0.0.0"),
    "impress-servers": (10, 4, "0.0.0.0"),
    "resource-location-servers": (11, 4, "0.0.0.0"),
    "hostname": (12, -1, ""),
    "boot-size": (13, 4, 1000),
    "dump_path": (14, -1, ""),
    "domain": (15, -1, ""),
    "swap-server": (16, 4, "0.0.0.0"),
    "root_disk_path": (17, -1, ""),
    "extensions-path": (18, -1, ""),
    "ip-forwarding": (19, 4, 0),
    "non-local-source-routing": (20, 4, 0),
    "policy-filter": (21, 4, "0.0.0.0"),
    "max_dgram_reass_size": (22, 4, 300),
    "default_ttl": (23, 4, 50),
    "pmtu_timeout": (24, 4, 1000),
    "path-mtu-plateau-table": (25, 4, 1000),
    "interface-mtu": (26, 4, 50),
    "all-subnets-local": (27, 4, 0),
    "broadcast_address": (28, 4, "0.0.0.0"),
    "perform-mask-discovery": (29, 4, 0),
    "mask-supplier": (30, 4, 0),
    "router-discovery": (31, 4, 0),
    "router-solicitation-address": (32, 4, "0.0.0.0"),
    "static-routes": (33, 4, "0.0.0.0"),
    "trailer-encapsulation": (34, 4, 0),
    "arp_cache_timeout": (35, 4, 1000),
    "ieee802-3-encapsulation": (36, 4, 0),
    "tcp_ttl": (37, 4, 100),
    "tcp_keepalive_interval": (38, 4, 1000),
    "tcp_keepalive_garbage": (39, 4, 0),
    "NIS_domain": (40, -1, "www.example.com"),
    "NIS_server": (41, 4, "0.0.0.0"),
    "NTP_server": (42, 4, "0.0.0.0"),
    "vendor_specific": (43, -1, ""),
    "NetBIOS_server": (44, 4, "0.0.0.0"),
    "NetBIOS_dist_server": (45, 4, "0.0.0.0"),
    "NETBIOS_node_type": (46, 4, 100),
    "netbios-scope": (47, -1, ""),
    "font-servers": (48, 4, "0.0.0.0"),
    "x-display-manager": (49, 4, "0.0.0.0"),
    "requested_addr": (50, 4, "0.0.0.0"),
    "lease_time": (51, 4, 43200),
    "dhcp-option-overload": (52, 4, 100),
    "message-type": (53, 1, "_TYPES_"),
    "server_id": (54, 4, "0.0.0.0"),
    "param_req_list": (55, 4, ""),
    "error_message": (56, -1, ""),
    "max_dhcp_size": (57, 4, 1500),
    "renewal_time": (58, 4, 21600),
    "rebinding_time": (59, 4, 37800),
    "vendor_class_id": (60, -1, "id"),
    "client_id": (61, 7, ""),
    "nwip-domain-name": (62, -1, ""),
    "NISplus_domain": (64, -1, ""),
    "NISplus_server": (65, 4, "0.0.0.0"),
    "boot-file-name": (67, -1, ""),
    "mobile-ip-home-agent": (68, 4, "0.0.0.0"),
    "SMTP_server": (69, 4, "0.0.0.0"),
    "POP3_server": (70, 4, "0.0.0.0"),
    "NNTP_server": (71, 4, "0.0.0.0"),
    "WWW_server": (72, 4, "0.0.0.0"),
    "Finger_server": (73, 4, "0.0.0.0"),
    "IRC_server": (74, 4, "0.0.0.0"),
    "StreetTalk_server": (75, 4, "0.0.0.0"),
    "StreetTalk_Dir_Assistance": (76, 4, "0.0.0.0"),
    "slp_service_agent": (78, -1, ""),
    "slp_service_scope": (79, -1, ""),
    "client_FQDN": (81, -1, ""),
    "relay_agent_information": (82, -1, ""),
    "nds-server": (85, 4, "0.0.0.0"),
    "nds-tree-name": (86, -1, ""),
    "nds-context": (87, -1, ""),
    "bcms-controller-namesi": (88, -1, ""),
    "bcms-controller-address": (89, 4, "0.0.0.0"),
    "client-last-transaction-time": (91, -1, 1000),
    "associated-ip": (92, 4, "0.0.0.0"),
    "pxe_client_architecture": (93, -1, ""),
    "pxe_client_network_interface": (94, -1, ""),
    "pxe_client_machine_identifier": (97, -1, ""),
    "uap-servers": (98, -1, ""),
    "pcode": (100, -1, ""),
    "tcode": (101, -1, ""),
    "netinfo-server-address": (112, 4, "0.0.0.0"),
    "netinfo-server-tag": (113, -1, ""),
    "default-url": (114, -1, ""),
    "auto-config": (116, 4, 0),
    "name-service-search": (117, 4, 0),
    "subnet-selection": (118, 4, "0.0.0.0"),
    "vendor_class": (124, -1, ""),
    "vendor_specific_information": (125, -1, ""),
    "pana-agent": (136, 4, "0.0.0.0"),
    "v4-lost": (137, -1, ""),
    "capwap-ac-v4": (138, 4, "0.0.0.0"),
    "sip_ua_service_domains": (141, -1, ""),
    "rdnss-selection": (146, -1, ""),
    "v4-portparams": (159, -1, ""),
    "v4-captive-portal": (160, -1, ""),
    "pxelinux_magic": (208, -1, ""),
    "pxelinux_configuration_file": (209, -1, ""),
    "pxelinux_path_prefix": (210, -1, ""),
    "pxelinux_reboot_time": (211, -1, ""),
    "option-6rd": (212, -1, ""),
    "v4-access-domain": (213, -1, ""),
    "end": (255, -1, -1),
}

_types = {
    "discover": 1,
    "offer": 2,
    "request": 3,
    "decline": 4,
    "ack": 5,
    "nak": 6,
    "release": 7,
    "inform": 8,
    "force_renew": 9,
    "lease_query": 10,
    "lease_unassigned": 11,
    "lease_unknown": 12,
    "lease_active": 13,
}


class DHCP(Base):
    """DHCP class
    Definition:
        DHCP
            options                 (int)
        Examples:
            | + create
            |     dhcp = DHCP(options=..)
            |
    """

    name = "DHCP"

    def __init__(self, **kwargs):
        Base._prepare_kwargs(kwargs)

        super(DHCP, self).__init__()
        opts = kwargs.pop("options")
        key, value = "", ""
        self.options = ""
        if opts and isinstance(opts, list):
            for opt in opts:
                if isinstance(opt, tuple) and len(opt) == 2:
                    key, value = opt
                elif isinstance(opt, str):
                    key = opt
                else:
                    raise ValueError("Invalid type %r", type(opt))
                opt_val, opt_len, opt_def = _options.get(key)
                hex_str = hex(opt_val)[2:]
                if hex_str == "ff":
                    self.options += hex_str
                    continue
                if opt_def == "_TYPES_":
                    len_ = hex(opt_len)[2:].zfill(2)
                    type_ = _types.get(value)
                    hex_str += len_ + hex(type_)[2:].zfill(2)
                else:
                    if opt_len == -1:
                        len_ = hex(len(value))[2:]
                        len_ = len_.zfill(len(len_) + len(len_) % 2)
                    else:
                        len_ = hex(opt_len)[2:].zfill(2)
                        if opt_len == 7 and ":" in value:
                            hex_str += len_ + "01" + value.replace(":", "")
                        else:
                            len_ = hex(opt_len)[2:].zfill(2)
                            if isinstance(value, str) and "." in value:
                                # ipv4 address
                                value = int(ipaddress.IPv4Address(value))
                                value = hex(value)[2:].zfill(8)
                            else:
                                value = hex(value)[2:]
                            hex_str += len_ + value
                self.options += hex_str

        if kwargs:
            raise ValueError("Unsupported key(s) %s" % list(kwargs.keys()))

    def _members(self):
        """Member information"""
        value = eval("0x" + self.options)
        len_ = len(self.options)
        members = (("options", value, len_),)
        return {"dhcp": members}


# =============================================================================
