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
""" Interface module """
import socket
import subprocess
from collections import namedtuple

import ipaddress
import netifaces
import psutil

# =============================================================================
Intf = namedtuple("Intf", "name family address netmask broadcast mac")
Stats = namedtuple("Stats", "isup duplex speed mtu")
Route = namedtuple("Route", "name gateway is_default")
Gateway = namedtuple("Gateway", "name mac address")


class Interface:
    """Interface class"""

    @staticmethod
    def get_interfaces():
        """Get interfaces

        Returns:
            list: list[(name, family, address, netmask, broadcast, mac), .]
        Examples:
            | interfaces = get_interfaces()
            |
        """
        interfaces, mac = [], ""
        for name, nics in psutil.net_if_addrs().items():
            mac = ""
            intf = None
            for nic in nics:
                if nic.family == socket.AF_PACKET:
                    mac = nic.address
                if nic.family == socket.AF_INET:
                    intf = nic
            if intf:
                interfaces.append(
                    Intf(
                        name,
                        intf.family,
                        intf.address,
                        intf.netmask,
                        intf.broadcast,
                        mac,
                    )
                )
        return interfaces

    @staticmethod
    def get_interface_names():
        """Get interface names

        Returns:
            list: list[<name>, ...]
        Examples:
            | names = get_interface_names()
            |
        """
        interfaces = Interface.get_interfaces()
        return [each.name for each in interfaces]

    @staticmethod
    def get_interface(name, family=socket.AF_INET):
        """Get interface

        Args:
            name             (str): interface name
            family           (int): ip address family
        Returns:
            tuple: (name, family, address, netmask, broadcast, mac)
        Examples:
            | interface = Interface.get_interface("ens160", socket.AF_INET)
            |
        """
        interfaces = Interface.get_interfaces()
        for each in interfaces:
            if each.name == name and each.family == family:
                return each
        raise ValueError("Unable to find interface %r" % name)

    @staticmethod
    def get_stats(name):
        """Get interface stats

        Args:
            name             (str): interface name
        Returns:
            list: list[(name, type, ipaddr, netmask, broadcast, mac), ...]
        Examples:
            | stats = Interface.get_stats("ens160")
            |
        """
        for name_, stats in psutil.net_if_stats().items():
            if name_ == name:
                return Stats(stats.isup, stats.duplex, stats.speed, stats.mtu)
        return None

    @staticmethod
    def get_routes(name=""):
        """Get routes

        Args:
            name             (str): interface name
        Returns:
            list: list[(name, type, ipaddr, netmask, broadcast, mac), ...]
        Examples:
            | routes = Interface.get_routes("ens160")
            |
        """
        routes = []
        gateways = netifaces.gateways()
        for _, group in gateways.items():
            is_default = False
            if isinstance(group, dict):
                each = list(group.values())[0]
                if len(each) == 3:
                    gateway, name_, is_default = each
                else:
                    gateway, name_ = each
                if name == name_:
                    return [Route(name_, gateway, is_default)]
                routes.append(Route(name_, gateway, is_default))
            if isinstance(group, list):
                for each in group:
                    is_default = False
                    if len(each) == 3:
                        gateway, name_, is_default = each
                    else:
                        gateway, name_ = each
                    if name == name_:
                        return [Route(name_, gateway, is_default)]
                    routes.append(Route(name_, gateway, is_default))
        return routes

    @staticmethod
    def get_gateway(name=""):
        """Get default gateway

        Args:
            name             (str): interface name
        Returns:
            tuple: (name, mac, address) or NoneType if not found
        Examples:
            | gateway = Interface.get_gateway()
            |
        """

        def get_gateway_mac(address):
            subprocess.call("ping -c 1 %s" % address, shell=True)
            proc = subprocess.Popen(
                "arp -n -a | grep %s" % address, stdout=subprocess.PIPE, shell=True
            )
            output = proc.stdout.read()
            for line in output.splitlines():
                text = line.decode("ascii")
                words = text.split()
                if words[0] == address:
                    # linux
                    return words[2]
                if words[0] == "?":
                    # mac
                    return words[3]
            return None

        routes = Interface.get_routes(name)
        if name and not len(routes):
            raise ValueError("Unable to find gateway for interface %r" % name)
        route = routes[0]
        try:
            address = str(ipaddress.IPv4Address(route.gateway))
        except ValueError:
            if name:
                raise ValueError("Unable to gw ip for interface %r" % name)
            address = ""
        if not address:
            routes = Interface.get_routes()
            for route in routes:
                try:
                    address = str(ipaddress.IPv4Address(route.gateway))
                    break
                except ValueError:
                    pass
            if not address:
                return None
        gw_mac = get_gateway_mac(address)
        if gw_mac is None:
            raise ValueError("Unable to get gateway mac")
        return Gateway(route.name, gw_mac, address)

    @staticmethod
    def select(name=""):
        """Look for interface name. Returns name if name provided
        and matched existing interface names. Else, returns
        default interface name

        Args:
            name             (str): interface name
        Returns:
            str: interface name
        Examples:
            | intf_name = Interface.select("ens160")
            |
        """
        if name:
            if name in Interface.get_interface_names():
                return name
            raise ValueError("Interface name %r not found" % name)
        for each in Interface.get_routes():
            if each.is_default:
                return each.name
        raise ValueError("Unable to find default interface")


# =============================================================================
