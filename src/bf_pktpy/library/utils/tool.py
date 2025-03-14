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
""" bf_pktpy python library """
import socket


# =============================================================================
class Tool:
    """Tool collection"""

    @staticmethod
    def get_ipaddr_from_dname(dname, port=80):
        """Return IP of domain name

        Args:
            dname            (str): domain name
            port             (int): port number
        Returns:
            str: ip address
        Raises:
            socket.gaierror
        Examples:
            | addr = Tool.get_ipaddr_from_dname("google.com")
            |
        """
        try:
            result = socket.getaddrinfo(dname, port)
            return result[0][4][0]
        except socket.gaierror:
            raise


# =============================================================================
