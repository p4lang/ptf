#!/usr/bin/env python


# Copyright (c) 2021 Intel Corporation.
# SPDX-License-Identifier: Apache-2.0

###############################################################################
"""bf_pktpy python library"""

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
