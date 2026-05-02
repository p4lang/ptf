# Copyright 2010 The Board of Trustees of The Leland Stanford Junior University
# SPDX-License-Identifier: Apache-2.0

# This file was derived from code in the Floodlight OFTest repository
# https://github.com/floodlight/oftest released under the OpenFlow
# Software License:
# https://github.com/floodlight/oftest/blob/master/LICENSE
# See file README-oftest.md in the ptf repository for more details.

"""
Eth platform

This platform uses the --interface command line option to choose the ethernet interfaces.
"""


def platform_config_update(config):
    """
    Update configuration for the local platform

    @param config The configuration dictionary to use/update
    """

    port_map = {}

    for device, port, interface in config["interfaces"]:
        port_map[(device, port)] = interface

    # Default to a veth configuration compatible with the reference switch
    if not port_map:
        port_map = {
            (0, 0): "veth1",
            (0, 1): "veth3",
            (0, 2): "veth5",
            (0, 3): "veth7",
        }

    config["port_map"] = port_map
