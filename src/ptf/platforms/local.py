# Copyright 2010 The Board of Trustees of The Leland Stanford Junior University
# SPDX-License-Identifier: Apache-2.0

# This file was derived from code in the Floodlight OFTest repository
# https://github.com/floodlight/oftest released under the OpenFlow
# Software License:
# https://github.com/floodlight/oftest/blob/master/LICENSE
# See file README-oftest.md in the ptf repository for more details.

"""
Local platform

This platform uses veth pairs to send packets to and from a userspace
switch. The switch should be connected to veth0, veth2, veth4, and veth6.
"""


def platform_config_update(config):
    """
    Update configuration for the local platform

    @param config The configuration dictionary to use/update
    """
    base_port = 0  # oftest uses 0
    base_if_index = 1
    port_count = 4
    device_number = 0

    port_map = {}
    # Use every other veth interface (veth1, veth3, ...)
    for idx in range(port_count):
        port_map[(device_number, base_port + idx)] = "veth%d" % (
            base_if_index + 2 * idx
        )
    config["port_map"] = port_map
