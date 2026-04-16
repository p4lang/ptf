# Copyright 2010 The Board of Trustees of The Leland Stanford Junior University
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
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
