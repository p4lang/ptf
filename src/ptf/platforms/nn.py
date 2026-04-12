# Copyright 2016 Antonin Bas
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

"""
nn platform

This platform uses nanomsg sockets (both IPC and TCP are supported) to send and
receive packets. Unlike for other platforms, the '--interface' option is
ignored, you instead have to use '--device-socket'. This is because there has to
be a 1-1 mapping between the devices and the nanomsg sockets.

For example:
--device-socket 0-[1,2,5-8]@<socket addr>
In this case, ports 1, 2 and 5 through 8 (included) are enabled on device 0.

The socket address must be either:
ipc://<path to file>
tcp://<iface>:<port>
"""


def platform_config_update(config):
    """
    Update configuration for the nn platform

    @param config The configuration dictionary to use/update
    """

    port_map = {}

    for device, ports, socket_addr in config["device_sockets"]:
        for port in ports:
            port_map[(device, port)] = socket_addr

    # no default configuration for this platform

    config["port_map"] = port_map
