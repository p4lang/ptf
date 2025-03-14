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


import ipaddress
import six


def to_bin(value, bit_size=1):
    """Convert to binary"""
    if isinstance(value, (list, tuple)):
        if not value:
            return ""
        binary = ""
        for entry in value:
            binary += to_bin(entry)
        return binary

    if isinstance(value, six.binary_type):
        if not value:
            return "0".zfill(bit_size)
        return "".join(bin(b)[2:].zfill(8) for b in value)

    if isinstance(value, six.string_types):
        if not value:
            return "0".zfill(bit_size)
        try:
            ip = ipaddress.ip_address(six.u(value))
            if ip.version == 4:
                return bin(int(ip))[2:].zfill(32)
            elif ip.version == 6:
                return bin(int(ip))[2:].zfill(128)
        except ValueError:
            pass
        temp = (
            format(i, "b").zfill(bit_size) for i in bytearray(six.ensure_binary(value))
        )
        return "".join(temp)
    if bit_size:
        return bin(value)[2:].zfill(bit_size)
    return bin(value)[2:]
