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


import six


def hexdump(packet, dump=False):
    def to_number(number):
        return number if isinstance(number, int) else ord(number)

    def to_char(_number):
        j = to_number(_number)
        if (j < 32) or (j >= 127):
            return "."
        return chr(j)

    def make_rows(obj, num):
        return [
            obj[start : start + num]
            for start in range(0, len(obj), num)
            if obj[start : start + num]
        ]

    def convert_incoming_packet():
        potential_hex = None
        if hasattr(packet, "hex"):  # conversion for the 'Base' objects
            potential_hex = packet.hex()
        elif six.PY2:
            if isinstance(packet, str):
                if [b for b in packet.split() if len(b) == 2]:
                    potential_hex = packet.split()
                else:
                    import binascii

                    potential_hex = binascii.b2a_hex(packet)
        else:  # do for the Python 3.5+
            if isinstance(packet, str):
                return packet.replace(" ", "")
            try:
                potential_hex = bytes(packet).hex()
            except TypeError:
                try:
                    potential_hex = bytes(packet, encoding="utf-8").hex()
                except TypeError:
                    pass

        if potential_hex is None:
            raise TypeError(
                "Given packet is of incorrect type: {}".format(type(packet).__name__)
            )
        return potential_hex

    if isinstance(packet, list):
        packet_hex = [
            (hex(b)[2:].zfill(2) if isinstance(b, int) else b) for b in packet
        ]
    else:
        packet_hex = convert_incoming_packet()

    if not isinstance(packet_hex, list) and " " not in packet_hex:
        packet_hex = make_rows(packet_hex, 2)
    elif isinstance(packet_hex, str) and " " in packet_hex:
        packet_hex = packet_hex.split()

    output = []
    for e, line in enumerate(make_rows(packet_hex, 16)):
        console_char = [to_char(int(x, 16)) for x in line]
        if len(line) < 16:
            line += ["  " for _ in range(16 - len(line))]

        output.append(
            "%03x0   %s   %s" % (e, " ".join(line).upper(), "".join(console_char))
        )
    if dump:
        return output
    print("\n".join(output))
