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
""" IPOption templates """
import six

from bf_pktpy.library.specs.packet import Packet
from bf_pktpy.library.fields import (
    BitField,
    ByteField,
    ByteEnumField,
    ShortField,
    StrField,
    IPListField,
)

_option_names = {
    0: "EOOL",
    1: "NOP",
    130: "SEC",
    131: "LSR",
    68: "TS",
    133: "E-SEC",
    134: "CIPSO",
    7: "RR",
    136: "SID",
    137: "SSR",
    10: "ZSU",
    11: "MTUP",
    12: "MTUR",
    205: "FINN",
    142: "VISA",
    15: "ENCODE",
    144: "IMITD",
    145: "EIP",
    82: "TR",
    147: "ADDEXT",
    148: "RTRALT",
    149: "SDB",
    151: "DPS",
    152: "UMP",
    25: "QS",
    30: "EXP1",
    94: "EXP2",
    158: "EXP3",
    222: "EXP4",
}

_opt_type_header = ByteEnumField("opt_type", 0, _option_names)


class _IPOption(Packet):
    """Base class for IP options header definitions"""

    name = "Internal IP Option"
    fields_desc = [_opt_type_header]

    def __init__(self, raw_option=None, **fields):
        self.default_if_none = False
        if raw_option is not None:
            if not isinstance(raw_option, six.binary_type):
                raw_option = six.ensure_binary(raw_option)
            # we are omitting Packet constructor as we don't want to use **fields in
            # this case
            super(Packet, self).__init__()
            for field_def in self.fields_desc:
                object.__setattr__(self, field_def.name, None)
            self.parse_raw_option(raw_option)
        else:
            self.default_if_none = True
            super(_IPOption, self).__init__(**fields)
            self.opt_type = next(
                (
                    num
                    for num, name in six.iteritems(_option_names)
                    if name == self.name.lstrip("IP Option")
                ),
                self.opt_type,
            )

    def _members(self, **fields_to_override):
        return super(_IPOption, self)._members(
            default_if_none=self.default_if_none, **fields_to_override
        )

    # noinspection PyAttributeOutsideInit
    def parse_raw_option(self, raw_option):
        option_bits = "".join(bin(opt_byte)[2:].zfill(8) for opt_byte in raw_option)
        offset = 0
        for field in self.fields_desc:
            if offset >= len(option_bits):
                return
            new_offset = offset + field.size
            value = (
                int(option_bits[offset:new_offset], 2)
                if option_bits[offset:new_offset]
                else None
            )
            object.__setattr__(self, field.name, value)
            offset = new_offset

        if len(raw_option) > self.hdr_len:
            self._body = raw_option[self.hdr_len :]


class IPOption(_IPOption):
    """Default IP Option definition

    This type is for cases when byte sequence is
    not recognized (does not match with any defined IP options).
    """

    name = "IP Option"
    fields_desc = [
        _opt_type_header,
        ByteField("length", lambda opt: 2 + len(opt.value)),
        StrField("value", ""),
    ]

    # noinspection PyMissingConstructor
    def __init__(self, raw_option=None, **fields):
        opt_class = self.__class__
        if raw_option is not None:
            if not isinstance(raw_option, six.binary_type):
                raw_option = six.ensure_binary(raw_option)
            # We are guessing type of provided IP option, defaults to this class
            opt_class = ipoptions_mapping.get(raw_option[0], IPOption)
            self.__class__ = opt_class

        # In fact, we are calling _IPOption constructor
        super(opt_class, self).__init__(raw_option, **fields)

    # noinspection PyAttributeOutsideInit
    def parse_raw_option(self, raw_option):
        try:
            self.opt_type = raw_option[0]
            self.length = raw_option[1]
            self.value = raw_option[2:]
        except IndexError:
            return


class IPOption_EOL(_IPOption):
    name = "IP Option EOOL"
    fields_desc = [_opt_type_header]


class IPOption_NOP(_IPOption):
    name = "IP Option NOP"
    fields_desc = [_opt_type_header]


class IPOption_Stream_Id(_IPOption):
    name = "IP Option SID"
    fields_desc = [_opt_type_header, ByteField("length", 4), ShortField("security", 0)]


class IPOption_Security(_IPOption):
    name = "IP Option SEC"
    fields_desc = [
        _opt_type_header,
        ByteField("length", 11),
        ShortField("security", 0),
        ShortField("compartment", 0),
        ShortField("handling_restrictions", 0),
        BitField("transmission_control_code", 0, 24),
    ]


class _IPOption_RR(_IPOption):
    name = "IP Option RR"
    fields_desc = [
        _opt_type_header,
        ByteField("length", lambda pkt: len(pkt.route_data) * 4 + 3),
        ByteField("pointer", 4),
        IPListField("route_data"),
    ]

    # noinspection PyAttributeOutsideInit
    def parse_raw_option(self, raw_option):
        try:
            self.opt_type = raw_option[0]
            self.length = raw_option[1]
            self.pointer = raw_option[2]
            self.route_data = []
            ip_addr_count = (self.length - 3) // 4
            for i in range(ip_addr_count):
                self.route_data.append(raw_option[3 + i * 4 : 3 + (i + 1) * 4])

        except IndexError:
            return
        if len(raw_option) > 11:
            self._body = raw_option[11:]


class IPOption_LSRR(_IPOption_RR):
    name = "IP Option LSR"


class IPOption_SSRR(_IPOption_RR):
    name = "IP Option SSR"


ipoptions_mapping = {
    0: IPOption_EOL,
    1: IPOption_NOP,
    136: IPOption_Stream_Id,
    130: IPOption_Security,
    131: IPOption_LSRR,
    137: IPOption_SSRR,
}

IPOptionPlaceholder = IPOption
