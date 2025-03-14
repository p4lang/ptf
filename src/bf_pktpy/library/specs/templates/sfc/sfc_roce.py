#!/usr/bin/env python


# Copyright (c) 2022 Intel Corporation.
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
""" RoCE headers """

from enum import Enum

from bf_pktpy.library.specs.packet import Packet
from bf_pktpy.library.fields import (
    ByteEnumField,
    XBitField,
    XShortField,
    X3ByteField,
    XIntField,
    XLongField,
)


class RoceOpcode(Enum):
    UC_SEND_FIRST = 0b00100000
    UC_SEND_MIDDLE = 0b00100001
    UC_SEND_LAST = 0b00100010
    UC_SEND_LAST_IMMEDIATE = 0b00100011
    UC_SEND_ONLY = 0b00100100
    UC_SEND_ONLY_IMMEDIATE = 0b00100101
    UC_RDMA_WRITE_FIRST = 0b00100110
    UC_RDMA_WRITE_MIDDLE = 0b00100111
    UC_RDMA_WRITE_LAST = 0b00101000
    UC_RDMA_WRITE_LAST_IMMEDIATE = 0b00101001
    UC_RDMA_WRITE_ONLY = 0b00101010
    UC_RDMA_WRITE_ONLY_IMMEDIATE = 0b00101011
    RC_RDMA_WRITE_ONLY = 0b00001010
    RC_RDMA_WRITE_ONLY_IMMEDIATE = 0b00001011
    RC_WRITE_ACK = 0b0001000

    @staticmethod
    def to_dict():
        return {i.name: i.value for i in RoceOpcode}


class IB_BTH(Packet):
    name = "IB_BTH"
    fields_desc = [
        ByteEnumField("opcode", 0b0, RoceOpcode.to_dict()),
        XBitField("se", 0, 1),
        XBitField("migration_req", 1, 1),  # ???
        XBitField("pad_count", 0, 2),
        XBitField("transport_version", 0, 4),
        XShortField("partition_key", 0xFFFF),
        XBitField("f_res1", 0, 1),
        XBitField("b_res1", 0, 1),
        XBitField("reserved", 0, 6),
        X3ByteField("dst_qp", 0),
        XBitField("ack_req", 0, 1),
        XBitField("reserved2", 0, 7),
        X3ByteField("psn", 0),
    ]

    def _combine(self, body_copy):
        if body_copy.name in ("IB_RETH", "IB_IMM", "IB_AETH"):
            self._body = body_copy
            return self

        raise ValueError("Unsupported binding")


class IB_RETH(Packet):
    name = "IB_RETH"

    fields_desc = [
        XLongField("addr", 0),
        XIntField("rkey", 0),
        XIntField("len", 0),
    ]

    def _combine(self, body_copy):
        if body_copy.name == "IB_IMM":
            self._body = body_copy
            return self

        raise ValueError("Unsupported binding")


class IB_AETH(Packet):
    name = "IB_AETH"
    fields_desc = [
        XBitField("res", 0, 1),
        XBitField("opcode", 0, 2),  # ???
        XBitField("credit_count", 0, 5),
        X3ByteField("message_seq", 0),
    ]

    def _combine(self, body_copy):
        if body_copy.name == "IB_ICRC":
            self._body = body_copy
            return self

        raise ValueError("Unsupported binding")


class IB_IMM(Packet):
    name = "IB_IMM"
    fields_desc = [XIntField("imm", 0)]


class IB_ICRC(Packet):
    name = "IB_ICRC"
    fields_desc = [XIntField("icrc", None)]


#######################################################################################
# classes not yet implemented + their desired bindings

# class IB_GRH(Packet):
#     name = "IB_GRH"
#     fields_desc = [
#         XBitField("ipver", 6, 4),
#         XBitField("tclass", 2, 8),
#         XBitField("flowlabel", 0, 20),
#         XShortField("paylen", 0),
#         XByteField("nxthdr", 27),
#         XByteField("hoplmt", 64),
#         IP6Field("sgid", "::1"),
#         IP6Field("dgid", "::1")
#     ]

# class IB_Payload(Packet):
#     name = "IB_Payload"
#     fields_desc = [
#         FieldListField('data', None, SignedIntField('', 0),
#                        length_from=lambda pkt: len(pkt.payload) - 4)
#     ]

# bind_layers(IB_BTH, IB_Payload)
# bind_layers(IB_RETH, IB_Payload)
# bind_layers(IB_IMM, IB_Payload)
# bind_layers(IB_Payload, IB_ICRC)
