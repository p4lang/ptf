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
""" DtelReportV2Hdr template """
from bf_pktpy.library.specs.packet import Packet
from bf_pktpy.library.fields import (
    BitField,
    ByteField,
    ShortField,
    ThreeBytesField,
    IntField,
    XLongField,
    ConditionalField,
)


def calculate_md_length(pkt):
    return bin(pkt.rep_md_bits).count("1") + bin(pkt.rep_md_bits & 0x0E00).count("1")


class DtelReportV2Hdr(Packet):
    name = "DtelReportV2Hdr"
    fields_desc = [
        BitField("ver", 0, 4),
        BitField("hw_id", 0, 6),
        BitField("sequence_number", 0, 22),
        IntField("switch_id", 0),
        BitField("rep_type", 0, 4),
        BitField("in_type", 0, 4),
        ByteField("report_length", 0),
        ByteField("md_length", calculate_md_length),
        BitField("dropped", 0, 1),
        BitField("congested_queue", 0, 1),
        BitField("path_tracking_flow", 0, 1),
        BitField("reserved", 0, 5),
        ShortField("rep_md_bits", 0),
        ShortField("domain_specific_id", 0),
        ShortField("ds_md_bits", 0),
        ShortField("ds_md_status", 0),
        # level_1_if_ids
        ConditionalField(
            ShortField("ingress_port", 0), lambda pkt: pkt.rep_md_bits & 0x4000
        ),
        ConditionalField(
            ShortField("egress_port", 0), lambda pkt: pkt.rep_md_bits & 0x4000
        ),
        # hop_latency
        ConditionalField(
            IntField("hop_latency", 0), lambda pkt: pkt.rep_md_bits & 0x2000
        ),
        # queue_occupancy
        ConditionalField(
            ByteField("queue_id", 0), lambda pkt: pkt.rep_md_bits & 0x1000
        ),
        ConditionalField(
            ThreeBytesField("queue_depth", 0), lambda pkt: pkt.rep_md_bits & 0x1000
        ),
        # ingress_tstamp
        ConditionalField(
            XLongField("timestamp", 0), lambda pkt: pkt.rep_md_bits & 0x0800
        ),
        # egress_tstamp
        ConditionalField(
            XLongField("egress_tstamp", 0), lambda pkt: pkt.rep_md_bits & 0x0400
        ),
        # level_2_if_ids
        ConditionalField(
            IntField("ingress_if_id", 0), lambda pkt: pkt.rep_md_bits & 0x0200
        ),
        ConditionalField(
            IntField("egress_if_id", 0), lambda pkt: pkt.rep_md_bits & 0x0200
        ),
        # eg_port_tx_util
        ConditionalField(
            IntField("eg_port_tx_util", 0), lambda pkt: pkt.rep_md_bits & 0x0100
        ),
        # buffer_occupancy
        ConditionalField(
            ByteField("buffer_id", 0), lambda pkt: pkt.rep_md_bits & 0x0080
        ),
        ConditionalField(
            ThreeBytesField("buffer_occupancy", 0), lambda pkt: pkt.rep_md_bits & 0x0080
        ),
        # drop_reason
        ConditionalField(
            ByteField("drop_queue_id", 0), lambda pkt: pkt.rep_md_bits & 0x0001
        ),
        ConditionalField(
            ByteField("drop_reason", 0), lambda pkt: pkt.rep_md_bits & 0x0001
        ),
        ConditionalField(
            ShortField("drop_reserved", 0), lambda pkt: pkt.rep_md_bits & 0x0001
        ),
    ]

    def _combine(self, body_copy):
        if body_copy.name == "Ether":
            self._body = body_copy
            self.in_type = 3
            return self

        raise ValueError("Unsupported binding")
