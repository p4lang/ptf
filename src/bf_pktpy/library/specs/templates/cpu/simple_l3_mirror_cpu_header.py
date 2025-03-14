#!/usr/bin/env python


#  Copyright (c) 2022 Intel Corporation
#  All Rights Reserved.
#
#  This software and the related documents are Intel copyrighted materials,
#  and your use of them is governed by the express license under which they
#  were provided to you ("License"). Unless the License provides otherwise,
#  you may not use, modify, copy, publish, distribute, disclose or transmit this
#  software or the related documents without Intel's prior written permission.
#
#  This software and the related documents are provided as is, with no express or
#  implied warranties, other than those that are expressly stated in the License.

###############################################################################
""" SimpleL3SwitchCpuHeader template """
import six
from bf_pktpy.library.specs.packet import Packet
from bf_pktpy.library.fields import ShortEnumField, ShortField


class SimpleL3SwitchCpuHeader(Packet):
    MIRROR_TYPE_MAPPING = {"ingress": 0, "egress": 1}
    MIRROR_TYPE_REVERSED = {
        value: key for key, value in six.iteritems(MIRROR_TYPE_MAPPING)
    }

    name = "SimpleL3SwitchCpuHeader"
    fields_desc = [
        ShortEnumField("mirror_type", 0, MIRROR_TYPE_REVERSED),
        ShortField("ingress_port", 0),
        ShortField("pkt_length", 0),
    ]

    def __init__(self, **kwargs):
        mirror = kwargs.pop("mirror_type", 0)
        if isinstance(mirror, six.string_types):
            if mirror.lower() not in self.MIRROR_TYPE_MAPPING:
                raise ValueError(
                    "Mirror type can be only either 'Ingress' or " "'Egress'"
                )
            mirror = self.MIRROR_TYPE_MAPPING[mirror.lower()]
        kwargs["mirror_type"] = mirror

        super(SimpleL3SwitchCpuHeader, self).__init__(**kwargs)

    def _combine(self, body_copy):
        if body_copy.name == "Ether":
            self._body = body_copy
            return self

        raise ValueError("Unsupported binding")
