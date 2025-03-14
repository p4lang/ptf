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
""" BFD template """
from bf_pktpy.library.specs.packet import Packet
from bf_pktpy.library.fields import (
    BitField,
    BitEnumField,
    FlagsField,
    ByteField,
    IntField,
)


# =============================================================================


diagnostic_types = {
    0: "No Diagnostic",
    1: "Control Detection Time Expired",
    2: "Echo Function Failed",
    3: "Neighbor Signaled Session Down",
    4: "Forwarding Plane Reset",
    5: "Path Down",
    6: "Concatenated Path Down",
    7: "Administratively Down",
    8: "Reverse Concatenated Path Down",
}

status_names = {
    0: "AdminDown",
    1: "Down",
    2: "Init",
    3: "Up",
}


class BFD(Packet):
    """
    BFD class
    Bidirectional Forwarding Detection

    BFD
        version             (int)
        diag                (int)
        sta                 (int)
        flags               (int)
        detect_mult         (int)
        len                 (int)
        my_discriminator    (int)
        your_discriminator  (int)
        min_tx_interval     (int)
        min_rx_interval     (int)
        echo_rx_interval    (int)

    Examples:
        | + create
        |       bfd = BFD(version=..., diag=..., ..)
        | + make change
        |       bfd.version = <value>
        |       bfd.diag = <value>
    """

    name = "BFD"
    fields_desc = [
        BitField("version", 1, 3),
        BitEnumField("diag", 0, 5, diagnostic_types),
        BitEnumField("sta", 3, 2, status_names),
        FlagsField("flags", 0x00, 6, "MDACFP"),
        ByteField("detect_mult", 3),
        ByteField("len", 24),
        IntField("my_discriminator", 286331153),
        IntField("your_discriminator", 572662306),
        IntField("min_tx_interval", 1000000000),
        IntField("min_rx_interval", 1000000000),
        IntField("echo_rx_interval", 1000000000),
    ]

    @property
    def hdr_len(self):
        return 24

    @property
    def diagnostic_code(self):
        return diagnostic_types.get(self.diag)

    @property
    def session_state(self):
        return status_names.get(self.sta)


# =============================================================================
